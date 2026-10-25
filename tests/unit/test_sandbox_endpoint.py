from __future__ import annotations

import hashlib
import json
import socket
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from git_reviewer.sandbox.endpoint import (
    DockerUnavailableError,
    UnsafeDockerEndpointError,
    resolve_endpoint,
)


@pytest.fixture
def sock_dir() -> Iterator[Path]:
    # Unix socket paths are limited to ~104 bytes on macOS: pytest's tmp_path is too long.
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="gr-") as tmp:
        yield Path(tmp).resolve()


def make_socket(path: Path) -> Path:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.close()  # the socket file stays
    return path


def test_docker_host_unix_socket(sock_dir: Path) -> None:
    sock = make_socket(sock_dir / "docker.sock")
    assert resolve_endpoint({"DOCKER_HOST": f"unix://{sock}"}) == sock


@pytest.mark.parametrize(
    "host",
    ["tcp://10.0.0.5:2375", "ssh://user@build-server", "npipe:////./pipe/docker", "10.0.0.5:2375"],
)
def test_remote_endpoints_are_refused(host: str) -> None:
    with pytest.raises(UnsafeDockerEndpointError):
        resolve_endpoint({"DOCKER_HOST": host})


def test_relative_socket_is_refused() -> None:
    with pytest.raises(UnsafeDockerEndpointError):
        resolve_endpoint({"DOCKER_HOST": "unix://docker.sock"})


def test_missing_socket_means_docker_is_not_running(sock_dir: Path) -> None:
    with pytest.raises(DockerUnavailableError, match="not running"):
        resolve_endpoint({"DOCKER_HOST": f"unix://{sock_dir / 'nothing.sock'}"})


def test_a_regular_file_is_not_a_socket(sock_dir: Path) -> None:
    fake = sock_dir / "docker.sock"
    fake.write_text("not a socket")
    with pytest.raises(DockerUnavailableError, match="not a socket"):
        resolve_endpoint({"DOCKER_HOST": f"unix://{fake}"})


def test_socket_in_a_directory_others_can_write_is_refused(sock_dir: Path) -> None:
    shared = sock_dir / "shared"
    shared.mkdir()
    shared.chmod(0o777)  # writable by everyone and not sticky
    sock = make_socket(shared / "docker.sock")
    with pytest.raises(UnsafeDockerEndpointError, match="writable"):
        resolve_endpoint({"DOCKER_HOST": f"unix://{sock}"})


def test_current_context_is_followed(sock_dir: Path, tmp_path: Path) -> None:
    sock = make_socket(sock_dir / "docker.sock")
    config = tmp_path / "docker"
    meta = config / "contexts" / "meta" / hashlib.sha256(b"desktop-linux").hexdigest()
    meta.mkdir(parents=True)
    (meta / "meta.json").write_text(
        json.dumps({"Name": "desktop-linux", "Endpoints": {"docker": {"Host": f"unix://{sock}"}}})
    )
    (config / "config.json").write_text(
        json.dumps({"currentContext": "desktop-linux", "auths": {"registry": {"auth": "c2VjcmV0"}}})
    )
    assert resolve_endpoint({"DOCKER_CONFIG": str(config)}) == sock


def test_remote_context_is_refused(tmp_path: Path) -> None:
    config = tmp_path / "docker"
    meta = config / "contexts" / "meta" / hashlib.sha256(b"remote").hexdigest()
    meta.mkdir(parents=True)
    (meta / "meta.json").write_text(
        json.dumps({"Endpoints": {"docker": {"Host": "ssh://me@remote-builder"}}})
    )
    with pytest.raises(UnsafeDockerEndpointError):
        resolve_endpoint({"DOCKER_CONFIG": str(config), "DOCKER_CONTEXT": "remote"})


def test_unknown_context_is_an_environment_problem(tmp_path: Path) -> None:
    with pytest.raises(DockerUnavailableError, match="not found"):
        resolve_endpoint({"DOCKER_CONFIG": str(tmp_path), "DOCKER_CONTEXT": "missing"})


def test_relative_docker_config_is_refused() -> None:
    # It would be read from the current directory: the reviewed repository.
    with pytest.raises(UnsafeDockerEndpointError):
        resolve_endpoint({"DOCKER_CONFIG": "docker-config"})

"""DockerSandbox with proc.run replaced by a scripted fake Docker (no daemon needed)."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from git_reviewer import proc
from git_reviewer.sandbox import docker
from git_reviewer.sandbox.docker import DockerError, ImageMissingError, sandbox_session

IMAGE_ID = "sha256:" + "cd" * 32
RUN_ID = "0123456789abcdef0123456789abcdef"
SOCKET = Path("/var/run/docker.sock")

Handler = Callable[[list[str]], proc.Result]


class FakeDocker:
    def __init__(self, run: Handler | None = None) -> None:
        self.calls: list[list[str]] = []
        self.envs: list[dict[str, str]] = []
        self.image_ids = [IMAGE_ID]
        self.run_handler = run or (lambda args: proc.Result(0, b"1 passed\n", b""))

    def __call__(self, binary: str, args: Sequence[str], **kwargs: object) -> proc.Result:
        assert binary == "docker"
        args = list(args)
        self.calls.append(args)
        env = kwargs.get("env_extra")
        assert isinstance(env, dict)
        self.envs.append(env)
        assert args[:2] == ["--host", f"unix://{SOCKET}"]
        command = args[2]
        if command == "image":
            image_id = self.image_ids[0] if len(self.image_ids) == 1 else self.image_ids.pop(0)
            return proc.Result(0, f"{image_id}\n".encode(), b"")
        if command == "run":
            return self.run_handler(args)
        if command == "ps":
            return proc.Result(0, b"", b"")
        return proc.Result(0, b"", b"")

    def commands(self) -> list[str]:
        return [call[2] for call in self.calls]


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    fake_docker = FakeDocker()
    monkeypatch.setattr(docker.proc, "run", fake_docker)
    return fake_docker


def test_session_workspace_is_private_and_removed(fake: FakeDocker) -> None:
    with sandbox_session(SOCKET, "git-reviewer-sandbox:0.1", 60) as sandbox:
        workspace = sandbox.tree.parent
        assert oct(workspace.stat().st_mode & 0o777) == "0o700"
        assert sandbox.tree.is_dir()
    assert not workspace.exists()


def test_run_uses_the_validated_argv_and_an_empty_docker_config(fake: FakeDocker) -> None:
    with sandbox_session(SOCKET, "git-reviewer-sandbox:0.1", 60) as sandbox:
        result = sandbox.run("pytest", RUN_ID, IMAGE_ID)
        config = str(sandbox.tree.parent / "docker-config")
    assert result.outcome == "passed"
    assert result.exit_code == 0
    assert "1 passed" in result.output
    run_call = next(call for call in fake.calls if call[2] == "run")
    assert "--network=none" in run_call
    expected = ["python", "-P", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--color=no"]
    assert run_call[-8:] == expected
    assert all(env == {"DOCKER_CONFIG": config} for env in fake.envs)
    # The image is checked again right before the run, and the container removed afterwards.
    assert fake.commands() == ["image", "run", "rm"]


@pytest.mark.parametrize(
    ("tool", "code", "outcome"),
    [
        ("pytest", 1, "failed"),
        ("pytest", 5, "no_tests"),
        ("pytest", 137, "killed"),
        ("pytest", 125, "error"),
        ("pytest", 4, "error"),
        ("ruff", 1, "failed"),
        ("ruff", 2, "error"),
    ],
)
def test_exit_codes_map_to_outcomes(
    fake: FakeDocker, tool: docker.SandboxTool, code: int, outcome: str
) -> None:
    fake.run_handler = lambda args: proc.Result(code, b"", b"")
    with sandbox_session(SOCKET, "img:1", 60) as sandbox:
        assert sandbox.run(tool, RUN_ID, IMAGE_ID).outcome == outcome


def test_timeout_is_killed_and_the_container_removed(fake: FakeDocker) -> None:
    def hang(args: list[str]) -> proc.Result:
        raise proc.ProcTimeoutError("process exceeded 90s")

    fake.run_handler = hang
    with sandbox_session(SOCKET, "img:1", 60) as sandbox:
        result = sandbox.run("pytest", RUN_ID, IMAGE_ID)
    assert result.outcome == "killed"
    assert fake.calls[-1][2:] == ["rm", "--force", "--", f"gr-{RUN_ID}-pytest"]


def test_output_flood_is_an_error(fake: FakeDocker) -> None:
    def flood(args: list[str]) -> proc.Result:
        raise proc.OutputTooLargeError("too much")

    fake.run_handler = flood
    with sandbox_session(SOCKET, "img:1", 60) as sandbox:
        result = sandbox.run("pytest", RUN_ID, IMAGE_ID)
    assert (result.outcome, result.detail) == ("error", "stopped: output larger than 4 MiB")
    assert fake.commands()[-1] == "rm"


def test_output_keeps_only_the_end(fake: FakeDocker) -> None:
    fake.run_handler = lambda args: proc.Result(1, b"x" * 50_000 + b"THE END", b"")
    with sandbox_session(SOCKET, "img:1", 60) as sandbox:
        result = sandbox.run("pytest", RUN_ID, IMAGE_ID)
    assert len(result.output) <= 8_000
    assert "THE END" in result.output


def test_image_swapped_during_the_review_stops_the_run(fake: FakeDocker) -> None:
    fake.image_ids = ["sha256:" + "ee" * 32, IMAGE_ID]
    with sandbox_session(SOCKET, "img:1", 60) as sandbox, pytest.raises(DockerError):
        sandbox.run("pytest", RUN_ID, IMAGE_ID)
    assert "run" not in fake.commands()


def test_missing_image(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docker.proc, "run", lambda *a, **k: proc.Result(1, b"", b"No such image"))
    with sandbox_session(SOCKET, "img:1", 60) as sandbox, pytest.raises(ImageMissingError):
        sandbox.image_id()


def test_invalid_answers_from_docker_are_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docker.proc, "run", lambda *a, **k: proc.Result(0, b"--privileged\n", b""))
    with sandbox_session(SOCKET, "img:1", 60) as sandbox:
        with pytest.raises(DockerError):
            sandbox.image_id()
        with pytest.raises(DockerError):
            sandbox.leftover_containers(RUN_ID)


def test_leftover_containers_are_listed_by_label(monkeypatch: pytest.MonkeyPatch) -> None:
    container = "f" * 64

    def ps(binary: str, args: Sequence[str], **kwargs: object) -> proc.Result:
        assert f"--filter=label=git-reviewer.run={RUN_ID}" in args
        return proc.Result(0, f"{container}\n".encode(), b"")

    monkeypatch.setattr(docker.proc, "run", ps)
    with sandbox_session(SOCKET, "img:1", 60) as sandbox:
        assert sandbox.leftover_containers(RUN_ID) == [container]


def test_a_failed_removal_keeps_the_run_result(fake: FakeDocker) -> None:
    def hang(args: list[str]) -> proc.Result:
        raise proc.ProcTimeoutError("process exceeded 90s")

    fake.run_handler = hang
    original = fake.__call__

    def slow_rm(binary: str, args: Sequence[str], **kwargs: object) -> proc.Result:
        if "rm" in args:
            raise proc.ProcTimeoutError("docker rm exceeded 30s")
        return original(binary, args, **kwargs)

    with sandbox_session(SOCKET, "img:1", 60) as sandbox:
        docker.proc.run = slow_rm  # restored by the fixture's monkeypatch
        result = sandbox.run("pytest", RUN_ID, IMAGE_ID)
    # The leftover check that follows in the graph is what blocks a surviving container.
    assert result.outcome == "killed"


def test_pytest_exit_0_without_passed_tests_is_an_error(fake: FakeDocker) -> None:
    # os._exit(0) in code the tests import makes pytest exit 0 before running any test.
    fake.run_handler = lambda args: proc.Result(0, b"", b"")
    with sandbox_session(SOCKET, "img:1", 60) as sandbox:
        result = sandbox.run("pytest", RUN_ID, IMAGE_ID)
    assert (result.outcome, result.detail) == (
        "error",
        "pytest exited 0 without reporting passed tests",
    )

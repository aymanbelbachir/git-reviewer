"""Shared fixtures. Every test runs with outbound network access blocked (T-24, T-25)."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.helpers import git, write_files

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex


def _check_address(sock: socket.socket, address: Any) -> None:
    if sock.family == socket.AF_UNIX:
        return
    host = address[0] if isinstance(address, tuple) else address
    try:
        loopback = ipaddress.ip_address(str(host).split("%", 1)[0]).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise RuntimeError(f"network access blocked in tests: {address!r}")


def _guarded_connect(self: socket.socket, address: Any) -> None:
    _check_address(self, address)
    _real_connect(self, address)


def _guarded_connect_ex(self: socket.socket, address: Any) -> int:
    _check_address(self, address)
    return _real_connect_ex(self, address)


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)


@pytest.fixture
def make_repo(tmp_path: Path) -> Callable[..., Path]:
    """Create a git repository with one initial commit containing `files`."""

    def factory(files: dict[str, str | bytes] | None = None) -> Path:
        repo = tmp_path / "repo"
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        write_files(repo, files or {"README.md": "hello\n"})
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "initial")
        return repo

    return factory

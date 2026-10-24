from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from git_reviewer import proc


def test_only_allowlisted_binaries() -> None:
    for name in ("python3", "sh", "bash", "curl", "../git", "/usr/bin/git"):
        with pytest.raises(proc.BinaryNotAllowedError):
            proc.resolve_binary(name)


def test_git_resolves_to_an_absolute_trusted_path() -> None:
    path = proc.resolve_binary("git")
    assert path.is_absolute()
    assert path.name == "git"


def test_runs_git_and_captures_output(tmp_path: Path) -> None:
    result = proc.run("git", ["--version"], cwd=tmp_path)
    assert result.returncode == 0
    assert result.stdout.startswith(b"git version")


def test_environment_is_built_from_scratch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}
    real_popen = subprocess.Popen

    def spy(*args: Any, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return real_popen(*args, **kwargs)

    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-leak")
    monkeypatch.setattr(proc.subprocess, "Popen", spy)
    proc.run("git", ["--version"], cwd=tmp_path, env_extra={"GIT_TERMINAL_PROMPT": "0"})
    env = captured["env"]
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert set(env) == {*proc.BASE_ENV, "GIT_TERMINAL_PROMPT"}
    assert captured["shell"] is False


@pytest.mark.parametrize(
    "name",
    [
        "LD_PRELOAD",
        "PYTHONPATH",
        "HOME",
        "PATH",
        "DOCKER_HOST",
        "GIT_EXTERNAL_DIFF",
        "GIT_EXEC_PATH",
        "GIT_CONFIG_PARAMETERS",
        "GIT_SSH_COMMAND",
    ],
)
def test_extra_environment_is_allowlisted(name: str, tmp_path: Path) -> None:
    with pytest.raises(proc.EnvNotAllowedError):
        proc.run("git", ["--version"], cwd=tmp_path, env_extra={name: "x"})


def test_nul_bytes_in_arguments_are_refused(tmp_path: Path) -> None:
    with pytest.raises(proc.ProcError):
        proc.run("git", ["--version\x00--exec-path"], cwd=tmp_path)


def test_timeout_kills_the_process(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(proc, "resolve_binary", lambda name, **_: Path("/bin/sleep"))
    with pytest.raises(proc.ProcTimeoutError):
        proc.run("git", ["30"], cwd=tmp_path, timeout=0.5)


def test_output_cap_kills_the_process(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(proc, "resolve_binary", lambda name, **_: Path("/usr/bin/yes"))
    with pytest.raises(proc.OutputTooLargeError):
        proc.run("git", [], cwd=tmp_path, max_output=64 * 1024, timeout=10)


def test_stdin_is_delivered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(proc, "resolve_binary", lambda name, **_: Path("/bin/cat"))
    payload = b"x" * (300 * 1024)
    result = proc.run("git", [], cwd=tmp_path, stdin=payload)
    assert result.stdout == payload


def test_group_writable_binary_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = tmp_path / "git"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o775)
    monkeypatch.setattr(proc, "TRUSTED_DIRS", (tmp_path,))
    with pytest.raises(proc.UnsafeBinaryError):
        proc.resolve_binary("git")


def test_binary_inside_the_reviewed_repo_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "git"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    tmp_path.chmod(0o755)
    monkeypatch.setattr(proc, "TRUSTED_DIRS", (tmp_path,))
    with pytest.raises(proc.UnsafeBinaryError):
        proc.resolve_binary("git", forbidden_root=tmp_path)


def test_child_that_stops_reading_stdin_is_an_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(proc, "resolve_binary", lambda name, **_: Path("/usr/bin/true"))
    with pytest.raises(proc.ProcError, match="closed its input"):
        proc.run("git", [], cwd=tmp_path, stdin=b"x" * (4 * 1024 * 1024))

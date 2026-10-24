"""Helpers shared by the tests."""

from __future__ import annotations

from pathlib import Path

from git_reviewer import proc


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> proc.Result:
    """Run git in a test repository through the project's own subprocess module."""
    identity = ["-c", "user.name=Test", "-c", "user.email=test@example.com"]
    isolation = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    result = proc.run("git", [*identity, *args], cwd=repo, env_extra={**isolation, **(env or {})})
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr.decode()}")
    return result


def write_files(repo: Path, files: dict[str, str | bytes]) -> None:
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

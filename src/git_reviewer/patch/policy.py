"""Deterministic path rules for patches: they run first and have the final say
(docs/ARCHITECTURE.md §11, step 2; SECURITY.md T-18).

A patch may only change one Python file of the reviewed change, given as a plain relative path.
Names are compared after NFC normalization and casefolding, as macOS and Windows file systems see
them (`.GIT/config` is `.git/config`). Denied whatever the diff says: git's own files and hooks,
CI, dependency and build files, test setup, Python startup hooks, tool configuration, and files
that editors and coding agents load automatically. Before writing, `on_disk_problems` checks the
user's working tree: no symlink anywhere on the path, a regular file, inside the repository.
"""

from __future__ import annotations

import fnmatch
import re
import stat
import unicodedata
from collections.abc import Iterable
from pathlib import Path

from git_reviewer.models import FileChange

DENIED_DIRS = frozenset(
    {
        ".git",
        ".githooks",
        ".husky",
        ".github",
        ".circleci",
        ".vscode",
        ".idea",
        ".devcontainer",
        ".claude",
        ".cursor",
    }
)
DENIED_NAMES = frozenset(
    {
        # CI
        ".gitlab-ci.yml",
        "jenkinsfile",
        "azure-pipelines.yml",
        ".travis.yml",
        ".pre-commit-config.yaml",
        # dependencies and build
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "uv.lock",
        "poetry.lock",
        "makefile",
        # test setup
        "conftest.py",
        "pytest.ini",
        "pytest.toml",
        ".pytest.toml",
        ".pytest.ini",
        "tox.ini",
        "noxfile.py",
        # Python startup hooks
        "sitecustomize.py",
        "usercustomize.py",
        # tool configuration
        ".gitleaks.toml",
        ".gitleaksignore",
        "ruff.toml",
        ".ruff.toml",
        ".bandit",
        # loaded automatically by editors and coding agents
        ".envrc",
        "claude.md",
        "agents.md",
        # git
        ".gitattributes",
        ".gitmodules",
    }
)
DENIED_PATTERNS = (
    "requirements*.txt",
    "constraints*.txt",
    "pipfile*",
    "dockerfile*",
    "*.pth",
    ".git-reviewer*",
)
_PLAIN_PATH = re.compile(r"[A-Za-z0-9._/-]{1,512}")


def normalized(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def denied(path: str) -> bool:
    *directories, name = normalized(path).split("/")
    return (
        any(directory in DENIED_DIRS for directory in directories)
        or name in DENIED_NAMES
        or any(fnmatch.fnmatchcase(name, pattern) for pattern in DENIED_PATTERNS)
    )


def problems(path: str, files: Iterable[FileChange]) -> list[str]:
    """Why `path` may not be patched (empty when it may)."""
    if not _PLAIN_PATH.fullmatch(path):
        return ["only plain relative paths (letters, digits, '.', '_', '-', '/') are patched"]
    parts = path.split("/")
    if path.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        return ["the path is absolute or not normalized"]
    found: list[str] = []
    if denied(path):
        found.append(
            f"{path} is never patched (git, hooks, CI, dependencies, test setup, startup hooks "
            "or tool configuration)"
        )
    if not path.endswith(".py"):
        found.append("only Python files are patched")
    target = normalized(path)
    change = next((c for c in files if normalized(c.path) == target), None)
    if change is None or change.status == "deleted" or change.binary:
        found.append(f"{path} is not a file of the reviewed change")
    return found


def on_disk_problems(repo: Path, path: str) -> list[str]:
    """The target in the user's working tree: real directories, a regular file, in the repo."""
    current = repo
    for part in path.split("/")[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            return [f"{path} does not exist in the working tree"]
        if not stat.S_ISDIR(info.st_mode):
            return [f"a parent directory of {path} is a symbolic link or not a directory"]
    target = repo.joinpath(*path.split("/"))
    try:
        info = target.lstat()
    except OSError:
        return [f"{path} does not exist in the working tree"]
    if not stat.S_ISREG(info.st_mode):
        return [f"{path} is not a regular file (a symbolic link?)"]
    if not target.resolve().is_relative_to(repo.resolve()):
        return [f"{path} resolves outside the repository"]
    return []

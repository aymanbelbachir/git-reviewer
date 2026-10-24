"""Hardened git invocation (docs/ARCHITECTURE.md §6.1; SECURITY.md T-23, T-36).

Repository content is untrusted, and so is any git feature it can switch on: hooks, fsmonitor,
external diff drivers, textconv, replace refs, and `.gitattributes`. A branch that adds
`* -diff` or `*.py binary` would make git print "Binary files differ" instead of the code, hiding it
from the review; every call therefore reads attributes from the empty tree (`--attr-source`, git
2.40+). System and global git configuration is ignored. The repository's own `.git/config` still
applies: the user controls it.
"""

from __future__ import annotations

import functools
import os
from collections.abc import Sequence
from pathlib import Path

from git_reviewer import proc, sanitize

HARDENING_CONFIG: tuple[str, ...] = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "core.quotePath=true",
    "-c", "diff.suppressBlankEmpty=false",
    "-c", "color.ui=false",
)  # fmt: skip
HARDENING_ENV: dict[str, str] = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_ATTR_NOSYSTEM": "1",
}
# Set by git when it runs a hook. `git commit -a` and `git commit <paths>` commit a temporary
# index named by GIT_INDEX_FILE; without it the review would read the wrong index (T-28).
HOOK_ENV_VARS: tuple[str, ...] = ("GIT_INDEX_FILE", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")
# The empty tree exists in every repository without being stored.
EMPTY_TREE: dict[str, str] = {
    "sha1": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    "sha256": "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321",
}


class GitError(RuntimeError):
    """A git command failed."""


def hook_env() -> dict[str, str]:
    """The git variables of the hook environment, to pass through in hook mode only."""
    return {name: os.environ[name] for name in HOOK_ENV_VARS if name in os.environ}


def run_git(
    repo: Path,
    args: Sequence[str],
    *,
    hook: bool = False,
    timeout: float = proc.DEFAULT_TIMEOUT_SECONDS,
    max_output: int = proc.DEFAULT_MAX_OUTPUT_BYTES,
) -> proc.Result:
    attr_source = ("--attr-source", _empty_tree(repo, hook))
    return _run(repo, [*attr_source, *args], hook=hook, timeout=timeout, max_output=max_output)


def repo_root(start: Path, *, hook: bool = False) -> Path:
    result = run_git(start, ["rev-parse", "--show-toplevel"], hook=hook)
    if result.returncode != 0:
        raise GitError(f"not inside a git repository ({stderr_text(result)})")
    try:
        return Path(result.stdout.decode("utf-8", "strict").strip())
    except UnicodeDecodeError as exc:
        raise GitError("the repository path is not valid UTF-8") from exc


def stderr_text(result: proc.Result) -> str:
    """git's own error message, made safe to print."""
    return sanitize.one_line(result.stderr.decode("utf-8", "replace").strip(), max_chars=300)


@functools.lru_cache(maxsize=32)
def _empty_tree(repo: Path, hook: bool) -> str:
    result = _run(repo, ["rev-parse", "--show-object-format"], hook=hook)
    object_format = result.stdout.decode("ascii", "replace").strip()
    # Outside a repository the query fails; the actual command then fails on its own.
    return EMPTY_TREE.get(object_format, EMPTY_TREE["sha1"])


def _run(
    repo: Path,
    args: Sequence[str],
    *,
    hook: bool,
    timeout: float = proc.DEFAULT_TIMEOUT_SECONDS,
    max_output: int = proc.DEFAULT_MAX_OUTPUT_BYTES,
) -> proc.Result:
    env = dict(HARDENING_ENV)
    if hook:
        env.update(hook_env())
    return proc.run(
        "git",
        [*HARDENING_CONFIG, *args],
        cwd=repo,
        timeout=timeout,
        env_extra=env,
        max_output=max_output,
        forbidden_root=repo,
    )

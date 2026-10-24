"""The only module that starts subprocesses (docs/ARCHITECTURE.md §7; SECURITY.md T-21, T-22).

Every call goes through `run()`:
- the binary must be on an allowlist and is resolved to an absolute path from fixed, trusted
  directories; the user's PATH is never consulted, so a `git` planted in the repository or in a
  hostile PATH entry is never executed;
- argv is a list and no shell is ever involved;
- the environment is built from scratch; the user's environment is never inherited;
- every call has a timeout and a cap on captured output; on timeout or overflow the whole process
  group is killed.
"""

from __future__ import annotations

import contextlib
import os
import selectors
import signal
import stat

# This module is the single, audited subprocess entry point.
import subprocess  # nosec B404
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO

ALLOWED_BINARIES = frozenset({"git", "docker", "gitleaks", "lsof", "ruff", "bandit"})
# ruff and bandit are pinned dependencies of git-reviewer and come from its own virtualenv.
VENV_BINARIES = frozenset({"ruff", "bandit"})
TRUSTED_DIRS: tuple[Path, ...] = (
    Path("/opt/homebrew/bin"),
    Path("/usr/local/bin"),
    Path("/usr/bin"),
    Path("/bin"),
    Path("/usr/sbin"),
    Path("/sbin"),
)
BASE_ENV: Mapping[str, str] = {
    "PATH": os.pathsep.join(str(d) for d in TRUSTED_DIRS),
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}
# Extra variables a caller may add, by exact name: git hardening flags and the hook-mode index
# (docs/ARCHITECTURE.md §6.1), and the private Docker config dir (§8.3). A prefix such as GIT_*
# would also admit GIT_EXTERNAL_DIFF, GIT_EXEC_PATH or GIT_CONFIG_PARAMETERS, which run programs
# or re-enable the configuration the hardening turns off.
ALLOWED_EXTRA_ENV_NAMES = frozenset(
    {
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_TERMINAL_PROMPT",
        "GIT_OPTIONAL_LOCKS",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_ATTR_NOSYSTEM",
        "GIT_INDEX_FILE",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "DOCKER_CONFIG",
    }
)

DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
_READ_CHUNK = 64 * 1024
_KILL_GRACE_SECONDS = 5.0


class ProcError(RuntimeError):
    """Base class for subprocess policy violations and failures."""


class BinaryNotAllowedError(ProcError):
    """The binary is not on the allowlist."""


class BinaryNotFoundError(ProcError):
    """The allowlisted binary is not installed in a trusted directory."""


class UnsafeBinaryError(ProcError):
    """The binary or its directory is writable by other users, or lives in a forbidden tree."""


class EnvNotAllowedError(ProcError):
    """A caller tried to pass an environment variable that is not allowlisted."""


class ProcTimeoutError(ProcError):
    """The process ran longer than its timeout and was killed."""


class OutputTooLargeError(ProcError):
    """The process wrote more than the output cap and was killed."""


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: bytes
    stderr: bytes


def resolve_binary(name: str, *, forbidden_root: Path | None = None) -> Path:
    """Return the absolute path of an allowlisted binary, never looking at the user's PATH."""
    if name not in ALLOWED_BINARIES:
        raise BinaryNotAllowedError(f"binary not allowed: {name!r}")
    for directory in _search_dirs(name):
        candidate = directory / name
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        resolved = candidate.resolve(strict=True)
        _check_not_writable_by_others(resolved)
        if forbidden_root is not None and resolved.is_relative_to(forbidden_root.resolve()):
            raise UnsafeBinaryError(f"{name} resolves inside the reviewed repository: {resolved}")
        return resolved
    raise BinaryNotFoundError(f"{name} not found in trusted directories")


def run(
    binary: str,
    args: Sequence[str],
    *,
    cwd: Path,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    env_extra: Mapping[str, str] | None = None,
    stdin: bytes | None = None,
    max_output: int = DEFAULT_MAX_OUTPUT_BYTES,
    forbidden_root: Path | None = None,
) -> Result:
    """Run an allowlisted binary: argv list, clean environment, timeout and output cap."""
    executable = resolve_binary(binary, forbidden_root=forbidden_root)
    argv = [str(executable), *_checked_args(args)]
    env = _build_env(env_extra)
    # argv list, allowlisted absolute binary, no shell.
    process = subprocess.Popen(  # noqa: S603  # nosec B603
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = _communicate(process, stdin, timeout, max_output)
    except BaseException:
        _kill_group(process)
        raise
    return Result(returncode=process.returncode, stdout=stdout, stderr=stderr)


def _search_dirs(name: str) -> tuple[Path, ...]:
    if name in VENV_BINARIES:
        if sys.prefix == sys.base_prefix:
            return ()
        return (Path(sys.prefix) / "bin",)
    return TRUSTED_DIRS


def _check_not_writable_by_others(path: Path) -> None:
    for target in (path, path.parent):
        mode = target.stat().st_mode
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise UnsafeBinaryError(f"{target} is writable by group or others")


def _checked_args(args: Sequence[str]) -> list[str]:
    checked: list[str] = []
    for arg in args:
        if not isinstance(arg, str) or "\x00" in arg:
            raise ProcError("arguments must be strings without NUL bytes")
        checked.append(arg)
    return checked


def _build_env(env_extra: Mapping[str, str] | None) -> dict[str, str]:
    env = dict(BASE_ENV)
    for name, value in (env_extra or {}).items():
        if name not in ALLOWED_EXTRA_ENV_NAMES:
            raise EnvNotAllowedError(f"environment variable not allowed: {name!r}")
        if "\x00" in name or "\x00" in value or "=" in name:
            raise EnvNotAllowedError(f"invalid environment variable: {name!r}")
        env[name] = value
    return env


def _communicate(
    process: subprocess.Popen[bytes], stdin: bytes | None, timeout: float, max_output: int
) -> tuple[bytes, bytes]:
    stdin_stream, stdout_stream, stderr_stream = process.stdin, process.stdout, process.stderr
    if stdout_stream is None or stderr_stream is None:
        raise ProcError("subprocess pipes were not created")
    deadline = time.monotonic() + timeout
    outputs: dict[IO[bytes], list[bytes]] = {stdout_stream: [], stderr_stream: []}
    total = 0
    pending = memoryview(stdin or b"")
    with selectors.DefaultSelector() as selector:
        selector.register(stdout_stream, selectors.EVENT_READ)
        selector.register(stderr_stream, selectors.EVENT_READ)
        if stdin_stream is not None:
            if pending:
                os.set_blocking(stdin_stream.fileno(), False)
                selector.register(stdin_stream, selectors.EVENT_WRITE)
            else:
                stdin_stream.close()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProcTimeoutError(f"process exceeded {timeout:.0f}s")
            for key, _ in selector.select(remaining):
                if stdin_stream is not None and key.fileobj is stdin_stream:
                    pending = _write_some(selector, stdin_stream, pending)
                    continue
                stream = stdout_stream if key.fileobj is stdout_stream else stderr_stream
                chunk = os.read(stream.fileno(), _READ_CHUNK)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                total += len(chunk)
                if total > max_output:
                    raise OutputTooLargeError(f"process output exceeded {max_output} bytes")
                outputs[stream].append(chunk)
    try:
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        raise ProcTimeoutError(f"process exceeded {timeout:.0f}s") from exc
    return b"".join(outputs[stdout_stream]), b"".join(outputs[stderr_stream])


def _write_some(
    selector: selectors.BaseSelector, stdin: IO[bytes], pending: memoryview
) -> memoryview:
    try:
        written = os.write(stdin.fileno(), pending[:_READ_CHUNK])
    except BlockingIOError:
        return pending
    except BrokenPipeError as exc:
        # The child stopped reading: its result would cover only part of the input.
        raise ProcError("the process closed its input before reading all of it") from exc
    pending = pending[written:]
    if not pending:
        selector.unregister(stdin)
        stdin.close()
    return pending


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=_KILL_GRACE_SECONDS)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            stream.close()

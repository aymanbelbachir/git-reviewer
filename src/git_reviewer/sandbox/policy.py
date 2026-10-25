"""Assertions on the docker argv before every run: the execution guardian's barrier
(docs/ARCHITECTURE.md §8.3, §10.2; SECURITY.md T-10..T-15).

The argv is compared with this module's own copy of the required options, kept apart from the
builder in sandbox/docker.py on purpose: a change that weakens the builder is caught here, and a
change here alone stops every run. Every option must be present exactly once and nothing else is
allowed, so `-v`, `--privileged`, `--env-file`, a bare `--env NAME` (which copies the host value),
`--network=host` or a second mount are all deviations. One problem means no run.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import takewhile
from pathlib import Path

from git_reviewer.models import SandboxTool

REQUIRED_OPTIONS: tuple[str, ...] = (
    "--rm",
    "--pull=never",
    "--init",
    "--network=none",
    "--user=10001:10001",
    "--read-only",
    "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m",
    "--workdir=/work",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--pids-limit=256",
    "--memory=1g",
    "--memory-swap=1g",
    "--cpus=1",
    "--log-driver=none",
    "--env=HOME=/tmp",
    "--env=PYTHONDONTWRITEBYTECODE=1",
)
# `python -P` keeps /work out of the front of sys.path: the image appends /work/src and /work
# after the standard library and pytest, so the reviewed code cannot replace them.
COMMANDS: dict[SandboxTool, tuple[str, ...]] = {
    "pytest": ("python", "-P", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--color=no"),
    "ruff": ("ruff", "check", "--no-cache", "--output-format=concise", "."),
}
MIN_TIMEOUT_SECONDS = 10
MAX_TIMEOUT_SECONDS = 1_800
# Checked on their own as well, in case REQUIRED_OPTIONS itself is ever weakened.
_INVARIANTS = ("--network=none", "--read-only", "--user=10001:10001", "--cap-drop=ALL")
_RUN_ID = re.compile(r"[0-9a-f]{32}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
# Docker splits --mount on "," and "=": such a path could add mount options.
_UNSAFE_PATH_CHARS = frozenset(",=\n\r\t\x00")


class PolicyViolationError(RuntimeError):
    """A docker argv broke the sandbox policy."""


@dataclass(frozen=True)
class RunSpec:
    socket: Path
    tree: Path
    run_id: str
    tool: SandboxTool
    image_id: str
    timeout_seconds: int


def expected_options(spec: RunSpec) -> list[str]:
    return [
        *REQUIRED_OPTIONS,
        f"--name={container_name(spec)}",
        f"--label=git-reviewer.run={spec.run_id}",
        f"--mount=type=bind,source={spec.tree},target=/work,readonly",
    ]


def expected_command(spec: RunSpec) -> list[str]:
    # The container also stops itself, even if git-reviewer dies before it can remove it.
    timeout = ["timeout", "--signal=KILL", f"{spec.timeout_seconds}s"]
    return [*timeout, *COMMANDS[spec.tool]]


def container_name(spec: RunSpec) -> str:
    return f"gr-{spec.run_id}-{spec.tool}"


def problems(argv: Sequence[str], spec: RunSpec) -> list[str]:
    """Every way `argv` deviates from the policy for `spec` (empty when it may run)."""
    found = _spec_problems(spec)
    if spec.tool not in COMMANDS:
        return found
    head = ["docker", "--host", f"unix://{spec.socket}", "run"]
    if list(argv[:4]) != head:
        found.append("the command must start with: docker --host <validated socket> run")
    rest = list(argv[4:])
    options = list(takewhile(lambda arg: arg.startswith("-"), rest))
    positional = rest[len(options) :]
    expected = Counter(expected_options(spec))
    actual = Counter(options)
    found += [f"missing option {option}" for option in sorted((expected - actual).elements())]
    found += [f"unexpected option {option}" for option in sorted((actual - expected).elements())]
    found += [f"missing option {option}" for option in _INVARIANTS if option not in actual]
    if not positional or positional[0] != spec.image_id or not _IMAGE_ID.fullmatch(spec.image_id):
        found.append("the image must be the local image ID resolved for this run")
    if positional[1:] != expected_command(spec):
        found.append(f"the command must be exactly: {' '.join(expected_command(spec))}")
    return list(dict.fromkeys(found))


def check(argv: Sequence[str], spec: RunSpec) -> None:
    found = problems(argv, spec)
    if found:
        raise PolicyViolationError("; ".join(found))


def _spec_problems(spec: RunSpec) -> list[str]:
    found: list[str] = []
    if not _RUN_ID.fullmatch(spec.run_id):
        found.append("invalid run id")
    if spec.tool not in COMMANDS:
        found.append(f"unknown sandbox tool {spec.tool!r}")
    if not MIN_TIMEOUT_SECONDS <= spec.timeout_seconds <= MAX_TIMEOUT_SECONDS:
        found.append("the sandbox timeout is out of bounds")
    for label, path in (("socket", spec.socket), ("tree", spec.tree)):
        if not path.is_absolute() or _UNSAFE_PATH_CHARS & set(str(path)):
            found.append(f"unsafe {label} path")
    found += _tree_problems(spec.tree)
    return found


def _tree_problems(tree: Path) -> list[str]:
    """The only mount must be the private sandbox copy: <temp dir>/git-reviewer-sandbox-*/tree,
    in a 0700 directory of the current user. Never the repository, the home directory or `/`."""
    workspace = tree.parent
    temp_root = Path(tempfile.gettempdir()).resolve()
    if (
        tree.name != "tree"
        or not workspace.name.startswith("git-reviewer-sandbox-")
        or workspace.parent != temp_root
    ):
        return ["the mount must be the private sandbox copy (<temp>/git-reviewer-sandbox-*/tree)"]
    try:
        workspace_info = workspace.lstat()
        tree_info = tree.lstat()
    except OSError:
        return ["the sandbox copy does not exist"]
    private = (
        stat.S_ISDIR(workspace_info.st_mode)
        and workspace_info.st_uid == os.getuid()
        and not workspace_info.st_mode & 0o077
    )
    if not private or not stat.S_ISDIR(tree_info.st_mode):
        return ["the sandbox copy must sit in a private (0700) directory of the current user"]
    return []

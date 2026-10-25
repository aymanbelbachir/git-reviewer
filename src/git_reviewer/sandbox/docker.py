"""Run the project's tests and linter in a throwaway Docker container (effect module;
docs/ARCHITECTURE.md §8; SECURITY.md T-10..T-17, T-33).

- The container sees only a read-only copy of the reviewed tree (git/snapshot.py), never the user's
  working directory, home, SSH keys or Docker socket; no network, a non-root user, a read-only root
  file system with a small tmpfs, no capabilities, and CPU, memory and process limits.
- Every argv is checked by sandbox.policy right before it runs, whatever the graph decided.
- The image is the one the user built (`sandbox_image`), resolved to its local image ID once per
  review and checked again before each run; it is never built or pulled (`--pull=never`).
- A host-side timeout, plus `timeout --signal=KILL` inside the container, bound every run;
  `docker rm -f` runs in `finally`, and the caller checks that no container of the run remains.
"""

from __future__ import annotations

import contextlib
import re
import tempfile
import time
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

from git_reviewer import proc
from git_reviewer.models import SandboxOutcome, SandboxRun, SandboxTool

from . import policy
from .policy import RunSpec

SANDBOX_TOOLS: tuple[SandboxTool, ...] = ("pytest", "ruff")
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_OUTPUT_TAIL_CHARS = 8_000
_HOST_MARGIN_SECONDS = 30
_DOCKER_CALL_SECONDS = 30
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
_PYTEST_PASSED = re.compile(r"\b\d+ passed\b")


class DockerError(RuntimeError):
    """A docker call failed: Docker stopped, the image is missing or changed."""


class ImageMissingError(DockerError):
    """The sandbox image has not been built."""


class Sandbox(Protocol):
    """What the review graph needs from a sandbox (a fake one stands in for it in tests)."""

    @property
    def tree(self) -> Path: ...

    def image_id(self) -> str: ...

    def plan(self, tool: SandboxTool, run_id: str, image_id: str) -> tuple[list[str], RunSpec]: ...

    def run(self, tool: SandboxTool, run_id: str, image_id: str) -> SandboxRun: ...

    def leftover_containers(self, run_id: str | None = None) -> list[str]: ...


def build_run_argv(spec: RunSpec) -> list[str]:
    return [
        "docker",
        "--host",
        f"unix://{spec.socket}",
        "run",
        "--rm",
        "--pull=never",
        "--init",
        f"--name={policy.container_name(spec)}",
        f"--label=git-reviewer.run={spec.run_id}",
        "--network=none",
        "--user=10001:10001",
        "--read-only",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m",
        f"--mount=type=bind,source={spec.tree},target=/work,readonly",
        "--workdir=/work",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=256",
        "--memory=1g",
        "--memory-swap=1g",
        "--cpus=1",
        # Docker would otherwise keep the output (which may quote secrets) in its log files.
        "--log-driver=none",
        "--env=HOME=/tmp",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        spec.image_id,
        "timeout",
        "--signal=KILL",
        f"{spec.timeout_seconds}s",
        *policy.COMMANDS[spec.tool],
    ]


class DockerSandbox:
    def __init__(self, socket: Path, image: str, timeout_seconds: int, workspace: Path) -> None:
        self._socket = socket
        self._image = image
        self._timeout = timeout_seconds
        self._tree = workspace / "tree"
        # Empty, so nothing from ~/.docker (credentials, context, plugins) is used.
        self._config = workspace / "docker-config"

    @property
    def tree(self) -> Path:
        return self._tree

    def check_daemon(self) -> None:
        result = self._docker(["version", "--format={{.Server.Version}}"])
        if result.returncode != 0 or not result.stdout.strip():
            raise DockerError(f"Docker does not answer: {_error_text(result)}")

    def image_id(self) -> str:
        result = self._docker(["image", "inspect", "--format={{.Id}}", "--", self._image])
        image_id = result.stdout.decode("ascii", "replace").strip()
        if result.returncode != 0:
            raise ImageMissingError(f"the sandbox image {self._image} is not built")
        if not _IMAGE_ID.fullmatch(image_id):
            raise DockerError("docker returned an invalid image ID")
        return image_id

    def plan(self, tool: SandboxTool, run_id: str, image_id: str) -> tuple[list[str], RunSpec]:
        spec = RunSpec(
            socket=self._socket,
            tree=self._tree,
            run_id=run_id,
            tool=tool,
            image_id=image_id,
            timeout_seconds=self._timeout,
        )
        return build_run_argv(spec), spec

    def run(self, tool: SandboxTool, run_id: str, image_id: str) -> SandboxRun:
        argv, spec = self.plan(tool, run_id, image_id)
        # The execution guardian checked the same argv; checked again here so no caller can skip it.
        policy.check(argv, spec)
        if self.image_id() != image_id:
            raise DockerError("the sandbox image changed during the review")
        started = time.monotonic()
        try:
            result = proc.run(
                "docker",
                argv[1:],
                cwd=self._config,
                timeout=self._timeout + _HOST_MARGIN_SECONDS,
                env_extra={"DOCKER_CONFIG": str(self._config)},
                max_output=MAX_OUTPUT_BYTES,
            )
        except proc.ProcTimeoutError:
            return _run(tool, "killed", None, started, "stopped by the host-side time limit")
        except proc.OutputTooLargeError:
            return _run(tool, "error", None, started, "stopped: output larger than 4 MiB")
        finally:
            self._remove(policy.container_name(spec))
        outcome, detail = _outcome(tool, result.returncode)
        output = (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace")
        if tool == "pytest" and outcome == "passed" and not _PYTEST_PASSED.search(output):
            # os._exit(0) in code the tests import ends pytest "successfully" before any test.
            outcome, detail = "error", "pytest exited 0 without reporting passed tests"
        return _run(tool, outcome, result.returncode, started, detail, output)

    def leftover_containers(self, run_id: str | None = None) -> list[str]:
        """Containers of one run, or of every run when `run_id` is None."""
        label = "git-reviewer.run" if run_id is None else f"git-reviewer.run={run_id}"
        result = self._docker(
            ["ps", "--all", "--no-trunc", f"--filter=label={label}", "--format={{.ID}}"]
        )
        if result.returncode != 0:
            raise DockerError(f"cannot list containers: {_error_text(result)}")
        ids = result.stdout.decode("ascii", "replace").split()
        if not all(_CONTAINER_ID.fullmatch(container) for container in ids):
            raise DockerError("docker returned an invalid container ID")
        return ids

    def _remove(self, name: str) -> None:
        # Normally already gone (--rm); this also covers a timeout or a killed docker client.
        # Called from `finally`, so it must not replace the run's result: if the removal fails,
        # the leftover-container check that always follows blocks the review.
        with contextlib.suppress(DockerError, proc.ProcError):
            self._docker(["rm", "--force", "--", name])

    def _docker(self, args: Sequence[str]) -> proc.Result:
        try:
            return proc.run(
                "docker",
                ["--host", f"unix://{self._socket}", *args],
                cwd=self._config,
                timeout=_DOCKER_CALL_SECONDS,
                env_extra={"DOCKER_CONFIG": str(self._config)},
            )
        except proc.ProcTimeoutError as exc:
            raise DockerError("Docker did not answer in time") from exc


@contextmanager
def sandbox_session(socket: Path, image: str, timeout_seconds: int) -> Generator[DockerSandbox]:
    """A sandbox with a private workspace (mode 0700), removed afterwards."""
    with tempfile.TemporaryDirectory(prefix="git-reviewer-sandbox-") as tmp:
        # Resolved (on macOS /var is a link to /private/var): Docker must get the real path.
        workspace = Path(tmp).resolve()
        for name in ("tree", "docker-config"):
            (workspace / name).mkdir(mode=0o700)
        yield DockerSandbox(socket, image, timeout_seconds, workspace)


def _outcome(tool: SandboxTool, code: int) -> tuple[SandboxOutcome, str]:
    if code == 125:
        return "error", "Docker could not start the container"
    if code in {126, 127}:
        return "error", "the command could not run in the sandbox image"
    if code in {124, 137}:
        return "killed", "stopped by the sandbox time or memory limit"
    if code == 0:
        return "passed", ""
    if code == 1:
        return "failed", ""
    if tool == "pytest" and code == 5:
        return "no_tests", "no tests were collected"
    return "error", f"{tool} could not run normally"


def _run(
    tool: SandboxTool,
    outcome: SandboxOutcome,
    code: int | None,
    started: float,
    detail: str,
    output: str = "",
) -> SandboxRun:
    return SandboxRun(
        tool=tool,
        outcome=outcome,
        exit_code=code,
        seconds=round(time.monotonic() - started, 2),
        detail=detail,
        output=output[-_OUTPUT_TAIL_CHARS:],
    )


def _error_text(result: proc.Result) -> str:
    text = result.stderr.decode("utf-8", "replace").strip()
    return text[:300] or f"exit code {result.returncode}"

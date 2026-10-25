from __future__ import annotations

import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from git_reviewer.sandbox import policy
from git_reviewer.sandbox.docker import build_run_argv
from git_reviewer.sandbox.policy import RunSpec

RUN_ID = "0123456789abcdef0123456789abcdef"
IMAGE_ID = "sha256:" + "ab" * 32


@pytest.fixture
def spec() -> Iterator[RunSpec]:
    """A spec on a real private sandbox workspace, as the policy requires."""
    with tempfile.TemporaryDirectory(prefix="git-reviewer-sandbox-") as tmp:
        tree = Path(tmp).resolve() / "tree"
        tree.mkdir()
        yield RunSpec(
            socket=Path("/var/run/docker.sock"),
            tree=tree,
            run_id=RUN_ID,
            tool="pytest",
            image_id=IMAGE_ID,
            timeout_seconds=300,
        )


def changed(spec: RunSpec, **fields: object) -> RunSpec:
    return RunSpec(**{**spec.__dict__, **fields})  # type: ignore[arg-type]


def replaced(spec: RunSpec, old: str, new: str) -> list[str]:
    command = build_run_argv(spec)
    assert old in command
    return [new if arg == old else arg for arg in command]


def test_the_builder_satisfies_the_policy(spec: RunSpec) -> None:
    for tool in policy.COMMANDS:
        tool_spec = changed(spec, tool=tool)
        assert policy.problems(build_run_argv(tool_spec), tool_spec) == []


def test_required_options_are_pinned() -> None:
    # A third copy of the sandbox options: weakening the policy also needs a change here, in
    # a test the security gate reads (SECURITY.md T-15).
    assert policy.REQUIRED_OPTIONS == (
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
    # -P: the reviewed code never comes first on sys.path (the image appends it).
    assert policy.COMMANDS["pytest"][:4] == ("python", "-P", "-m", "pytest")


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("--network=none", "--network=host"),
        ("--network=none", "--network=bridge"),
        ("--user=10001:10001", "--user=0:0"),
        ("--read-only", "--privileged"),
        ("--cap-drop=ALL", "--cap-add=SYS_ADMIN"),
        ("--security-opt=no-new-privileges", "--security-opt=seccomp=unconfined"),
        ("--memory-swap=1g", "--memory-swap=-1"),
        ("--pids-limit=256", "--pids-limit=-1"),
        ("--pull=never", "--pull=always"),
        ("--env=HOME=/tmp", "--env=HOME"),
        ("--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m", "--tmpfs=/tmp:rw,exec"),
    ],
)
def test_weakened_options_are_rejected(spec: RunSpec, old: str, new: str) -> None:
    assert policy.problems(replaced(spec, old, new), spec)


def test_writable_or_foreign_mount_is_rejected(spec: RunSpec) -> None:
    mount = f"--mount=type=bind,source={spec.tree},target=/work,readonly"
    assert policy.problems(replaced(spec, mount, mount.removesuffix(",readonly")), spec)
    other = "--mount=type=bind,source=/Users/me,target=/work,readonly"
    assert policy.problems(replaced(spec, mount, other), spec)


@pytest.mark.parametrize(
    "extra",
    [
        ["--volume=/var/run/docker.sock:/var/run/docker.sock"],
        ["-v", "/:/host"],
        ["--env-file=.env"],
        ["--env=AWS_SECRET_ACCESS_KEY"],
        ["--env=PYTHONPATH=/work"],
        ["--device=/dev/kvm"],
        ["--pid=host"],
        ["--mount=type=bind,source=/Users/me/.ssh,target=/ssh,readonly"],
    ],
)
def test_extra_options_are_rejected(spec: RunSpec, extra: list[str]) -> None:
    command = build_run_argv(spec)
    command[4:4] = extra
    assert policy.problems(command, spec)


def test_dropped_option_is_rejected(spec: RunSpec) -> None:
    command = [arg for arg in build_run_argv(spec) if arg != "--network=none"]
    assert "missing option --network=none" in policy.problems(command, spec)


def test_other_endpoint_image_or_command_is_rejected(spec: RunSpec) -> None:
    assert policy.problems(
        replaced(spec, "unix:///var/run/docker.sock", "tcp://10.0.0.5:2375"), spec
    )
    assert policy.problems(replaced(spec, IMAGE_ID, "python:3.12"), spec)
    assert policy.problems([*build_run_argv(spec), "--deselect", "tests"], spec)
    assert policy.problems(replaced(spec, "pytest", "sh"), spec)


@pytest.mark.parametrize(
    "tree",
    [
        Path.home(),
        Path.home() / ".ssh",
        Path("/"),
        Path("/var/run"),
        Path(tempfile.gettempdir()).resolve() / "tree",
        Path(tempfile.gettempdir()).resolve() / "git-reviewer-sandbox-missing" / "tree",
    ],
)
def test_the_mount_must_be_the_private_sandbox_copy(spec: RunSpec, tree: Path) -> None:
    # Even when the builder and the spec agree, a mount outside the sandbox copy is refused.
    unsafe = changed(spec, tree=tree)
    assert policy.problems(build_run_argv(unsafe), unsafe)


def test_a_sandbox_copy_others_can_read_is_rejected(spec: RunSpec) -> None:
    spec.tree.parent.chmod(0o755)
    assert any("private" in problem for problem in policy.problems(build_run_argv(spec), spec))


@pytest.mark.parametrize(
    "fields",
    [{"run_id": "../../etc"}, {"timeout_seconds": 99_999}, {"tool": "bash"}],
)
def test_unsafe_specs_are_rejected(spec: RunSpec, fields: dict[str, object]) -> None:
    unsafe = changed(spec, **fields)
    argv = build_run_argv(spec)  # an unknown tool has no command: check against a valid argv
    assert policy.problems(argv, unsafe)


def test_check_raises_on_any_problem(spec: RunSpec) -> None:
    with pytest.raises(policy.PolicyViolationError, match="network"):
        policy.check(replaced(spec, "--network=none", "--network=host"), spec)

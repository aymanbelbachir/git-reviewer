"""Structural rules from docs/ARCHITECTURE.md §2: effects live in a few audited modules only."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "git_reviewer"
SUBPROCESS_MODULES = {"proc.py"}
EFFECT_MODULES = {
    "proc.py",
    "git/snapshot.py",
    "sandbox/docker.py",
    "patch/apply.py",
    "hook/install.py",
}
FORBIDDEN_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "remove"),
    ("os", "unlink"),
    ("os", "rename"),
    ("os", "replace"),
    ("os", "chmod"),
    ("os", "symlink"),
    ("os", "mkdir"),
    ("os", "makedirs"),
    ("shutil", "rmtree"),
    ("shutil", "copytree"),
    ("shutil", "move"),
}
FORBIDDEN_METHODS = {"write_text", "write_bytes", "unlink", "rmdir", "mkdir", "symlink_to", "chmod"}


def modules() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def relative(path: Path) -> str:
    return path.relative_to(SRC).as_posix()


@pytest.mark.parametrize("path", modules(), ids=relative)
def test_subprocess_only_in_proc(path: Path) -> None:
    if relative(path) in SUBPROCESS_MODULES:
        return
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            names = {(node.module or "").split(".")[0]}
        else:
            continue
        assert "subprocess" not in names, f"{relative(path)} imports subprocess"


@pytest.mark.parametrize("path", modules(), ids=relative)
def test_no_shell_true_anywhere(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "shell":
            assert isinstance(node.value, ast.Constant) and node.value.value is False


@pytest.mark.parametrize("path", modules(), ids=relative)
def test_file_writes_only_in_effect_modules(path: Path) -> None:
    if relative(path) in EFFECT_MODULES:
        return
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                assert (func.value.id, func.attr) not in FORBIDDEN_CALLS, (
                    f"{relative(path)} calls {func.value.id}.{func.attr}"
                )
            assert func.attr not in FORBIDDEN_METHODS, f"{relative(path)} calls .{func.attr}()"
        if _is_open_for_writing(node):
            pytest.fail(f"{relative(path)} opens a file for writing")


def _is_open_for_writing(node: ast.Call) -> bool:
    func = node.func
    is_open = (isinstance(func, ast.Name) and func.id == "open") or (
        isinstance(func, ast.Attribute) and func.attr == "open"
    )
    if not is_open:
        return False
    is_os_open = isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
    if is_os_open and func.value.id == "os":  # type: ignore[union-attr]
        return _os_open_may_write(node)
    # open(path, mode) has the mode second; Path.open(mode) has it first.
    position = 1 if isinstance(func, ast.Name) else 0
    modes = node.args[position : position + 1] + [
        kw.value for kw in node.keywords if kw.arg == "mode"
    ]
    for mode in modes:
        if not isinstance(mode, ast.Constant) or not isinstance(mode.value, str):
            return True
        if set(mode.value) & {"w", "a", "x", "+"}:
            return True
    return False


_OS_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC", "O_EXCL"}


def _os_open_may_write(node: ast.Call) -> bool:
    """os.open(path, flags): read-only only when the flags are spelled out and none of them
    writes. Flags held in a variable count as writing."""
    flags = node.args[1:2] + [kw.value for kw in node.keywords if kw.arg == "flags"]
    if not flags:
        return True
    names: set[str] = set()
    for sub in ast.walk(flags[0]):
        if isinstance(sub, ast.Attribute):
            names.add(sub.attr)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            names.add(sub.value)
        elif isinstance(sub, ast.Name) and sub.id not in {"os", "getattr"}:
            return True
    return bool(names & _OS_WRITE_FLAGS)


@pytest.mark.parametrize(
    ("source", "writes"),
    [
        ("os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))", False),
        ("os.open(p, os.O_WRONLY | os.O_CREAT)", True),
        ("os.open(p, flags)", True),
        ("open(p, 'rb')", False),
        ("Path(p).open('a')", True),
    ],
)
def test_write_detection(source: str, writes: bool) -> None:
    call = ast.parse(source, mode="eval").body
    assert isinstance(call, ast.Call)
    assert _is_open_for_writing(call) is writes


_FORBIDDEN_GIT_COMMANDS = {"add", "commit", "push", "update-index", "update-ref", "reset", "stash"}


@pytest.mark.parametrize("path", modules(), ids=relative)
def test_no_git_command_that_stages_commits_or_pushes(path: Path) -> None:
    """The tool never stages, commits or pushes (docs/SPEC.md security requirement 4; R4.6)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.List | ast.Tuple) and node.elts:
            first = node.elts[0]
            if isinstance(first, ast.Constant) and first.value in _FORBIDDEN_GIT_COMMANDS:
                pytest.fail(f"{relative(path)} builds a git {first.value} command")


# Where the user's own git configuration lives (aliases, pager, diff drivers...). Only the
# read-only core.hooksPath lookup at hook installation passes them on (docs/ARCHITECTURE.md §7,
# §13); config.py reads XDG_CONFIG_HOME to find git-reviewer's own settings file.
_USER_CONFIG_ENV = {"HOME", "XDG_CONFIG_HOME", "GIT_CONFIG_SYSTEM"}
_USER_CONFIG_ENV_MODULES = {"proc.py", "config.py", "hook/install.py"}


@pytest.mark.parametrize("path", modules(), ids=relative)
def test_user_configuration_is_passed_only_by_hook_installation(path: Path) -> None:
    if relative(path) in _USER_CONFIG_ENV_MODULES:
        return
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value in _USER_CONFIG_ENV:
            pytest.fail(f"{relative(path)} uses {node.value}")

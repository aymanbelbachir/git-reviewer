"""Structural rules from docs/ARCHITECTURE.md §2: effects live in a few audited modules only."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "git_reviewer"
SUBPROCESS_MODULES = {"proc.py"}
EFFECT_MODULES = {
    "proc.py",
    "git/worktree.py",
    "sandbox/docker.py",
    "patch/apply.py",
    "hook/install.py",
    "report/write.py",
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

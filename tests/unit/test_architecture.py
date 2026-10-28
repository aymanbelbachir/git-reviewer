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
    ("os", "renames"),
    ("os", "replace"),
    ("os", "chmod"),
    ("os", "fchmod"),
    ("os", "lchmod"),
    ("os", "symlink"),
    ("os", "link"),
    ("os", "truncate"),
    ("os", "mkdir"),
    ("os", "makedirs"),
    ("os", "rmdir"),
    ("os", "removedirs"),
    ("os", "mkfifo"),
    ("shutil", "rmtree"),
    ("shutil", "copytree"),
    ("shutil", "copy"),
    ("shutil", "copy2"),
    ("shutil", "copyfile"),
    ("shutil", "copyfileobj"),
    ("shutil", "copymode"),
    ("shutil", "copystat"),
    ("shutil", "move"),
    ("os", "utime"),
    ("os", "mknod"),
    ("tempfile", "mkstemp"),
    ("tempfile", "mkdtemp"),
    ("tempfile", "NamedTemporaryFile"),
    ("tempfile", "TemporaryFile"),
    ("tempfile", "SpooledTemporaryFile"),
    ("tempfile", "TemporaryDirectory"),
}
FORBIDDEN_METHODS = {
    "write_text",
    "write_bytes",
    "unlink",
    "rmdir",
    "mkdir",
    "symlink_to",
    "hardlink_to",
    "chmod",
    "lchmod",
    "rename",
    "touch",
}


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
        if (problem := _write_problem(node)) is not None:
            pytest.fail(f"{relative(path)} {problem}")


_WRITING_MODULES = {"os", "shutil", "tempfile"}


def _write_problem(node: ast.AST) -> str | None:
    """How `node` could write a file outside the effect modules, or None."""
    if isinstance(node, ast.Import):
        # An alias (`import os as o`) would hide every call below from this check.
        aliased = [a.name for a in node.names if a.name in _WRITING_MODULES and a.asname]
        return f"imports {aliased[0]} under another name" if aliased else None
    if isinstance(node, ast.ImportFrom) and node.module in _WRITING_MODULES:
        names = [a.name for a in node.names if (node.module, a.name) in FORBIDDEN_CALLS]
        return f"imports {node.module}.{names[0]}" if names else None
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and (func.value.id, func.attr) in FORBIDDEN_CALLS:
            return f"calls {func.value.id}.{func.attr}"
        if func.attr in FORBIDDEN_METHODS:
            return f"calls .{func.attr}()"
        # Path.replace(target) takes one argument; str.replace(old, new) takes two or more.
        arguments = len(node.args) + sum(1 for kw in node.keywords if kw.arg == "target")
        if func.attr == "replace" and arguments == 1 and len(node.keywords) <= 1:
            return "calls .replace(target)"
    if _is_open_for_writing(node):
        return "opens a file for writing"
    return None


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


@pytest.mark.parametrize(
    ("source", "writes"),
    [
        ("temporary.replace(target)", True),
        ("temporary.replace(target=dest)", True),
        ("text.replace('a', 'b')", False),
        ("when.replace(year=2000)", False),
        ("chained.rename(target)", True),
        ("Path(p).touch()", True),
        ("Path(p).hardlink_to(q)", True),
        ("os.link(a, b)", True),
        ("shutil.copy(a, b)", True),
        ("tempfile.mkdtemp()", True),
        ("from tempfile import NamedTemporaryFile", True),
        ("tempfile.gettempdir()", False),
        ("os.utime(p)", True),
        ("from os import replace", True),
        ("from os import path", False),
        ("import shutil as sh", True),
        ("import os", False),
    ],
)
def test_write_detection_of_moves_links_and_imports(source: str, writes: bool) -> None:
    node = ast.parse(source).body[0]
    target = node.value if isinstance(node, ast.Expr) else node
    assert (_write_problem(target) is not None) is writes


# Commands that change the index, HEAD, the branches or the remote. Not "rm": the same list
# check would flag `docker rm`, and the sandbox runner needs it.
_FORBIDDEN_GIT_COMMANDS = {
    "add",
    "am",
    "apply",
    "checkout",
    "cherry-pick",
    "commit",
    "commit-tree",
    "merge",
    "mv",
    "push",
    "rebase",
    "reset",
    "restore",
    "revert",
    "stash",
    "switch",
    "update-index",
    "update-ref",
}
# Global options of git that take the next element as their value.
_GIT_OPTIONS_WITH_VALUE = {"-c", "-C", "--attr-source", "--git-dir", "--work-tree", "--namespace"}


def _git_subcommand(node: ast.List | ast.Tuple) -> str | None:
    """The first element after git's global options (`-c name=value`, `--literal-pathspecs`...),
    when it is written in the code."""
    elements = iter(node.elts)
    for element in elements:
        if isinstance(element, ast.Starred) or _is_formatted_option(element):
            continue  # a spread of options, such as HARDENING_CONFIG, or f"--work-tree={tree}"
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return None
        if element.value == "--":
            return None
        if element.value in _GIT_OPTIONS_WITH_VALUE:
            next(elements, None)
        elif not element.value.startswith("-"):
            return element.value
    return None


def _is_formatted_option(element: ast.expr) -> bool:
    if not isinstance(element, ast.JoinedStr) or not element.values:
        return False
    start = element.values[0]
    return isinstance(start, ast.Constant) and str(start.value).startswith("-")


@pytest.mark.parametrize("path", modules(), ids=relative)
def test_no_git_command_that_stages_commits_or_pushes(path: Path) -> None:
    """The tool never stages, commits or pushes (docs/SPEC.md security requirement 4; R4.6)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.List | ast.Tuple):
            command = _git_subcommand(node)
            if command in _FORBIDDEN_GIT_COMMANDS:
                pytest.fail(f"{relative(path)} builds a git {command} command")


@pytest.mark.parametrize(
    ("source", "command"),
    [
        ('["commit", "-m", "x"]', "commit"),
        ('["-c", "core.hooksPath=/dev/null", "commit"]', "commit"),
        ('[*HARDENING_CONFIG, "--literal-pathspecs", "push"]', "push"),
        ('["--attr-source", tree, "add", "-A"]', "add"),
        ('[f"--work-tree={tree}", "commit"]', "commit"),
        ('[f"{name}", "commit"]', None),
        ('["diff", "--cached", "--", "add"]', "diff"),
        ('["--", "commit"]', None),
        ("[program, 'commit']", None),
    ],
)
def test_git_subcommand_detection(source: str, command: str | None) -> None:
    node = ast.parse(source, mode="eval").body
    assert isinstance(node, ast.List)
    assert _git_subcommand(node) == command


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

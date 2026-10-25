from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer.models import FileChange
from git_reviewer.patch import policy

DOC = Path(__file__).resolve().parents[2] / "docs" / "ARCHITECTURE.md"


def change(path: str, status: str = "modified", binary: bool = False) -> FileChange:
    return FileChange.model_validate(
        {"path": path, "status": status, "binary": binary, "added_lines": frozenset({1})}
    )


def test_a_python_file_of_the_change_may_be_patched() -> None:
    assert policy.problems("src/app.py", [change("src/app.py")]) == []


def test_the_deny_list_matches_the_architecture_document() -> None:
    # docs/ARCHITECTURE.md §11 is the single source of the deny list (checklist R4.3).
    text = DOC.read_text(encoding="utf-8")
    section = text[text.index("2. `patch.policy`") : text.index("3. Then, in this order")]
    not_entries = {"patch.policy", "lstat", "..", ".GIT/config", ".git/config", ".", "_", "-", "/"}
    entries = set(re.findall(r"`([^`]+)`", section)) - not_entries
    documented_dirs = {e.rstrip("/").casefold() for e in entries if e.endswith("/")}
    documented_patterns = {e.casefold() for e in entries if "*" in e}
    documented_names = {e.casefold() for e in entries if "*" not in e and not e.endswith("/")}
    assert documented_dirs == set(policy.DENIED_DIRS)
    assert documented_patterns == set(policy.DENIED_PATTERNS)
    assert documented_names == set(policy.DENIED_NAMES)


def denied_examples() -> list[str]:
    examples = [f"{directory}/x.py" for directory in sorted(policy.DENIED_DIRS)]
    examples += [f"pkg/{name}" for name in sorted(policy.DENIED_NAMES)]
    examples += ["requirements-dev.txt", "constraints.txt", "Pipfile.lock", "Dockerfile.dev"]
    examples += ["evil.pth", ".git-reviewer.toml"]
    return examples


@pytest.mark.parametrize("path", denied_examples())
def test_every_deny_list_entry_is_enforced(path: str) -> None:
    assert policy.denied(path)
    assert any("never patched" in problem for problem in policy.problems(path, [change(path)]))


@pytest.mark.parametrize(
    "path",
    [".GIT/hooks/x.py", ".Github/workflows/x.py", "sub/CONFTEST.py", "SetUp.py", "évil.pth"],
)
def test_case_and_unicode_variants_are_denied(path: str) -> None:
    assert policy.denied(path)


@pytest.mark.parametrize(
    ("path", "files", "message"),
    [
        ("other.py", [change("app.py")], "not a file of the reviewed change"),
        ("gone.py", [change("gone.py", "deleted")], "not a file of the reviewed change"),
        ("blob.py", [change("blob.py", binary=True)], "not a file of the reviewed change"),
        ("notes.md", [change("notes.md")], "only Python files"),
        ("../etc/passwd.py", [change("../etc/passwd.py")], "not normalized"),
        ("/etc/x.py", [change("/etc/x.py")], "not normalized"),
        ("a b.py", [change("a b.py")], "plain relative paths"),
        ("x\x1b.py", [change("x\x1b.py")], "plain relative paths"),
    ],
)
def test_other_paths_are_refused(path: str, files: list[FileChange], message: str) -> None:
    assert any(message in problem for problem in policy.problems(path, files))


def test_on_disk_checks(make_repo: Callable[..., Path], tmp_path: Path) -> None:
    repo = make_repo({"pkg/app.py": "x = 1\n"})
    assert policy.on_disk_problems(repo, "pkg/app.py") == []
    (repo / "link.py").symlink_to(repo / "pkg" / "app.py")
    assert "symbolic link" in policy.on_disk_problems(repo, "link.py")[0]
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_text("x = 1\n")
    (repo / "linked").symlink_to(outside)
    assert "symbolic link" in policy.on_disk_problems(repo, "linked/app.py")[0]
    assert "does not exist" in policy.on_disk_problems(repo, "missing.py")[0]

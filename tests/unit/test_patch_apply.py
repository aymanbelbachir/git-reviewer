"""Applying an accepted patch to the working tree (patch.apply)."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer.git.diff import collect_staged
from git_reviewer.llm.structured import PatchEditOutput
from git_reviewer.models import Diff, FixProposal, FixTarget
from git_reviewer.patch.apply import PatchApplyError, apply_patch
from git_reviewer.patch.edits import apply_edits, unified_diff
from tests.helpers import LIMITS, git
from tests.helpers import stage as staged

ORIGINAL = "def run(name):\n    return name\n"
PATCHED_LINE = "    return name.strip()\n"


def proposal(path: str = "app.py", original: str = ORIGINAL) -> FixProposal:
    edit = PatchEditOutput(path=path, start_line=2, end_line=2, replacement=PATCHED_LINE)
    patched = apply_edits(original, [edit], path)
    target = FixTarget(
        source="reviewer", rule="bug", file=path, line=2, severity="high", message="m"
    )
    return FixProposal(
        target=target,
        file=path,
        explanation="strip",
        diff=unified_diff(path, original, patched),
        patched=patched,
        original_sha256=hashlib.sha256(original.encode()).hexdigest(),
    )


@pytest.fixture
def repo(make_repo: Callable[..., Path]) -> Path:
    return staged(make_repo, {"app.py": ORIGINAL})


def diff_of(repo: Path) -> Diff:
    return collect_staged(repo, LIMITS)


def test_applies_to_the_working_tree_only(repo: Path) -> None:
    head = git(repo, "rev-parse", "HEAD").stdout
    index = git(repo, "ls-files", "--stage").stdout
    apply_patch(repo, diff_of(repo).files, proposal())
    assert (repo / "app.py").read_text() == "def run(name):\n    return name.strip()\n"
    # Nothing staged, nothing committed.
    assert git(repo, "ls-files", "--stage").stdout == index
    assert git(repo, "rev-parse", "HEAD").stdout == head


def test_a_file_changed_since_the_review_is_not_patched(repo: Path) -> None:
    files = diff_of(repo).files
    (repo / "app.py").write_text(ORIGINAL + "# edited after the review\n")
    with pytest.raises(PatchApplyError, match="changed since the review"):
        apply_patch(repo, files, proposal())
    assert (repo / "app.py").read_text().endswith("# edited after the review\n")


def test_a_file_swapped_for_a_symlink_is_not_patched(repo: Path, tmp_path: Path) -> None:
    files = diff_of(repo).files
    target = tmp_path / "elsewhere.py"
    target.write_text(ORIGINAL)
    (repo / "app.py").unlink()
    (repo / "app.py").symlink_to(target)
    with pytest.raises(PatchApplyError, match="symbolic link"):
        apply_patch(repo, files, proposal())
    assert target.read_text() == ORIGINAL


def test_denied_or_foreign_files_are_never_patched(make_repo: Callable[..., Path]) -> None:
    repo = staged(make_repo, {"setup.py": ORIGINAL, "app.py": ORIGINAL})
    files = diff_of(repo).files
    with pytest.raises(PatchApplyError, match="never patched"):
        apply_patch(repo, files, proposal("setup.py"))
    with pytest.raises(PatchApplyError, match="not a file of the reviewed change"):
        apply_patch(repo, [f for f in files if f.path != "app.py"], proposal())


def test_the_file_mode_is_kept_and_no_temporary_file_is_left(repo: Path) -> None:
    (repo / "app.py").chmod(0o755)
    apply_patch(repo, diff_of(repo).files, proposal())
    assert oct((repo / "app.py").stat().st_mode & 0o777) == "0o755"
    assert sorted(p.name for p in repo.iterdir() if p.name != ".git") == ["README.md", "app.py"]


def test_a_leftover_temporary_file_is_never_followed(repo: Path, tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("untouched\n")
    (repo / ".app.py.git-reviewer-new").symlink_to(victim)
    with pytest.raises(PatchApplyError, match="already exists"):
        apply_patch(repo, diff_of(repo).files, proposal())
    assert victim.read_text() == "untouched\n"
    assert (repo / "app.py").read_text() == ORIGINAL


def test_an_edit_saved_while_applying_is_never_overwritten(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from git_reviewer.patch import apply as apply_module

    real_fchmod = apply_module.os.fchmod

    def editor_saves(fd: int, mode: int) -> None:
        real_fchmod(fd, mode)
        (repo / "app.py").write_text(ORIGINAL + "# saved by the editor\n")

    monkeypatch.setattr(apply_module.os, "fchmod", editor_saves)
    with pytest.raises(PatchApplyError, match="changed while the patch was being applied"):
        apply_patch(repo, diff_of(repo).files, proposal())
    assert (repo / "app.py").read_text().endswith("# saved by the editor\n")
    assert not (repo / ".app.py.git-reviewer-new").exists()

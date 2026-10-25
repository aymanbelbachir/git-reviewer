"""The tree copied into the sandbox, and the fingerprint of the user's working directory."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer.git.diff import collect_range, collect_staged
from git_reviewer.git.snapshot import SnapshotError, export_tree
from git_reviewer.sandbox import fingerprint as fingerprint_module
from git_reviewer.sandbox.fingerprint import FingerprintError, fingerprint
from tests.helpers import LIMITS, git, write_files


def files_in(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_staged_tree_is_the_index_not_the_working_tree(
    make_repo: Callable[..., Path], tmp_path: Path
) -> None:
    repo = make_repo({"src/app.py": "x = 1\n", "tests/test_app.py": "def test(): pass\n"})
    write_files(repo, {"src/app.py": "x = 2\n"})
    git(repo, "add", "src/app.py")
    write_files(repo, {"src/app.py": "x = 3  # not staged\n", ".env": "SECRET=1\n"})
    dest = tmp_path / "tree"
    dest.mkdir()
    export = export_tree(repo, collect_staged(repo, LIMITS), dest)
    assert files_in(dest) == {"src/app.py": b"x = 2\n", "tests/test_app.py": b"def test(): pass\n"}
    assert export.files == 2
    assert not (dest / ".git").exists()


def test_range_tree_is_the_head_commit(make_repo: Callable[..., Path], tmp_path: Path) -> None:
    repo = make_repo({"a.py": "x = 1\n"})
    git(repo, "checkout", "-q", "-b", "feature")
    write_files(repo, {"a.py": "x = 2\n", "b.py": "y = 1\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "feature")
    git(repo, "checkout", "-q", "main")
    dest = tmp_path / "tree"
    dest.mkdir()
    export_tree(repo, collect_range(repo, "main..feature", LIMITS), dest)
    assert files_in(dest) == {"a.py": b"x = 2\n", "b.py": b"y = 1\n"}


def test_modes_are_readable_by_the_sandbox_user_whatever_the_umask(
    make_repo: Callable[..., Path], tmp_path: Path
) -> None:
    repo = make_repo({"run.sh": "#!/bin/sh\n", "pkg/data.txt": "data\n"})
    git(repo, "update-index", "--chmod=+x", "run.sh")
    dest = tmp_path / "tree"
    dest.mkdir()
    previous = os.umask(0o077)
    try:
        export_tree(repo, collect_staged(repo, LIMITS), dest)
    finally:
        os.umask(previous)
    mode = {path: oct(path.stat().st_mode & 0o777) for path in [dest, dest / "pkg"]}
    assert mode == {dest: "0o755", dest / "pkg": "0o755"}
    assert oct((dest / "run.sh").stat().st_mode & 0o777) == "0o755"
    assert oct((dest / "pkg" / "data.txt").stat().st_mode & 0o777) == "0o644"


def test_symlinks_and_submodules_are_not_materialized(
    make_repo: Callable[..., Path], tmp_path: Path
) -> None:
    repo = make_repo({"a.py": "x = 1\n"})
    (repo / "ssh_keys").symlink_to(Path.home() / ".ssh")
    git(repo, "add", "ssh_keys")
    commit = git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{commit},vendor/lib")
    dest = tmp_path / "tree"
    dest.mkdir()
    export = export_tree(repo, collect_staged(repo, LIMITS), dest)
    assert export.skipped == ("ssh_keys", "vendor/lib")
    assert not (dest / "ssh_keys").exists() and not (dest / "ssh_keys").is_symlink()
    assert sorted(files_in(dest)) == ["a.py"]


def test_destination_must_be_empty(make_repo: Callable[..., Path], tmp_path: Path) -> None:
    repo = make_repo()
    dest = tmp_path / "tree"
    dest.mkdir()
    (dest / "planted.py").write_text("x = 1\n")
    with pytest.raises(SnapshotError, match="not empty"):
        export_tree(repo, collect_staged(repo, LIMITS), dest)


def test_too_many_files_is_refused(
    make_repo: Callable[..., Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from git_reviewer.git import snapshot

    repo = make_repo({f"f{i}.py": "x = 1\n" for i in range(5)})
    monkeypatch.setattr(snapshot, "MAX_TREE_FILES", 3)
    dest = tmp_path / "tree"
    dest.mkdir()
    with pytest.raises(SnapshotError, match="more than 3 files"):
        export_tree(repo, collect_staged(repo, LIMITS), dest)


def test_large_trees_are_read_in_batches(
    make_repo: Callable[..., Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from git_reviewer.git import snapshot

    files = {f"f{i}.txt": f"{i}\n" * 1000 for i in range(6)}
    repo = make_repo(files)
    monkeypatch.setattr(snapshot, "MAX_SNAPSHOT_BYTES", 6000)
    dest = tmp_path / "tree"
    dest.mkdir()
    export_tree(repo, collect_staged(repo, LIMITS), dest)
    assert {name: data.decode() for name, data in files_in(dest).items()} == files


# --- fingerprint ------------------------------------------------------------------------------


@pytest.fixture
def repo(make_repo: Callable[..., Path]) -> Path:
    repo = make_repo({"a.py": "x = 1\n", ".gitignore": "ignored/\n"})
    write_files(repo, {"untracked.txt": "u\n", "ignored/big.bin": "i\n"})
    return repo


def test_fingerprint_is_stable(repo: Path) -> None:
    assert fingerprint(repo) == fingerprint(repo)


@pytest.mark.parametrize(
    "change",
    [
        lambda repo: (repo / "a.py").write_text("x = 2\n"),
        lambda repo: (repo / "a.py").unlink(),
        lambda repo: (repo / "a.py").chmod(0o755),
        lambda repo: (repo / "untracked.txt").write_text("changed\n"),
        lambda repo: (repo / "new_file.py").write_text("planted\n"),
        lambda repo: (repo / ".git" / "config").write_text("[core]\n\thooksPath = /tmp/evil\n"),
        lambda repo: (repo / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\ncurl x\n"),
        lambda repo: (repo / ".git" / "HEAD").write_text("ref: refs/heads/evil\n"),
        lambda repo: (repo / "link.py").symlink_to("/etc/passwd"),
    ],
)
def test_fingerprint_detects_changes(repo: Path, change: Callable[[Path], object]) -> None:
    before = fingerprint(repo)
    change(repo)
    assert fingerprint(repo) != before


def test_symlink_retarget_is_detected(repo: Path) -> None:
    (repo / "link").symlink_to("a.py")
    before = fingerprint(repo)
    (repo / "link").unlink()
    (repo / "link").symlink_to("/etc/passwd")
    assert fingerprint(repo) != before


def test_ignored_files_are_left_out(repo: Path) -> None:
    before = fingerprint(repo)
    (repo / "ignored" / "big.bin").write_text("changed\n")
    assert fingerprint(repo) == before


def test_too_large_working_directory_fails_closed(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fingerprint_module, "MAX_FINGERPRINT_BYTES", 3)
    with pytest.raises(FingerprintError, match="too large"):
        fingerprint(repo)


def test_a_change_staged_during_the_review_is_never_copied_or_scanned(
    make_repo: Callable[..., Path], tmp_path: Path
) -> None:
    from git_reviewer.git.snapshot import reviewed_files

    repo = make_repo()
    write_files(repo, {"a.py": "x = 1\n"})
    git(repo, "add", "-A")
    diff = collect_staged(repo, LIMITS)
    # While the model answers, an IDE stages a conftest.py nobody reviewed.
    write_files(repo, {"tests/conftest.py": "import os\nos.system('id')\n"})
    git(repo, "add", "-A")
    dest = tmp_path / "tree"
    dest.mkdir()
    with pytest.raises(SnapshotError, match="changed during the review"):
        export_tree(repo, diff, dest)
    with (
        pytest.raises(SnapshotError, match="changed during the review"),
        reviewed_files(repo, diff),
    ):
        pass
    assert not any(dest.iterdir())


def test_fingerprint_covers_the_shared_git_directory_of_a_linked_worktree(
    make_repo: Callable[..., Path], tmp_path: Path
) -> None:
    repo = make_repo()
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-q", "-b", "wt", str(linked))
    changes = [
        lambda: (repo / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\ncurl x\n"),
        lambda: (repo / ".git" / "config").write_text("[core]\n\tfsmonitor = /tmp/evil\n"),
        lambda: (repo / ".git" / "info" / "exclude").write_text("planted.py\n"),
    ]
    for change in changes:
        before = fingerprint(linked)
        change()
        assert fingerprint(linked) != before


def test_an_unreadable_file_fails_closed_with_its_name(repo: Path) -> None:
    secret = repo / "unreadable.txt"
    secret.write_text("x\n")
    secret.chmod(0)
    try:
        with pytest.raises(FingerprintError, match=r"unreadable\.txt"):
            fingerprint(repo)
    finally:
        secret.chmod(0o600)

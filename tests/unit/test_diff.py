from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer.git.diff import (
    DiffLimits,
    DiffTooLargeError,
    UnsafePathError,
    collect_range,
    collect_staged,
)
from tests.helpers import git, write_files

LIMITS = DiffLimits(max_bytes=1024 * 1024, max_files=200, max_line_chars=10_000)


def test_empty_when_nothing_is_staged(make_repo: Callable[..., Path]) -> None:
    diff = collect_staged(make_repo(), LIMITS)
    assert diff.files == ()


def test_staged_changes_and_added_lines(make_repo: Callable[..., Path]) -> None:
    repo = make_repo({"app.py": "a = 1\nb = 2\nc = 3\n", "old.txt": "bye\n"})
    write_files(repo, {"app.py": "a = 1\nb = 20\nc = 3\nd = 4\n", "new.py": "x = 1\n"})
    (repo / "old.txt").unlink()
    git(repo, "add", "-A")
    diff = collect_staged(repo, LIMITS)
    by_path = {change.path: change for change in diff.files}
    assert by_path["app.py"].status == "modified"
    assert by_path["app.py"].added_lines == {2, 4}
    assert by_path["new.py"].status == "added"
    assert by_path["new.py"].added_lines == {1}
    assert by_path["old.txt"].status == "deleted"
    assert by_path["old.txt"].added_lines == frozenset()
    assert diff.added_line_count == 3


def test_unstaged_changes_are_ignored(make_repo: Callable[..., Path]) -> None:
    repo = make_repo({"app.py": "a = 1\n"})
    write_files(repo, {"app.py": "a = 2\n"})
    assert collect_staged(repo, LIMITS).files == ()


def test_binary_file_is_flagged(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    write_files(repo, {"logo.bin": bytes(range(256)) * 4})
    git(repo, "add", "logo.bin")
    (change,) = collect_staged(repo, LIMITS).files
    assert change.binary is True
    assert change.added_lines == frozenset()


def test_unusual_but_safe_file_names(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    names = ["with space.py", "été/café.py", 'quote"name.py', "tab" + chr(0xA0) + "nbsp.py"]
    write_files(repo, dict.fromkeys(names, "x = 1\n"))
    git(repo, "add", "-A")
    paths = {change.path for change in collect_staged(repo, LIMITS).files}
    assert paths == set(names)


def test_control_characters_in_file_names_are_refused(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    write_files(repo, {"evil\x1b[31m.py": "x = 1\n"})
    git(repo, "add", "-A")
    with pytest.raises(UnsafePathError):
        collect_staged(repo, LIMITS)


def test_diff_over_the_byte_limit_is_not_reviewed(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    write_files(repo, {"big.py": "x = 1\n" * 5000})
    git(repo, "add", "-A")
    with pytest.raises(DiffTooLargeError):
        collect_staged(repo, DiffLimits(max_bytes=4096, max_files=200, max_line_chars=10_000))


def test_too_many_files_is_not_reviewed(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    write_files(repo, {f"f{i}.py": "x = 1\n" for i in range(5)})
    git(repo, "add", "-A")
    with pytest.raises(DiffTooLargeError):
        collect_staged(repo, DiffLimits(max_bytes=1024 * 1024, max_files=3, max_line_chars=10_000))


def test_overlong_line_is_not_reviewed(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    write_files(repo, {"min.js": "a" * 500 + "\n"})
    git(repo, "add", "-A")
    with pytest.raises(DiffTooLargeError):
        collect_staged(repo, DiffLimits(max_bytes=1024 * 1024, max_files=200, max_line_chars=100))


def test_range_reviews_what_head_adds_since_the_merge_base(
    make_repo: Callable[..., Path],
) -> None:
    repo = make_repo({"shared.py": "v = 1\n"})
    git(repo, "checkout", "-q", "-b", "feature")
    write_files(repo, {"feature.py": "f = 1\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "feature work")
    git(repo, "checkout", "-q", "main")
    write_files(repo, {"main_only.py": "m = 1\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "main work")
    diff = collect_range(repo, "main..feature", LIMITS)
    assert [change.path for change in diff.files] == ["feature.py"]
    assert diff.mode == "range"


def test_textconv_and_external_diff_drivers_are_not_run(
    make_repo: Callable[..., Path], tmp_path: Path
) -> None:
    marker = tmp_path / "driver-ran"
    repo = make_repo()
    write_files(repo, {".gitattributes": "*.py diff=evil\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "attributes")
    git(repo, "config", "diff.evil.textconv", f"touch {marker} && cat")
    git(repo, "config", "diff.external", f"touch {marker} && true")
    write_files(repo, {"a.py": "x = 1\n"})
    git(repo, "add", "-A")
    collect_staged(repo, LIMITS)
    assert not marker.exists()


def test_sha256_repositories_are_supported(tmp_path: Path) -> None:
    repo = tmp_path / "repo256"
    repo.mkdir()
    git(repo, "init", "-q", "--object-format=sha256", "-b", "main")
    write_files(repo, {".gitattributes": "* -diff\n", "a.py": "x = 1\n"})
    git(repo, "add", "-A")
    by_path = {change.path: change for change in collect_staged(repo, LIMITS).files}
    assert by_path["a.py"].added_lines == {1}


def test_file_replaced_by_symlink(make_repo: Callable[..., Path]) -> None:
    repo = make_repo({"a.py": "x = 1\n", "b.py": "y = 2\n"})
    (repo / "a.py").unlink()
    (repo / "a.py").symlink_to("b.py")
    git(repo, "add", "-A")
    (change,) = collect_staged(repo, LIMITS).files
    assert change.path == "a.py"
    assert change.status == "type_changed"
    assert change.added_lines == {1}


def test_symlink_replaced_by_file(make_repo: Callable[..., Path]) -> None:
    repo = make_repo({"b.py": "y = 2\n"})
    (repo / "a.py").symlink_to("b.py")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "link")
    (repo / "a.py").unlink()
    write_files(repo, {"a.py": "import os\nos.system('id')\n"})
    git(repo, "add", "-A")
    (change,) = collect_staged(repo, LIMITS).files
    assert change.status == "type_changed"
    assert change.added_lines == {1, 2}


def test_line_numbers_survive_suppress_blank_empty(make_repo: Callable[..., Path]) -> None:
    repo = make_repo({"a.py": "a = 1\n\nc = 3\nd = 4\n"})
    git(repo, "config", "diff.suppressBlankEmpty", "true")
    write_files(repo, {"a.py": "a = 1\n\nc = 3\nd = 40\n"})
    git(repo, "add", "-A")
    (change,) = collect_staged(repo, LIMITS).files
    assert change.added_lines == {4}


def test_diff_relative_config_is_ignored(make_repo: Callable[..., Path]) -> None:
    repo = make_repo({"sub/a.py": "a = 1\n", "b.py": "b = 1\n"})
    git(repo, "config", "diff.relative", "true")
    write_files(repo, {"sub/a.py": "a = 2\n", "b.py": "b = 2\n"})
    git(repo, "add", "-A")
    assert {change.path for change in collect_staged(repo, LIMITS).files} == {"sub/a.py", "b.py"}


def test_missing_final_newline_and_crlf(make_repo: Callable[..., Path]) -> None:
    repo = make_repo({"a.py": "a = 1\r\nb = 2"})
    write_files(repo, {"a.py": "a = 1\r\nb = 3\r\nc = 4"})
    git(repo, "add", "-A")
    (change,) = collect_staged(repo, LIMITS).files
    assert change.added_lines == {2, 3}

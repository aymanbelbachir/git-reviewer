from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer.llm.structured import PatchEditOutput
from git_reviewer.patch.edits import (
    EditError,
    added_lines,
    apply_edits,
    numbered,
    split_lines,
    unified_diff,
)
from tests.helpers import git, write_files

ORIGINAL = "a = 1\nb = 2\nc = 3\n"


def edit(start: int, end: int, replacement: str, path: str = "m.py") -> PatchEditOutput:
    return PatchEditOutput(path=path, start_line=start, end_line=end, replacement=replacement)


@pytest.mark.parametrize(
    ("edits", "expected"),
    [
        ([edit(2, 2, "b = 20\n")], "a = 1\nb = 20\nc = 3\n"),
        ([edit(2, 1, "x = 0\n")], "a = 1\nx = 0\nb = 2\nc = 3\n"),
        ([edit(4, 3, "d = 4")], "a = 1\nb = 2\nc = 3\nd = 4\n"),
        ([edit(1, 2, "")], "c = 3\n"),
        ([edit(3, 3, "c = 30\n"), edit(1, 1, "a = 10\n")], "a = 10\nb = 2\nc = 30\n"),
    ],
)
def test_edits(edits: list[PatchEditOutput], expected: str) -> None:
    assert apply_edits(ORIGINAL, edits, "m.py") == expected


@pytest.mark.parametrize(
    ("edits", "message"),
    [
        ([edit(1, 1, "x\n", path="other.py")], "only m.py"),
        ([edit(5, 4, "x\n")], "out of range"),
        ([edit(2, 9, "x\n")], "out of range"),
        ([edit(1, 2, "x\n"), edit(2, 3, "y\n")], "overlap"),
        ([edit(2, 2, "b = 2\n")], "change nothing"),
        ([edit(1, 1, "x = 1\n" * 300)], "limit"),
    ],
)
def test_invalid_edits_are_refused(edits: list[PatchEditOutput], message: str) -> None:
    with pytest.raises(EditError, match=message):
        apply_edits(ORIGINAL, edits, "m.py")


def test_lines_are_split_on_newlines_only_like_git() -> None:
    # str.splitlines would also split on U+2028 and shift every following line number.
    text = f"s = 'a{chr(0x2028)}b'\nt = 1\n"
    assert len(split_lines(text)) == 2
    assert apply_edits(text, [edit(2, 2, "t = 2\n")], "m.py").endswith("t = 2\n")


def test_numbered_view() -> None:
    assert numbered(ORIGINAL).splitlines()[1] == "    2| b = 2"


def test_added_lines_use_the_new_line_numbers() -> None:
    patched = apply_edits(ORIGINAL, [edit(2, 1, "x = 0\n"), edit(3, 3, "c = 9\n")], "m.py")
    assert added_lines(ORIGINAL, patched) == [(2, "x = 0"), (4, "c = 9")]


@pytest.mark.parametrize(
    "original",
    ["a = 1\nb = 2\nc = 3\n", "a = 1\nb = 2\nc = 3"],
    ids=["final-newline", "no-final-newline"],
)
def test_the_generated_diff_is_accepted_by_git_apply(
    make_repo: Callable[..., Path], original: str
) -> None:
    repo = make_repo({"m.py": original})
    patched = apply_edits(original, [edit(3, 3, "c = 30\n"), edit(1, 1, "a = 10\n")], "m.py")
    diff = unified_diff("m.py", original, patched)
    write_files(repo, {"m.patch": diff})
    git(repo, "apply", "--check", "m.patch")
    git(repo, "apply", "m.patch")
    assert (repo / "m.py").read_text() == patched

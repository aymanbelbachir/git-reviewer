from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer.git.refs import RefError, merge_base, parse_range, resolve_commit
from tests.helpers import git, write_files


def test_parse_range() -> None:
    assert parse_range("main..feature") == ("main", "feature")


@pytest.mark.parametrize("spec", ["main...feature", "main", "..feature", "main..", "a..b..c"])
def test_parse_range_refuses_other_forms(spec: str) -> None:
    with pytest.raises(RefError):
        parse_range(spec)


def test_resolve_commit_returns_full_id(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    object_id = resolve_commit(repo, "HEAD")
    assert len(object_id) == 40
    assert resolve_commit(repo, "main") == object_id


@pytest.mark.parametrize("ref", ["does-not-exist", "HEAD~5", "HEAD:README.md"])
def test_resolve_commit_refuses_unknown_or_non_commit(
    make_repo: Callable[..., Path], ref: str
) -> None:
    with pytest.raises(RefError):
        resolve_commit(make_repo(), ref)


def test_merge_base(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    start = resolve_commit(repo, "HEAD")
    git(repo, "checkout", "-q", "-b", "feature")
    write_files(repo, {"a.py": "x = 1\n"})
    git(repo, "add", "a.py")
    git(repo, "commit", "-q", "-m", "feature")
    head = resolve_commit(repo, "feature")
    assert merge_base(repo, resolve_commit(repo, "main"), head) == start


def test_merge_base_refuses_non_ids(make_repo: Callable[..., Path]) -> None:
    with pytest.raises(RefError):
        merge_base(make_repo(), "main", "HEAD")

"""Validation of user-supplied refs (docs/ARCHITECTURE.md §6.1; SECURITY.md T-21).

A ref is turned into a full commit id with `rev-parse --verify --end-of-options` before any other
use, so a value such as `--output=/tmp/x` can never reach git as an option.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from git_reviewer.git.command import run_git, stderr_text

_OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_MAX_REF_CHARS = 256


class RefError(ValueError):
    """A ref or range given by the user is invalid."""


def parse_range(spec: str) -> tuple[str, str]:
    """Split `A..B`. Three-dot ranges and single refs are refused."""
    if "..." in spec:
        raise RefError("three-dot ranges are not supported: use BASE..HEAD")
    base, separator, head = spec.partition("..")
    if not separator or not base or not head or ".." in head:
        raise RefError("expected a range of the form BASE..HEAD")
    return base, head


def resolve_commit(repo: Path, ref: str) -> str:
    """Return the full commit id for `ref`, or raise RefError."""
    _check_ref_text(ref)
    result = run_git(
        repo, ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}"]
    )
    object_id = result.stdout.decode("ascii", "replace").strip()
    if result.returncode != 0 or not _OBJECT_ID.fullmatch(object_id):
        raise RefError(f"not a commit: {ref!r}")
    return object_id


def merge_base(repo: Path, base: str, head: str) -> str:
    """Return the merge base of two commit ids already returned by `resolve_commit`."""
    for object_id in (base, head):
        if not _OBJECT_ID.fullmatch(object_id):
            raise RefError(f"not a commit id: {object_id!r}")
    result = run_git(repo, ["merge-base", base, head])
    object_id = result.stdout.decode("ascii", "replace").strip()
    if result.returncode != 0 or not _OBJECT_ID.fullmatch(object_id):
        detail = (
            stderr_text(result) or "no common ancestor (in a shallow clone, fetch more history)"
        )
        raise RefError(f"cannot find the merge base: {detail}")
    return object_id


def _check_ref_text(ref: str) -> None:
    if not ref or len(ref) > _MAX_REF_CHARS:
        raise RefError("empty or overlong ref")
    if ref.startswith("-"):
        raise RefError(f"refs cannot start with '-': {ref!r}")
    if any(unicodedata.category(char) in {"Cc", "Cf", "Zs", "Zl", "Zp"} for char in ref):
        raise RefError("refs cannot contain whitespace or control characters")

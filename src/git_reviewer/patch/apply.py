"""Apply an accepted patch to the user's working tree (effect module; docs/ARCHITECTURE.md §11,
step 5; SECURITY.md T-18, T-20).

Called only by the CLI, after the user typed "yes" on an interactive terminal. Just before
writing, everything is checked again against the working tree as it is now: the path rules, no
symlink on the path, a regular file inside the repository, and the exact bytes that were reviewed
(a file edited since the review, or with unstaged changes, is never patched).

The new content is the exact content validated in the sandbox and checked by the auditor. It is
written to a new file next to the target, then renamed over it: the rename replaces the path
itself, so a file swapped for a symlink at the last moment is replaced, never followed. No git
command is involved (git apply would also run filters selected by .gitattributes; and git 2.46
crashes in `git apply` with `--attr-source`). Nothing is staged, committed or pushed.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from pathlib import Path

from git_reviewer.models import FileChange, FixProposal
from git_reviewer.patch import policy


class PatchApplyError(RuntimeError):
    """The patch was not applied; the working tree is unchanged."""


def apply_patch(repo: Path, files: Iterable[FileChange], proposal: FixProposal) -> None:
    found = policy.problems(proposal.file, files) or policy.on_disk_problems(repo, proposal.file)
    if found:
        raise PatchApplyError("; ".join(found))
    target = repo.joinpath(*proposal.file.split("/"))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(target, flags), "rb") as handle:
        current = handle.read()
        checked = os.fstat(handle.fileno())
    mode = checked.st_mode & 0o777
    if hashlib.sha256(current).hexdigest() != proposal.original_sha256:
        raise PatchApplyError(
            f"{proposal.file} changed since the review, or has unstaged changes: the patch was "
            "made for the reviewed version"
        )
    temporary = target.with_name(f".{target.name}.git-reviewer-new")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
    except FileExistsError as exc:
        raise PatchApplyError(f"{temporary.name} already exists: remove it and retry") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(proposal.patched.encode("utf-8"))
            os.fchmod(handle.fileno(), mode)
        # An editor may have saved the file while the new content was written: never overwrite
        # what the user changed after the check.
        now = target.lstat()
        if (now.st_ino, now.st_size, now.st_mtime_ns) != (
            checked.st_ino,
            checked.st_size,
            checked.st_mtime_ns,
        ):
            raise PatchApplyError(f"{proposal.file} changed while the patch was being applied")
        temporary.replace(target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise

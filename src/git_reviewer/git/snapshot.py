"""Export the reviewed version of the changed files for static analysis (effect module).

The scanners must see exactly what is reviewed: the staged content (or the hook's index), or the
content at HEAD of a range, never the working tree, which can differ. Blobs are read from git and
written into a private temporary directory (mode 0700, files 0600) that is removed afterwards.
Only regular files are exported: symlinks and submodules are never materialized, so a link to
`~/.ssh` cannot be followed by a scanner (SECURITY.md T-18).
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from git_reviewer import proc
from git_reviewer.git.command import run_git, stderr_text
from git_reviewer.models import Diff

_REGULAR_MODES = frozenset({"100644", "100755"})
# gitleaks reads <scan root>/.gitleaksignore whatever --gitleaks-ignore-path says: never export it.
_NOT_EXPORTED = frozenset({".gitleaksignore"})
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024


class SnapshotError(RuntimeError):
    """The reviewed files could not be exported safely."""


@dataclass(frozen=True)
class Snapshot:
    root: Path
    files: tuple[str, ...]
    """Repository-relative paths that were exported (regular, non-binary, not deleted)."""

    work: Path
    """A private scratch directory next to `root`, for tool reports."""

    empty: Path
    """An empty private directory (e.g. to point gitleaks at "no ignore file")."""


@contextmanager
def reviewed_files(repo: Path, diff: Diff, *, hook: bool = False) -> Generator[Snapshot]:
    wanted = [
        c.path
        for c in diff.files
        if c.status != "deleted" and not c.binary and c.path.rsplit("/", 1)[-1] not in _NOT_EXPORTED
    ]
    with tempfile.TemporaryDirectory(prefix="git-reviewer-") as tmp:
        base = Path(tmp)
        root = base / "files"
        work = base / "work"
        empty = base / "empty"
        for directory in (root, work, empty):
            directory.mkdir(mode=0o700)
        blobs = _blob_ids(repo, diff, wanted, hook=hook)
        contents = _read_blobs(repo, sorted(set(blobs.values())), hook=hook)
        for path, object_id in sorted(blobs.items()):
            _write_private(root, path, contents[object_id])
        yield Snapshot(root=root, files=tuple(sorted(blobs)), work=work, empty=empty)


def _blob_ids(repo: Path, diff: Diff, paths: list[str], *, hook: bool) -> dict[str, str]:
    """path -> object id for the regular files among `paths`."""
    if not paths:
        return {}
    if diff.mode == "staged":
        result = run_git(repo, ["ls-files", "--stage", "-z", "--", *paths], hook=hook)
    else:
        if diff.head is None:
            raise SnapshotError("range diff without a head commit")
        result = run_git(repo, ["ls-tree", "-r", "-z", diff.head, "--", *paths])
    if result.returncode != 0:
        raise SnapshotError(f"cannot list the reviewed files: {stderr_text(result)}")
    wanted = set(paths)
    blobs: dict[str, str] = {}
    for entry in result.stdout.split(b"\x00"):
        if not entry:
            continue
        meta, _, raw_path = entry.partition(b"\t")
        fields = meta.decode("ascii", "replace").split()
        # ls-files --stage: "<mode> <id> <stage>"; ls-tree: "<mode> <type> <id>".
        mode = fields[0]
        object_id = fields[1] if diff.mode == "staged" else fields[2]
        path = raw_path.decode("utf-8", "strict")
        if path in wanted and mode in _REGULAR_MODES:
            blobs[path] = object_id
    return blobs


def _read_blobs(repo: Path, object_ids: list[str], *, hook: bool) -> dict[str, bytes]:
    if not object_ids:
        return {}
    request = "".join(f"{object_id}\n" for object_id in object_ids).encode("ascii")
    try:
        result = run_git(
            repo, ["cat-file", "--batch"], hook=hook, stdin=request, max_output=MAX_SNAPSHOT_BYTES
        )
    except proc.OutputTooLargeError as exc:
        raise SnapshotError("the reviewed files are too large to analyze") from exc
    if result.returncode != 0:
        raise SnapshotError(f"cannot read the reviewed files: {stderr_text(result)}")
    return _parse_batch(result.stdout)


def _parse_batch(output: bytes) -> dict[str, bytes]:
    contents: dict[str, bytes] = {}
    position = 0
    while position < len(output):
        header_end = output.index(b"\n", position)
        header = output[position:header_end].decode("ascii", "replace").split()
        if len(header) != 3 or header[1] != "blob":
            raise SnapshotError("unexpected answer from git cat-file")
        size = int(header[2])
        start = header_end + 1
        contents[header[0]] = output[start : start + size]
        position = start + size + 1
    return contents


def _write_private(root: Path, path: str, data: bytes) -> None:
    """Create root/path as a new 0600 file. Never follows or replaces an existing entry."""
    target = root.joinpath(*path.split("/"))
    if root not in target.parents:
        raise SnapshotError("path escapes the snapshot directory")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        # Two paths that differ only by case on a case-insensitive file system.
        raise SnapshotError("two reviewed paths map to the same file") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)

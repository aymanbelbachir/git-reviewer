"""Export the reviewed version of the repository from git (effect module).

Two exports, both read from git objects, never from the working tree, which can differ:
- `reviewed_files`: the changed files, for the scanners, in a private temporary directory
  (mode 0700, files 0600) removed afterwards;
- `export_tree`: the whole reviewed tree (the index, or HEAD of a range), for the Docker sandbox.
  It replaces a `git worktree`: nothing is written to the user's `.git`, no checkout filter or hook
  runs, and untracked files such as `.env` are never copied (T-11, T-13).
Only regular files are exported: symlinks and submodules are never materialized, so a link to
`~/.ssh` cannot be followed by a scanner or by code in the sandbox (SECURITY.md T-18).
In staged mode the index must still be the one the diff was read from: a file staged during the
review is never scanned or run without having been reviewed.
"""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from git_reviewer import proc
from git_reviewer.git.command import run_git, stderr_text
from git_reviewer.git.diff import UnsafePathError, decode_path, index_digest, staged_index
from git_reviewer.models import Diff

_REGULAR_MODES = frozenset({"100644", "100755"})
# gitleaks reads <scan root>/.gitleaksignore whatever --gitleaks-ignore-path says: never export it.
_NOT_EXPORTED = frozenset({".gitleaksignore"})
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_TREE_FILES = 20_000
MAX_TREE_BYTES = 256 * 1024 * 1024
# The sandbox user (another uid) must read the tree; the private parent directory keeps other
# local users out on the host.
_TREE_DIR_MODE = 0o755
_TREE_FILE_MODES = {"100644": 0o644, "100755": 0o755}

Entry = tuple[str, str, str]
"""(mode, object id, path) of one entry of the reviewed tree."""


class SnapshotError(RuntimeError):
    """The reviewed files could not be exported safely."""


class UnsafeTreeError(SnapshotError):
    """The reviewed tree has a path that could escape or target git itself: a security block."""


@dataclass(frozen=True)
class Snapshot:
    root: Path
    files: tuple[str, ...]
    """Repository-relative paths that were exported (regular, non-binary, not deleted)."""

    work: Path
    """A private scratch directory next to `root`, for tool reports."""

    empty: Path
    """An empty private directory (e.g. to point gitleaks at "no ignore file")."""


@dataclass(frozen=True)
class TreeExport:
    files: int
    skipped: tuple[str, ...]
    """Paths not materialized: symlinks and submodules."""


@contextmanager
def reviewed_files(repo: Path, diff: Diff, *, hook: bool = False) -> Generator[Snapshot]:
    wanted = {
        c.path
        for c in diff.files
        if c.status != "deleted" and not c.binary and c.path.rsplit("/", 1)[-1] not in _NOT_EXPORTED
    }
    with tempfile.TemporaryDirectory(prefix="git-reviewer-") as tmp:
        base = Path(tmp)
        root = base / "files"
        work = base / "work"
        empty = base / "empty"
        for directory in (root, work, empty):
            directory.mkdir(mode=0o700)
        blobs = {
            path: object_id
            for mode, object_id, path in _entries(repo, diff, hook=hook, only=wanted)
            if mode in _REGULAR_MODES
        }
        contents = _read_blobs(repo, sorted(set(blobs.values())), hook=hook)
        for path, object_id in sorted(blobs.items()):
            _write_file(root, path, contents[object_id], file_mode=0o600, dir_mode=0o700)
        yield Snapshot(root=root, files=tuple(sorted(blobs)), work=work, empty=empty)


def export_tree(repo: Path, diff: Diff, dest: Path, *, hook: bool = False) -> TreeExport:
    """Write the whole reviewed tree into the empty directory `dest`, for the sandbox."""
    if any(dest.iterdir()):
        raise SnapshotError("the sandbox directory is not empty")
    entries = _entries(repo, diff, hook=hook)
    paths_by_blob: dict[str, list[tuple[str, int]]] = {}
    for mode, object_id, path in entries:
        if mode in _REGULAR_MODES:
            paths_by_blob.setdefault(object_id, []).append((path, _TREE_FILE_MODES[mode]))
    files = sum(len(paths) for paths in paths_by_blob.values())
    skipped = tuple(sorted(path for mode, _id, path in entries if mode not in _REGULAR_MODES))
    if files > MAX_TREE_FILES:
        raise SnapshotError(f"the repository has more than {MAX_TREE_FILES} files to copy")
    sizes = _blob_sizes(repo, sorted(paths_by_blob), hook)
    if sum(sizes[blob] * len(paths) for blob, paths in paths_by_blob.items()) > MAX_TREE_BYTES:
        raise SnapshotError(f"the repository is larger than {MAX_TREE_BYTES // 2**20} MiB to copy")
    dest.chmod(_TREE_DIR_MODE)
    for batch in _size_batches(sizes):
        contents = _read_blobs(repo, batch, hook=hook, max_output=sum(sizes[i] for i in batch))
        for object_id in batch:
            for path, mode in paths_by_blob[object_id]:
                data = contents[object_id]
                _write_file(dest, path, data, file_mode=mode, dir_mode=_TREE_DIR_MODE)
    return TreeExport(files=files, skipped=skipped)


def read_tree_file(tree: Path, path: str) -> bytes:
    """A file of the sandbox copy (the reviewed version), never through a symlink."""
    target = _tree_target(tree, path)
    descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        return handle.read()


def replace_tree_file(tree: Path, path: str, data: bytes) -> None:
    """Swap the content of an existing file of the sandbox copy (to run the tests with a patch,
    then to restore the reviewed version). Written to a new file, then renamed over the old one."""
    target = _tree_target(tree, path)
    mode = target.lstat().st_mode & 0o777
    temporary = target.with_name(f".{target.name}.git-reviewer-tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        os.fchmod(handle.fileno(), mode)
    temporary.replace(target)


@contextmanager
def single_file(path: str, data: bytes) -> Generator[Snapshot]:
    """A private snapshot holding one file, to run a scanner on a patched version."""
    try:
        decode_path(path.encode("utf-8"))
    except UnsafePathError as exc:
        raise UnsafeTreeError(str(exc)) from exc
    with tempfile.TemporaryDirectory(prefix="git-reviewer-") as tmp:
        base = Path(tmp)
        root, work, empty = base / "files", base / "work", base / "empty"
        for directory in (root, work, empty):
            directory.mkdir(mode=0o700)
        _write_file(root, path, data, file_mode=0o600, dir_mode=0o700)
        yield Snapshot(root=root, files=(path,), work=work, empty=empty)


def _tree_target(tree: Path, path: str) -> Path:
    """An existing regular file of the sandbox copy, with no symlink on the way."""
    try:
        decode_path(path.encode("utf-8"))
    except UnsafePathError as exc:
        raise UnsafeTreeError(str(exc)) from exc
    current = tree
    for part in path.split("/"):
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise SnapshotError(f"{path} is not in the sandbox copy") from exc
        if stat.S_ISLNK(info.st_mode):
            raise SnapshotError(f"{path} goes through a symbolic link")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise SnapshotError(f"{path} is not a regular file")
    return current


def _entries(repo: Path, diff: Diff, *, hook: bool, only: set[str] | None = None) -> list[Entry]:
    """Every entry of the reviewed tree (or only those in `only`): the index in staged mode,
    checked to be the index the diff was read from, or the tree of the range's head commit."""
    if diff.mode == "staged":
        listing = staged_index(repo, hook=hook)
        if diff.index_digest is None or index_digest(listing) != diff.index_digest:
            raise SnapshotError("the staged changes changed during the review; review again")
    else:
        if diff.head is None:
            raise SnapshotError("range diff without a head commit")
        result = run_git(repo, ["ls-tree", "-r", "-z", "--full-tree", diff.head])
        if result.returncode != 0:
            raise SnapshotError(f"cannot list the reviewed tree: {stderr_text(result)}")
        listing = result.stdout
    wanted = None if only is None else {path.encode("utf-8") for path in only}
    entries: list[Entry] = []
    for entry in listing.split(b"\x00"):
        meta, _, raw_path = entry.partition(b"\t")
        if not entry or (wanted is not None and raw_path not in wanted):
            continue
        fields = meta.decode("ascii", "replace").split()
        # ls-files --stage: "<mode> <id> <stage>"; ls-tree: "<mode> <type> <id>".
        if diff.mode == "staged":
            mode, object_id, stage = fields
            if stage != "0":
                raise SnapshotError("the index has unmerged entries")
        else:
            mode, _type, object_id = fields
        try:
            path = decode_path(raw_path)
        except UnsafePathError as exc:
            raise UnsafeTreeError(f"unsafe path in the reviewed tree: {exc}") from exc
        entries.append((mode, object_id, path))
    return entries


def _blob_sizes(repo: Path, object_ids: list[str], hook: bool) -> dict[str, int]:
    if not object_ids:
        return {}
    request = "".join(f"{object_id}\n" for object_id in object_ids).encode("ascii")
    result = run_git(repo, ["cat-file", "--batch-check"], hook=hook, stdin=request)
    if result.returncode != 0:
        raise SnapshotError(f"cannot read the reviewed tree: {stderr_text(result)}")
    sizes: dict[str, int] = {}
    for line in result.stdout.decode("ascii", "replace").splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[1] != "blob" or not fields[2].isdigit():
            raise SnapshotError("unexpected answer from git cat-file")
        sizes[fields[0]] = int(fields[2])
    if set(sizes) != set(object_ids):
        raise SnapshotError("git did not return every object of the reviewed tree")
    return sizes


def _size_batches(sizes: dict[str, int]) -> list[list[str]]:
    """Object ids grouped so that one `cat-file --batch` reads at most MAX_SNAPSHOT_BYTES (a
    single larger blob gets its own batch)."""
    batches: list[list[str]] = []
    current: list[str] = []
    total = 0
    for object_id in sorted(sizes):
        if current and total + sizes[object_id] > MAX_SNAPSHOT_BYTES:
            batches.append(current)
            current, total = [], 0
        current.append(object_id)
        total += sizes[object_id]
    if current:
        batches.append(current)
    return batches


def _read_blobs(
    repo: Path, object_ids: list[str], *, hook: bool, max_output: int = MAX_SNAPSHOT_BYTES
) -> dict[str, bytes]:
    if not object_ids:
        return {}
    request = "".join(f"{object_id}\n" for object_id in object_ids).encode("ascii")
    # Each blob also has a header line ("<id> blob <size>") and a newline.
    overhead = 128 * len(object_ids)
    try:
        result = run_git(
            repo,
            ["cat-file", "--batch"],
            hook=hook,
            stdin=request,
            max_output=max_output + overhead,
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


def _write_file(root: Path, path: str, data: bytes, *, file_mode: int, dir_mode: int) -> None:
    """Create root/path (a path validated by decode_path) as a new file with exact modes, umask
    ignored. Never follows or replaces an existing entry."""
    parent = root
    for part in path.split("/")[:-1]:
        parent = parent / part
        try:
            parent.mkdir()
            parent.chmod(dir_mode)
        except FileExistsError:
            if parent.is_symlink() or not parent.is_dir():
                raise SnapshotError("a reviewed path is both a file and a directory") from None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(parent / path.rsplit("/", 1)[-1], flags, 0o600)
    except FileExistsError as exc:
        # Two paths that differ only by case on a case-insensitive file system.
        raise SnapshotError("two reviewed paths map to the same file") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        os.fchmod(handle.fileno(), file_mode)

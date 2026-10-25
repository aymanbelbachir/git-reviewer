"""Fingerprint of the user's working directory (docs/ARCHITECTURE.md §10.2; SECURITY.md T-13).

Taken before the sandbox runs and again after: any difference blocks. It covers what the user
would lose or commit by mistake: tracked files, untracked files that are not ignored, and git's
control files: `HEAD`, `index` and `config.worktree` of the current worktree, and the shared
`config`, `hooks/` and `info/` (exclude, attributes) of the common git directory, which is a
different directory in a linked worktree. Content is hashed; symlinks are hashed as their target
text, never followed. Any file that cannot be read is an error, never skipped. Ignored files
(`.venv/`, build output) are left out, as hashing them would make every run slow; the sandbox
never sees the working directory anyway, so this is defense in depth against a container escape.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from git_reviewer.git.command import run_git, stderr_text
from git_reviewer.git.diff import UnsafePathError, decode_path

MAX_FINGERPRINT_BYTES = 2 * 1024**3
_READ_CHUNK = 1024 * 1024
_WORKTREE_FILES = ("HEAD", "index", "config.worktree")
_COMMON_FILES = ("config",)
_COMMON_DIRS = ("hooks", "info")


class FingerprintError(RuntimeError):
    """The working directory could not be fingerprinted."""


def fingerprint(repo: Path, *, hook: bool = False) -> str:
    listing = run_git(
        repo, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], hook=hook
    )
    if listing.returncode != 0:
        raise FingerprintError(f"cannot list the working directory: {stderr_text(listing)}")
    git_dirs = run_git(
        repo,
        ["rev-parse", "--path-format=absolute", "--absolute-git-dir", "--git-common-dir"],
        hook=hook,
    )
    try:
        paths = sorted({decode_path(raw) for raw in listing.stdout.split(b"\x00") if raw})
        worktree_dir, common_dir = git_dirs.stdout.decode("utf-8", "strict").splitlines()
    except (UnsafePathError, UnicodeDecodeError, ValueError) as exc:
        raise FingerprintError(f"cannot locate the git directory: {stderr_text(git_dirs)}") from exc
    digest = hashlib.sha256()
    budget = [MAX_FINGERPRINT_BYTES]
    for path in paths:
        _add(digest, budget, "tree", path, repo.joinpath(*path.split("/")))
    for name in _WORKTREE_FILES:
        _add(digest, budget, "git", name, Path(worktree_dir) / name)
    for name in _COMMON_FILES:
        _add(digest, budget, "common", name, Path(common_dir) / name)
    for name in _COMMON_DIRS:
        _add_dir(digest, budget, name, Path(common_dir) / name)
    return digest.hexdigest()


def _add_dir(digest: hashlib._Hash, budget: list[int], name: str, directory: Path) -> None:
    """Every entry of a control directory, recursively, without following symlinks."""
    if not directory.is_dir() or directory.is_symlink():
        _add(digest, budget, "common", name, directory)
        return
    try:
        entries = sorted(directory.rglob("*"))
    except OSError as exc:
        raise FingerprintError(f"cannot read {name}: {exc.strerror}") from exc
    for entry in entries:
        _add(digest, budget, name, entry.relative_to(directory).as_posix(), entry)


def _add(digest: hashlib._Hash, budget: list[int], kind: str, name: str, path: Path) -> None:
    digest.update(f"{kind}\0{name}\0".encode("utf-8", "surrogateescape"))
    try:
        _add_entry(digest, budget, path)
    except FingerprintError:
        raise
    except OSError as exc:
        # Deleted while being read, unreadable...: unknown content is never treated as unchanged.
        raise FingerprintError(f"cannot read {name}: {exc.strerror or exc}") from exc


def _add_entry(digest: hashlib._Hash, budget: list[int], path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        digest.update(b"missing\0")
        return
    if stat.S_ISLNK(info.st_mode):
        digest.update(b"link\0" + os.fsencode(path.readlink()) + b"\0")
    elif stat.S_ISREG(info.st_mode):
        budget[0] -= info.st_size
        if budget[0] < 0:
            raise FingerprintError("the working directory is too large to fingerprint")
        digest.update(f"file\0{info.st_mode & 0o111:o}\0".encode())
        _hash_file(digest, path)
    elif stat.S_ISDIR(info.st_mode):
        digest.update(b"dir\0")  # a submodule: its own content is out of scope
    else:
        digest.update(f"other\0{stat.S_IFMT(info.st_mode):o}\0".encode())


def _hash_file(digest: hashlib._Hash, path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        while chunk := handle.read(_READ_CHUNK):
            digest.update(chunk)
        digest.update(b"\0")

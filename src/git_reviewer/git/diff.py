"""Collect and parse the diff under review (docs/ARCHITECTURE.md §6.1; SECURITY.md T-21, T-35).

The file list comes from `--name-status -z` (raw, NUL-separated paths) and is cross-checked with the
paths parsed from the patch; any mismatch stops the review instead of guessing. Limits are hard:
over a limit the diff is "not reviewed", it is never truncated.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from git_reviewer import proc, sanitize
from git_reviewer.git.command import run_git, stderr_text
from git_reviewer.git.refs import merge_base, parse_range, resolve_commit
from git_reviewer.models import Diff, FileChange, FileStatus

DIFF_FLAGS: tuple[str, ...] = (
    "--no-ext-diff",
    "--no-textconv",
    "--no-color",
    "--no-renames",
    "--no-relative",
    # A branch's .gitmodules (`ignore = all`) or local config must not hide submodule updates.
    "--ignore-submodules=none",
    "--submodule=short",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--unified=3",
)
_STATUS: dict[str, FileStatus] = {
    "A": "added",
    "M": "modified",
    "D": "deleted",
    "T": "type_changed",
}
_HUNK_HEADER = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")
# The escapes git's quote_c_style writes, besides octal.
_SIMPLE_ESCAPES = {
    "\\\\": "\\",
    '\\"': '"',
    "\\a": "\a",
    "\\b": "\b",
    "\\t": "\t",
    "\\n": "\n",
    "\\v": "\v",
    "\\f": "\f",
    "\\r": "\r",
}


@dataclass(frozen=True)
class PatchLine:
    """One line of the patch. `line` is the new-file number for added and context lines, and the
    old-file number for removed lines."""

    path: str
    kind: Literal["+", "-", " "]
    line: int
    text: str


@dataclass(frozen=True)
class _Section:
    path: str
    binary: bool
    added: set[int]
    lines: list[PatchLine]


@dataclass(frozen=True)
class DiffLimits:
    max_bytes: int
    max_files: int
    max_line_chars: int


class DiffError(RuntimeError):
    """The diff cannot be reviewed safely."""


class DiffTooLargeError(DiffError):
    """The diff is over a hard limit; it is reported as not reviewed."""


class UnsafePathError(DiffError):
    """A path in the diff contains control characters, is absolute or escapes the repository."""


class DiffParseError(DiffError):
    """The patch does not match git's own file list."""


class IndexChangedError(DiffError):
    """The staged changes changed while they were being reviewed."""


class UnmergedPathsError(DiffError):
    """The index has unresolved merge conflicts."""


def collect_staged(repo: Path, limits: DiffLimits, *, hook: bool = False) -> Diff:
    """The staged changes, what `git commit` would record (the hook's index in hook mode)."""
    before = index_digest(staged_index(repo, hook=hook))
    statuses = _name_status(repo, ["--cached"], hook=hook)
    patch = _patch(repo, ["--cached"], limits, hook=hook)
    if index_digest(staged_index(repo, hook=hook)) != before:
        raise IndexChangedError("the staged changes changed while they were read; review again")
    diff = _build("staged", None, None, statuses, patch, limits)
    return diff.model_copy(update={"index_digest": before})


def staged_index(repo: Path, *, hook: bool = False) -> bytes:
    """`git ls-files --stage -z`: every index entry with its mode and object id."""
    result = run_git(repo, ["ls-files", "--stage", "-z"], hook=hook)
    if result.returncode != 0:
        raise DiffError(f"git ls-files failed: {stderr_text(result)}")
    return result.stdout


def index_digest(listing: bytes) -> str:
    return hashlib.sha256(listing).hexdigest()


def collect_range(repo: Path, spec: str, limits: DiffLimits) -> Diff:
    """What HEAD adds on top of BASE for `BASE..HEAD`: the diff from their merge base to HEAD."""
    base_ref, head_ref = parse_range(spec)
    base = resolve_commit(repo, base_ref)
    head = resolve_commit(repo, head_ref)
    start = merge_base(repo, base, head)
    statuses = _name_status(repo, [start, head])
    patch = _patch(repo, [start, head], limits)
    return _build("range", start, head, statuses, patch, limits)


def _name_status(repo: Path, revs: list[str], *, hook: bool = False) -> dict[str, FileStatus]:
    try:
        result = run_git(repo, ["diff", *DIFF_FLAGS, "--name-status", "-z", *revs, "--"], hook=hook)
    except proc.OutputTooLargeError as exc:
        raise DiffTooLargeError("the list of changed files is too large") from exc
    if result.returncode != 0:
        raise DiffError(f"git diff --name-status failed: {stderr_text(result)}")
    fields = result.stdout.split(b"\x00")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2:
        raise DiffParseError("unexpected --name-status output")
    statuses: dict[str, FileStatus] = {}
    for raw_status, raw_path in zip(fields[0::2], fields[1::2], strict=True):
        letter = raw_status.decode("ascii", "replace")
        if letter == "U":
            raise UnmergedPathsError("resolve merge conflicts before reviewing")
        if letter not in _STATUS:
            raise DiffParseError(f"unexpected file status {letter!r}")
        path = decode_path(raw_path)
        statuses[path] = _STATUS[letter]
    return statuses


def _patch(repo: Path, revs: list[str], limits: DiffLimits, *, hook: bool = False) -> str:
    try:
        result = run_git(
            repo, ["diff", *DIFF_FLAGS, *revs, "--"], hook=hook, max_output=limits.max_bytes
        )
    except proc.OutputTooLargeError as exc:
        raise DiffTooLargeError(f"diff is larger than {limits.max_bytes} bytes") from exc
    if result.returncode != 0:
        raise DiffError(f"git diff failed: {stderr_text(result)}")
    return result.stdout.decode("utf-8", "replace")


def _build(
    mode: Literal["staged", "range"],
    base: str | None,
    head: str | None,
    statuses: dict[str, FileStatus],
    patch: str,
    limits: DiffLimits,
) -> Diff:
    if len(statuses) > limits.max_files:
        raise DiffTooLargeError(f"diff touches {len(statuses)} files (limit {limits.max_files})")
    parsed = _parse_patch(patch, statuses, limits)
    if set(parsed) != set(statuses):
        raise DiffParseError("patch paths do not match git's file list")
    files = tuple(
        FileChange(path=path, status=statuses[path], binary=binary, added_lines=frozenset(lines))
        for path, (binary, lines) in sorted(parsed.items())
    )
    return Diff(mode=mode, base=base, head=head, files=files, patch=patch)


def _parse_patch(
    patch: str, statuses: dict[str, FileStatus], limits: DiffLimits
) -> dict[str, tuple[bool, set[int]]]:
    files: dict[str, tuple[bool, set[int]]] = {}
    merged: set[str] = set()
    for section in _sections(patch):
        parsed = _parse_section(section, limits)
        path, binary, lines = parsed.path, parsed.binary, parsed.added
        if path not in files:
            files[path] = (binary, lines)
            continue
        # A type change (file to symlink or submodule, and back) is printed as a deletion followed
        # by a creation of the same path. Any other repetition is unexpected.
        if statuses.get(path) != "type_changed" or path in merged:
            raise DiffParseError("a path appears twice in the patch")
        merged.add(path)
        previous_binary, previous_lines = files[path]
        files[path] = (previous_binary or binary, previous_lines | lines)
    return files


def _sections(patch: str) -> list[list[str]]:
    sections: list[list[str]] = []
    for line in patch.split("\n"):
        if line.startswith("diff --git "):
            sections.append([line])
        elif sections:
            sections[-1].append(line)
        elif line:
            raise DiffParseError("patch does not start with a file header")
    return sections


def _parse_section(section: list[str], limits: DiffLimits) -> _Section:
    """Parse one file's patch. Hunk line counts are checked against their headers, so a
    misnumbered line (which would misplace findings, T-05) stops the review instead."""
    old_path = new_path = None
    binary = False
    added: set[int] = set()
    records: list[tuple[Literal["+", "-", " "], int, str]] = []
    line_number = old_number = old_left = new_left = 0
    in_hunks = False
    for line in section[1:]:
        if old_left or new_left:
            marker = line[:1]
            if marker == "\\":  # "\ No newline at end of file"
                continue
            if marker == "+":
                if len(line) - 1 > limits.max_line_chars:
                    raise DiffTooLargeError(
                        f"a line is longer than {limits.max_line_chars} characters"
                    )
                added.add(line_number)
                records.append(("+", line_number, line[1:]))
                line_number += 1
                new_left -= 1
            elif marker == "-":
                records.append(("-", old_number, line[1:]))
                old_number += 1
                old_left -= 1
            elif marker == " ":
                records.append((" ", line_number, line[1:]))
                line_number += 1
                old_number += 1
                old_left -= 1
                new_left -= 1
            else:
                raise DiffParseError("unexpected line inside a hunk")
            if old_left < 0 or new_left < 0:
                raise DiffParseError("a hunk is longer than its header says")
        elif line.startswith("@@"):
            match = _HUNK_HEADER.match(line)
            if match is None:
                raise DiffParseError("malformed hunk header")
            old_number = int(match.group(1))
            old_left = int(match.group(2) or "1")
            line_number = int(match.group(3))
            new_left = int(match.group(4) or "1")
            in_hunks = True
        elif line.startswith("\\") or (in_hunks and line == ""):
            continue  # "\ No newline" after a hunk's last line, or the patch's final newline
        elif in_hunks:
            raise DiffParseError("unexpected line after a hunk")
        elif line.startswith("--- "):
            old_path = _header_path(line[4:], "a/")
        elif line.startswith("+++ "):
            new_path = _header_path(line[4:], "b/")
        elif line.startswith("Binary files "):
            binary = True
    if old_left or new_left:
        raise DiffParseError("a hunk is shorter than its header says")
    path = new_path or old_path or _path_from_git_header(section[0])
    lines = [PatchLine(path, kind, number, text) for kind, number, text in records]
    return _Section(path=path, binary=binary, added=added, lines=lines)


def patch_lines(diff: Diff) -> list[PatchLine]:
    """Every line of the (already validated) patch, with its file and line number."""
    limits = DiffLimits(
        max_bytes=len(diff.patch) + 1,
        max_files=len(diff.files) + 1,
        max_line_chars=len(diff.patch) + 1,
    )
    return [
        line for section in _sections(diff.patch) for line in _parse_section(section, limits).lines
    ]


def numbered_view(diff: Diff) -> str:
    """The diff as shown to a model: one block per file, every line with its explicit number.

    Added lines read `  12 + code`, context lines `  13 | code`, removed lines `     - code`. A
    small model gets line numbers right from this far more reliably than from hunk headers.
    """
    by_path: dict[str, list[PatchLine]] = {}
    for line in patch_lines(diff):
        by_path.setdefault(line.path, []).append(line)
    blocks: list[str] = []
    for change in diff.files:
        header = f"=== FILE: {change.path} ({change.status}) ==="
        if change.binary:
            blocks.append(f"{header}\n(binary file, content not shown)")
            continue
        rows = [header]
        for line in by_path.get(change.path, []):
            if line.kind == "+":
                rows.append(f"{line.line:>6} + {line.text}")
            elif line.kind == " ":
                rows.append(f"{line.line:>6} | {line.text}")
            else:
                rows.append(f"{'':>6} - {line.text}")
        blocks.append("\n".join(rows))
    return "\n\n".join(blocks)


def _header_path(value: str, prefix: str) -> str | None:
    if value == "/dev/null":
        return None
    # Git ends the header with a tab when an unquoted name contains a space. A name with a
    # real tab is always quoted, so this tab is never part of the name.
    raw = _unquote(value) if value.startswith('"') else value.removesuffix("\t").encode("utf-8")
    if not raw.startswith(prefix.encode()):
        raise DiffParseError("unexpected path prefix in patch header")
    return decode_path(raw[len(prefix) :])


def _path_from_git_header(header: str) -> str:
    rest = header[len("diff --git ") :]
    if rest.startswith('"'):
        end = _closing_quote(rest)
        raw = _unquote(rest[: end + 1])
    else:
        # No renames, so the header is "a/<P> b/<P>" with the same path twice.
        length = (len(rest) - 5) // 2
        candidate = rest[2 : 2 + length]
        if rest != f"a/{candidate} b/{candidate}":
            raise DiffParseError("cannot read the path from a patch header")
        raw = f"a/{candidate}".encode()
    if not raw.startswith(b"a/"):
        raise DiffParseError("unexpected path prefix in patch header")
    return decode_path(raw[2:])


def _closing_quote(text: str) -> int:
    index = 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == '"':
            return index
        index += 1
    raise DiffParseError("unterminated quoted path")


def _unquote(quoted: str) -> bytes:
    """Decode a C-style quoted path as written by git (core.quotePath=true)."""
    if len(quoted) < 2 or not quoted.endswith('"'):
        raise DiffParseError("malformed quoted path")
    body = quoted[1:-1]
    out = bytearray()
    index = 0
    while index < len(body):
        if body[index] != "\\":
            out += body[index].encode("utf-8")
            index += 1
            continue
        octal = _OCTAL_ESCAPE.match(body, index)
        if octal:
            out.append(int(octal.group(1), 8))
            index = octal.end()
            continue
        pair = body[index : index + 2]
        if pair not in _SIMPLE_ESCAPES:
            raise DiffParseError("unsupported escape in quoted path")
        out += _SIMPLE_ESCAPES[pair].encode("utf-8")
        index += 2
    return bytes(out)


def decode_path(raw: bytes) -> str:
    """A repository-relative path from git output: UTF-8, no control characters, relative and
    normalized (no empty, "." or ".." component), and no `.git` component (git never tracks one;
    a crafted tree that has one targets git itself). Anything else raises UnsafePathError."""
    try:
        path = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        shown = sanitize.one_line(raw.decode("utf-8", "replace"))
        raise UnsafePathError(f"path is not valid UTF-8: {shown}") from exc
    # The offending path is named in its escaped form, so the message itself is safe to print.
    if not path or any(unicodedata.category(char) == "Cc" for char in path):
        raise UnsafePathError(f"path contains control characters: {sanitize.one_line(path)}")
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in path.split("/")):
        raise UnsafePathError(f"path is absolute or not normalized: {sanitize.one_line(path)}")
    # Case-insensitive file systems also treat ".GIT" or ".git." as ".git".
    if any(part.rstrip(". ").casefold() == ".git" for part in path.split("/")):
        raise UnsafePathError(f"path contains a .git component: {sanitize.one_line(path)}")
    return path

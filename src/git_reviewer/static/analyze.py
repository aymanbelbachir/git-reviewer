"""Static analysis step of the review graph (docs/SPEC.md "LangGraph graph"; ARCHITECTURE.md §6.4).

Runs the three scanners on the reviewed version of the changed files and keeps findings on added
lines: the review is about the change, not pre-existing code. Around them, deterministic integrity
checks make sure nothing escapes the scanners silently:
- Python files are recognized by suffix (.py, .pyi, .pyw) and by a python shebang;
- a finding beyond the last line git shows for a file means git and Python disagree on where lines
  end (a lone carriage return, an exotic encoding): the change is blocked (T-07);
- a PEP 263 encoding declaration other than UTF-8/ASCII/Latin-1 is blocked: with utf-7 or
  unicode_escape, Python decodes code that git, ruff and the model only see as a comment;
- an executable binary (.pyc, .so, .pth, wheels...) is blocked; other binaries and files bandit
  could not parse mean the change was not fully analyzed ("not reviewed");
- added suppression markers and scanner configuration edits are reported (T-08).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from git_reviewer import sanitize
from git_reviewer.git.diff import patch_lines
from git_reviewer.git.snapshot import Snapshot, reviewed_files, single_file
from git_reviewer.guardians.base import decision
from git_reviewer.models import SEVERITY_RANK, Decision, Diff, LineRef, Severity, StaticFinding
from git_reviewer.patch.edits import added_lines
from git_reviewer.static.tools import StaticAnalysisError, run_bandit, run_gitleaks, run_ruff

_PYTHON_SUFFIXES = (".py", ".pyi", ".pyw")
_PYTHON_SHEBANG = re.compile(rb"^#![^\n]*\bpython[0-9.]*\b")
_CODING_DECLARATION = re.compile(rb"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_SAFE_CODINGS = frozenset(
    {"utf-8", "utf8", "utf_8", "utf-8-sig", "ascii", "us-ascii", "latin-1", "latin1", "iso-8859-1"}
)
_EXECUTABLE_BINARY_SUFFIXES = (
    ".pyc",
    ".pyo",
    ".pyd",
    ".so",
    ".dylib",
    ".dll",
    ".whl",
    ".egg",
    ".zip",
    ".pth",
)
_SUPPRESSION_MARKERS = (
    (re.compile(r"#\s*noqa\b", re.IGNORECASE), "# noqa"),
    (re.compile(r"#\s*nosec\b", re.IGNORECASE), "# nosec"),
    (re.compile(r"gitleaks:allow", re.IGNORECASE), "gitleaks:allow"),
)
_SCANNER_CONFIG_FILES = frozenset(
    {".gitleaks.toml", ".gitleaksignore", ".bandit", "ruff.toml", ".ruff.toml"}
)
_SCANNER_CONFIG_SECTION = re.compile(r"^\s*\[tool\.(ruff|bandit)\b")
# Hardcoded passwords: rated low by bandit, never acceptable in a patch.
_ALWAYS_SERIOUS = frozenset({"B105", "B106", "B107"})
# Where Python ends a line: "\n", "\r\n", or a lone "\r".
_PYTHON_LINE_ENDS = re.compile(r"\r\n?")


@dataclass(frozen=True)
class StaticResult:
    findings: tuple[StaticFinding, ...]
    secrets: tuple[str, ...]
    """Secret values found by gitleaks: memory only, used to mask displayed text."""

    notes: tuple[str, ...]
    blocks: tuple[Decision, ...] = ()
    """Integrity problems: the change is blocked, whatever the mode."""

    incomplete: tuple[str, ...] = ()
    """Why part of the change could not be analyzed: the review is "not reviewed"."""

    coverage: tuple[tuple[str, int], ...] = ()
    """(scanner, number of files it analyzed)."""


def run_static_analysis(repo: Path, diff: Diff, *, hook: bool = False) -> StaticResult:
    with reviewed_files(repo, diff, hook=hook) as snapshot:
        python = [path for path in snapshot.files if _is_python(snapshot, path)]
        line_counts = {path: _line_count(snapshot, path) for path in snapshot.files}
        unsafe_codings = [path for path in python if not _safe_coding(snapshot, path)]
        findings = run_ruff(snapshot, python, repo)
        bandit_findings, unparsed = run_bandit(snapshot, python, repo)
        gitleaks_findings, secrets = run_gitleaks(snapshot, repo)
        exported = len(snapshot.files)
    scanned = [*findings, *bandit_findings, *gitleaks_findings]
    # A scanner message may quote a value another scanner identified as a secret.
    scanned = [
        f.model_copy(update={"message": sanitize.mask_secrets(f.message, tuple(secrets))})
        for f in scanned
    ]
    desync = [f for f in scanned if f.line > line_counts.get(f.file, 0)]
    on_added = [kept for f in scanned if (kept := _on_change(diff, f)) is not None]
    own = suppression_findings(diff)
    ordered = sorted([*on_added, *own], key=lambda f: (f.file, f.line, f.tool, f.rule))
    return StaticResult(
        findings=tuple(ordered),
        secrets=tuple(secrets),
        notes=tuple(f"bandit could not analyze {path}" for path in unparsed),
        blocks=tuple(_integrity_blocks(diff, desync, unsafe_codings)),
        incomplete=tuple(_incomplete(diff, unparsed)),
        coverage=(
            ("ruff", len(python)),
            ("bandit", len(python) - len(unparsed)),
            ("gitleaks", exported),
        ),
    )


def _on_change(diff: Diff, finding: StaticFinding) -> StaticFinding | None:
    """The finding if its statement touches an added line, anchored on the first such line:
    scanners report a multi-line call or string on one of its lines (bandit's B608 on the first
    line of a query whose `% value` was added below it), which may be unchanged."""
    if diff.is_added_line(finding.file, finding.line):
        return finding
    if finding.span is None:
        return None
    added = diff.first_added_line(finding.file, *finding.span)
    return None if added is None else finding.model_copy(update={"line": added})


def serious_findings(path: str, text: str, repo: Path) -> list[StaticFinding]:
    """The findings of ruff, bandit and gitleaks on `text` saved as `path` that a patch must not
    add (docs/ARCHITECTURE.md §11): medium severity or more, and every hardcoded password
    (bandit's B105-B107 are rated low) or secret. `repo` is the reviewed repository, where no
    scanner binary may live. Secret values stay in memory: only rule ids leave this function."""
    with single_file(path, text.encode("utf-8")) as snapshot:
        found = run_ruff(snapshot, [path], repo)
        bandit, unparsed = run_bandit(snapshot, [path], repo)
        leaks, _values = run_gitleaks(snapshot, repo)
    if unparsed:
        raise StaticAnalysisError("bandit could not parse the file")
    medium = SEVERITY_RANK["medium"]
    return [
        f
        for f in (*found, *bandit, *leaks)
        if SEVERITY_RANK[f.severity] >= medium or f.rule in _ALWAYS_SERIOUS or f.tool == "gitleaks"
    ]


def added_findings(path: str, original: str, patched: str, repo: Path) -> list[str]:
    """Why the patched version is refused by the scanners: a serious finding on a line the patch
    adds or changes (also when it only moved there, as into a new helper function), or more
    serious findings of one rule than before. An original the scanners cannot parse counts as
    having none."""
    # Line numbers as Python and the scanners count them: a lone "\r" ends a line, a U+2028 or a
    # form feed does not (`str.splitlines` would split there too). Any other count would shift the
    # numbers, and a finding on a changed line would go unnoticed.
    old, new = _PYTHON_LINE_ENDS.sub("\n", original), _PYTHON_LINE_ENDS.sub("\n", patched)
    added = {number for number, _text in added_lines(old, new)}
    after = serious_findings(path, patched, repo)
    try:
        before = Counter((f.tool, f.rule) for f in serious_findings(path, original, repo))
    except StaticAnalysisError:
        before = Counter()
    touched = [f for f in after if f.line in added or _span_touches(f.span, added)]
    reasons = [f"adds a {f.tool} finding ({f.rule}) on line {f.line}" for f in touched]
    named = {(f.tool, f.rule) for f in touched}
    more = Counter((f.tool, f.rule) for f in after) - before
    reasons += [
        f"adds a {tool} finding ({rule})"
        for tool, rule in sorted(more)
        if (tool, rule) not in named
    ]
    return list(dict.fromkeys(reasons))


def _span_touches(span: tuple[int, int] | None, lines: set[int]) -> bool:
    return span is not None and any(span[0] <= number <= span[1] for number in lines)


def suppression_findings(diff: Diff) -> list[StaticFinding]:
    """Added suppression markers and scanner configuration changes. git-reviewer ignores both,
    but other tools in the user's workflow would not."""
    findings: list[StaticFinding] = []
    for line in patch_lines(diff):
        if line.kind != "+":
            continue
        for pattern, label in _SUPPRESSION_MARKERS:
            if pattern.search(line.text):
                findings.append(
                    _own(
                        "suppression-marker",
                        line.path,
                        line.line,
                        "low",
                        f"adds a '{label}' suppression (ignored by git-reviewer, not by others)",
                    )
                )
        if line.path.endswith("pyproject.toml") and _SCANNER_CONFIG_SECTION.match(line.text):
            findings.append(
                _own(
                    "scanner-config-change",
                    line.path,
                    line.line,
                    "medium",
                    "changes ruff or bandit configuration",
                )
            )
    for change in diff.files:
        if change.path.rsplit("/", 1)[-1] in _SCANNER_CONFIG_FILES:
            first = min(change.added_lines, default=1)
            findings.append(
                _own(
                    "scanner-config-change",
                    change.path,
                    first,
                    "medium",
                    "changes the configuration of a security scanner",
                )
            )
    return findings


def _integrity_blocks(
    diff: Diff, desync: list[StaticFinding], unsafe_codings: list[str]
) -> list[Decision]:
    blocks: list[Decision] = []
    if desync:
        blocks.append(
            decision(
                "static.integrity",
                "block",
                ["a scanner saw lines git does not show (lone carriage return or exotic encoding)"],
                [LineRef(file=f.file, line=1) for f in desync],
            )
        )
    if unsafe_codings:
        blocks.append(
            decision(
                "static.integrity",
                "block",
                ["non-UTF-8 source encoding declaration: Python would decode hidden code"],
                [LineRef(file=path, line=1) for path in unsafe_codings],
            )
        )
    executables = [
        c.path
        for c in diff.files
        if c.binary
        and c.status != "deleted"
        and c.path.lower().endswith(_EXECUTABLE_BINARY_SUFFIXES)
    ]
    if executables:
        blocks.append(
            decision(
                "static.integrity",
                "block",
                ["executable binary added or changed (compiled Python, native module, archive)"],
                [LineRef(file=path, line=1) for path in executables],
            )
        )
    return blocks


def _incomplete(diff: Diff, unparsed: list[str]) -> list[str]:
    reasons: list[str] = []
    binaries = [c.path for c in diff.files if c.binary and c.status != "deleted"]
    if binaries:
        reasons.append(f"{len(binaries)} binary file(s) cannot be analyzed")
    if unparsed:
        reasons.append(f"bandit could not parse {len(unparsed)} Python file(s)")
    return reasons


def _is_python(snapshot: Snapshot, path: str) -> bool:
    if path.endswith(_PYTHON_SUFFIXES):
        return True
    return bool(_PYTHON_SHEBANG.match(_head(snapshot, path)))


def _safe_coding(snapshot: Snapshot, path: str) -> bool:
    return declared_coding_is_safe(_head(snapshot, path, lines=2))


def declared_coding_is_safe(data: bytes) -> bool:
    """A PEP 263 declaration in the first two lines, if any, names a safe encoding."""
    for line in data.split(b"\n")[:2]:
        match = _CODING_DECLARATION.match(line)
        if match:
            return match.group(1).decode("ascii", "replace").lower() in _SAFE_CODINGS
    return True


def _head(snapshot: Snapshot, path: str, *, lines: int = 1) -> bytes:
    data = snapshot.root.joinpath(*path.split("/")).read_bytes()[:4096]
    return b"\n".join(data.split(b"\n")[:lines])


def _line_count(snapshot: Snapshot, path: str) -> int:
    """Lines as git counts them: separated by LF only."""
    data = snapshot.root.joinpath(*path.split("/")).read_bytes()
    return data.count(b"\n") + (0 if not data or data.endswith(b"\n") else 1)


def _own(rule: str, path: str, line: int, severity: Severity, message: str) -> StaticFinding:
    return StaticFinding.model_validate(
        {
            "tool": "git-reviewer",
            "rule": rule,
            "file": path,
            "line": line,
            "severity": severity,
            "message": message,
        }
    )

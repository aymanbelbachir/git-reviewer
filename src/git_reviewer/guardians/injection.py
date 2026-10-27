"""Anti-injection guardian, before and after the LLM review (docs/ARCHITECTURE.md §10.1).

Before: the deterministic barrier scans the diff. Unless it blocks, an isolated guardian agent
classifies the flagged passages and every added comment, string and line of a non-Python file
(where text addressed to an AI hides; a fixed phrase list misses most of it), each with its
neighbours. It may raise the flagged passages to "suspect" or "block", the other lines only to
"suspect": an alert, since its blocks on ordinary comments and docs were mostly false. Passages are
sent in batches that fit the guardian's context: flagged ones that need too many batches block the
change; other lines left over raise an alert.
After: the reviewer's output must not contain the canary token (block) or the delimiter nonce
(suspect), even escaped, re-cased or split by punctuation; and every static finding of medium
severity or more must be mentioned by the reviewer without being downgraded, otherwise a
"probable injection" alert is raised.
"""

from __future__ import annotations

import contextlib
import json
import re
import unicodedata
from collections.abc import Iterator

from git_reviewer.git.diff import PatchLine, patch_lines
from git_reviewer.guardians import barriers
from git_reviewer.guardians.base import Row, decision, run_guardian_batches
from git_reviewer.llm import prompts
from git_reviewer.llm.structured import ChatFn
from git_reviewer.models import (
    SEVERITY_RANK,
    Decision,
    Diff,
    LineRef,
    ReviewFinding,
    StaticFinding,
)

_SCANNERS = frozenset({"ruff", "bandit", "gitleaks"})
_PYTHON_SUFFIXES = (".py", ".pyi", ".pyw")
_PROSE_MARKERS = re.compile(r"[#'\"]")
# Four or more words in a row: prose, whatever the line looks like.
_SENTENCE = re.compile(r"[^\W\d_]{2,}(?:[\s,.;:!?'\"-]+[^\W\d_]{2,}){3,}")
_CONTEXT_LINES = 1
_CROSS_CHECK_DISTANCE = 2
_DISMISSALS = (
    "false positive",
    "not an issue",
    "safe to ignore",
    "can be ignored",
    "not a problem",
)


def guard_before_review(diff: Diff, chat: ChatFn, *, context_tokens: int) -> list[Decision]:
    result = barriers.scan(diff)
    found = [decision("injection.barrier", result.verdict, result.reasons, result.lines)]
    if result.verdict == "block":
        return found
    flagged = _passages(diff, result.flagged) if result.flagged else []
    seen = set(flagged)
    prose = [row for row in _passages(diff, _prose_lines(diff)) if row not in seen]
    if not flagged and not prose:
        return found
    found += run_guardian_batches(
        "injection.agent",
        chat,
        prompts.INJECTION_GUARDIAN_SYSTEM_PROMPT,
        prompts.injection_guardian_user_prompt,
        flagged,
        context_tokens=context_tokens,
        optional=prose,
    )
    return found


def _prose_lines(diff: Diff) -> list[PatchLine]:
    """Added lines where text for a reader can hide. In Python files: comments and strings (a
    comment marker or a quote on the line, a line inside a triple-quoted string such as a docstring
    body) and, as a fail-safe when that count is wrong (a docstring opened above the hunk), any
    line that reads like a sentence. In other files: every line, lockfiles included (any file can
    be named uv.lock, and a change small enough for the reviewer fits the guardian's budget)."""
    found: list[PatchLine] = []
    inside: dict[str, bool] = {}
    for line in patch_lines(diff):
        if line.kind == "-":
            continue
        python = line.path.lower().endswith(_PYTHON_SUFFIXES)
        was_inside = inside.get(line.path, False)
        if python and (line.text.count('"""') + line.text.count("'''")) % 2:
            inside[line.path] = not was_inside
        if line.kind != "+" or not line.text.strip():
            continue
        prose = was_inside or _PROSE_MARKERS.search(line.text) or _SENTENCE.search(line.text)
        if not python or prose:
            found.append(line)
    return found


def guard_after_review(
    raw_output: str,
    findings: list[ReviewFinding],
    static_findings: tuple[StaticFinding, ...],
    *,
    canary: str,
    nonce: str,
) -> list[Decision]:
    found: list[Decision] = []
    output = _squashed(raw_output)
    if _squashed(canary) in output:
        found.append(
            decision("injection.canary", "block", ["the reviewer revealed its secret canary token"])
        )
    elif _squashed(nonce) in output:
        found.append(
            decision("injection.canary", "suspect", ["the reviewer repeated the delimiter nonce"])
        )
    else:
        found.append(decision("injection.canary", "ok"))
    # The spec's cross-check is about the scanners (ruff, bandit, gitleaks), not our own checks.
    scanned = [f for f in static_findings if f.tool in _SCANNERS]
    ignored = [static for static in scanned if _ignored_or_downgraded(static, findings)]
    if ignored:
        found.append(
            decision(
                "injection.cross_check",
                "suspect",
                [
                    "probable injection: the reviewer ignored or downgraded "
                    f"{len(ignored)} static finding(s) of medium severity or more"
                ],
                [LineRef(file=f.file, line=f.line) for f in ignored],
            )
        )
    else:
        found.append(decision("injection.cross_check", "ok"))
    return found


def _ignored_or_downgraded(static: StaticFinding, findings: list[ReviewFinding]) -> bool:
    if SEVERITY_RANK[static.severity] < SEVERITY_RANK["medium"]:
        return False
    nearby = [
        f
        for f in findings
        if f.file == static.file and abs(f.line - static.line) <= _CROSS_CHECK_DISTANCE
    ]
    if not nearby:
        return True
    downgraded = all(SEVERITY_RANK[f.severity] <= SEVERITY_RANK["low"] for f in nearby)
    dismissed = any(phrase in f.explanation.casefold() for f in nearby for phrase in _DISMISSALS)
    return downgraded or dismissed


def leaks(raw_output: str, token: str) -> bool:
    """Whether model output reveals `token` (a canary or a nonce), even disguised."""
    return _squashed(token) in _squashed(raw_output)


def _squashed(text: str) -> str:
    """Letters and digits only, compatibility-normalized and case-folded. JSON escapes are decoded
    first, so `\\u0043ANARY` or `canary - 1f2e...` still match the token."""
    decoded = [text]
    with contextlib.suppress(ValueError):
        decoded.extend(_strings(json.loads(text)))
    folded = unicodedata.normalize("NFKC", "\n".join(decoded)).casefold()
    return "".join(char for char in folded if char.isalnum())


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _passages(diff: Diff, flagged: list[PatchLine]) -> list[Row]:
    """The flagged lines with one neighbour on each side, as (`path:line: text`, line)."""
    lines = patch_lines(diff)
    wanted = set(flagged)
    keep: set[int] = set()
    for index, line in enumerate(lines):
        if line in wanted:
            keep.update(range(index - _CONTEXT_LINES, index + _CONTEXT_LINES + 1))
    rows: list[Row] = []
    for index in sorted(i for i in keep if 0 <= i < len(lines)):
        line = lines[index]
        ref = LineRef(file=line.path, line=max(line.line, 1))
        rows.append((f"{line.path}:{line.line}: {line.text}", ref))
    in_patch = set(lines)
    for line in dict.fromkeys(flagged):
        if line not in in_patch:  # flagged file names
            rows.append((f"{line.path}: file name: {line.text}", LineRef(file=line.path, line=1)))
    return rows

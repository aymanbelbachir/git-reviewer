"""Anti-injection guardian, before and after the LLM review (docs/ARCHITECTURE.md §10.1).

Before: the deterministic barrier scans the diff; when it only suspects something, an isolated
guardian agent classifies the flagged passages (with their neighbours) and may raise to "block".
Passages are sent in batches that fit the guardian's context; when they need too many batches,
the change is blocked rather than partly checked.
After: the reviewer's output must not contain the canary token (block) or the delimiter nonce
(suspect), even escaped, re-cased or split by punctuation; and every static finding of medium
severity or more must be mentioned by the reviewer without being downgraded, otherwise a
"probable injection" alert is raised.
"""

from __future__ import annotations

import contextlib
import json
import unicodedata
from collections.abc import Iterator

from git_reviewer.git.diff import PatchLine, patch_lines
from git_reviewer.guardians import barriers
from git_reviewer.guardians.base import decision, run_guardian
from git_reviewer.llm import prompts
from git_reviewer.llm.structured import ANSWER_TOKENS, ChatFn
from git_reviewer.models import (
    SEVERITY_RANK,
    Decision,
    Diff,
    LineRef,
    ReviewFinding,
    StaticFinding,
)

_SCANNERS = frozenset({"ruff", "bandit", "gitleaks"})
_CONTEXT_LINES = 1
_CROSS_CHECK_DISTANCE = 2
_MAX_BATCH_BYTES = 20_000
_MAX_GUARDIAN_CALLS = 5
_PROMPT_MARGIN_TOKENS = 1_024
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
    if result.verdict != "suspect":
        return found
    # Every token is at least one UTF-8 byte, so a batch of this many bytes always fits.
    system = prompts.INJECTION_GUARDIAN_SYSTEM_PROMPT
    budget = context_tokens - ANSWER_TOKENS - len(system.encode()) - _PROMPT_MARGIN_TOKENS
    batches = _batches(_passages(diff, result.flagged), min(_MAX_BATCH_BYTES, budget))
    if batches is None or len(batches) > _MAX_GUARDIAN_CALLS:
        found.append(
            decision(
                "injection.agent",
                "block",
                ["too many or too long suspect passages for the guardian to check them all"],
                result.lines,
            )
        )
        return found
    for text, shown in batches:
        user = prompts.injection_guardian_user_prompt(text, prompts.new_nonce())
        found.append(run_guardian("injection.agent", chat, system, user, allowed_lines=shown))
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


def _passages(diff: Diff, flagged: list[PatchLine]) -> list[tuple[str, LineRef]]:
    """The flagged lines with one neighbour on each side, as (`path:line: text`, line)."""
    lines = patch_lines(diff)
    wanted = set(flagged)
    keep: set[int] = set()
    for index, line in enumerate(lines):
        if line in wanted:
            keep.update(range(index - _CONTEXT_LINES, index + _CONTEXT_LINES + 1))
    rows: list[tuple[str, LineRef]] = []
    for index in sorted(i for i in keep if 0 <= i < len(lines)):
        line = lines[index]
        ref = LineRef(file=line.path, line=max(line.line, 1))
        rows.append((f"{line.path}:{line.line}: {line.text}", ref))
    in_patch = set(lines)
    for line in dict.fromkeys(flagged):
        if line not in in_patch:  # flagged file names
            rows.append((f"{line.path}: file name: {line.text}", LineRef(file=line.path, line=1)))
    return rows


def _batches(
    rows: list[tuple[str, LineRef]], max_bytes: int
) -> list[tuple[str, frozenset[LineRef]]] | None:
    """Group rows into batches of at most `max_bytes` UTF-8 bytes. Nothing is ever truncated:
    None when a single row is too long to be checked at all."""
    batches: list[tuple[str, frozenset[LineRef]]] = []
    texts: list[str] = []
    shown: set[LineRef] = set()
    size = 0
    for text, ref in rows:
        row_bytes = len(text.encode()) + 1
        if row_bytes > max_bytes:
            return None
        if size + row_bytes > max_bytes:
            batches.append(("\n".join(texts), frozenset(shown)))
            texts, shown, size = [], set(), 0
        texts.append(text)
        shown.add(ref)
        size += row_bytes
    if texts:
        batches.append(("\n".join(texts), frozenset(shown)))
    return batches

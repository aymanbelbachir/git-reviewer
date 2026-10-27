"""Rules common to all guardians (docs/SPEC.md "Guardian agents"; docs/ARCHITECTURE.md §10.0).

- A guardian can only alert ("suspect") or block. Decisions are combined with `worst()`, which is
  monotonic: no decision can lower another one, so a guardian never authorizes anything.
- Fail-closed: an exception, a timeout or an invalid answer is a "block".
- Isolation: each guardian call gets its own system prompt and only its own input; no tools and
  no reviewer history (the ChatFn is stateless).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from git_reviewer import audit_log
from git_reviewer.llm import prompts
from git_reviewer.llm.structured import ANSWER_TOKENS, ChatFn, GuardianOutput, ask_json
from git_reviewer.models import VERDICT_RANK, Decision, LineRef, Verdict

MAX_REASON_CHARS = 300
MAX_BATCH_BYTES = 20_000
MAX_GUARDIAN_CALLS = 5
FAILURE_PREFIX = "guardian failed"
_PROMPT_MARGIN_TOKENS = 1_024
_CAPPED_REASON = "no deterministic check flagged these lines"

Row = tuple[str, LineRef]
"""One line shown to a guardian agent (`path:line: text`) and the reference it may cite."""


def worst(decisions: Iterable[Decision]) -> Verdict:
    verdict: Verdict = "ok"
    for decision in decisions:
        if VERDICT_RANK[decision.verdict] > VERDICT_RANK[verdict]:
            verdict = decision.verdict
    return verdict


def decision(
    source: str, verdict: Verdict, reasons: Iterable[str] = (), lines: Iterable[LineRef] = ()
) -> Decision:
    unique_reasons = tuple(dict.fromkeys(r[:MAX_REASON_CHARS] for r in reasons))[:10]
    unique_lines = tuple(dict.fromkeys(lines))[:50]
    result = Decision(source=source, verdict=verdict, reasons=unique_reasons, lines=unique_lines)
    audit_log.event(
        "guardian_decision",
        source=source,
        verdict=verdict,
        reasons=len(unique_reasons),
        lines=len(unique_lines),
    )
    return result


def run_guardian(
    source: str,
    chat: ChatFn,
    system: str,
    user: str,
    *,
    allowed_lines: frozenset[LineRef] | None = None,
    max_verdict: Verdict = "block",
) -> Decision:
    """Ask a guardian agent. Any failure blocks, whatever `max_verdict` says; the agent's own
    verdict is capped at `max_verdict`. Line references outside `allowed_lines` are dropped: an
    agent cannot point the report at lines it was not shown."""
    try:
        output, _raw = ask_json(chat, system, user, GuardianOutput)
    # Fail closed on every error, timeouts and invalid answers included.
    except Exception as exc:
        return decision(source, "block", [f"{FAILURE_PREFIX} ({type(exc).__name__}): blocked"])
    lines = [LineRef(file=ref.file, line=ref.line) for ref in output.lines]
    if allowed_lines is not None:
        lines = [ref for ref in lines if ref in allowed_lines]
    verdict, reasons = output.verdict, list(output.reasons)
    if VERDICT_RANK[verdict] > VERDICT_RANK[max_verdict]:
        reasons.insert(0, f"rated {verdict}, reported as {max_verdict}: {_CAPPED_REASON}")
        verdict = max_verdict
    return decision(source, verdict, reasons, lines)


def run_guardian_batches(
    source: str,
    chat: ChatFn,
    system: str,
    user_prompt: Callable[[str, str], str],
    rows: list[Row],
    *,
    context_tokens: int,
    optional: list[Row] | None = None,
) -> list[Decision]:
    """Show every row to the agent, in batches that fit its context window. Nothing is ever
    truncated: rows that need more than MAX_GUARDIAN_CALLS batches, or a row too long for one
    batch, block, since the agent could not see everything. `optional` rows are lines no
    deterministic check flagged: they are checked with the calls left, in batches of their own,
    and raise at most an alert ("suspect"), both when the agent would block them and when they do
    not fit. On ordinary comments and docs the agent's blocks were mostly false and stopped
    honest commits. A failure still blocks."""
    # Every token is at least one UTF-8 byte, so a batch of this many bytes always fits.
    budget = context_tokens - ANSWER_TOKENS - len(system.encode()) - _PROMPT_MARGIN_TOKENS
    max_bytes = min(MAX_BATCH_BYTES, budget)
    batches = _batches(rows, max_bytes)
    if batches is None or len(batches) > MAX_GUARDIAN_CALLS:
        reason = "too many or too long passages for the guardian to check them all"
        return [decision(source, "block", [reason], [ref for _text, ref in rows])]
    fitting = [row for row in optional or [] if len(row[0].encode()) + 1 <= max_bytes]
    too_long = [ref for text, ref in optional or [] if len(text.encode()) + 1 > max_bytes]
    extra = _batches(fitting, max_bytes) or []
    room = MAX_GUARDIAN_CALLS - len(batches)
    left_over = [ref for _text, shown in extra[room:] for ref in sorted(shown, key=_ref_key)]
    found: list[Decision] = []
    if too_long:
        reason = f"{len(too_long)} line(s) too long for the guardian were not checked"
        found.append(decision(source, "suspect", [reason], too_long))
    if left_over:
        # Rows are single lines joined with newlines: count rows, not shared line references.
        count = sum(text.count("\n") + 1 for text, _shown in extra[room:])
        reason = f"{count} more line(s) were not checked: too many for the guardian's calls"
        found.append(decision(source, "suspect", [reason], left_over))
    for text, shown in batches:
        user = user_prompt(text, prompts.new_nonce())
        found.append(run_guardian(source, chat, system, user, allowed_lines=shown))
    for text, shown in extra[:room]:
        user = user_prompt(text, prompts.new_nonce())
        found.append(
            run_guardian(source, chat, system, user, allowed_lines=shown, max_verdict="suspect")
        )
    return found


def _batches(rows: list[Row], max_bytes: int) -> list[tuple[str, frozenset[LineRef]]] | None:
    """Group rows into batches of at most `max_bytes` UTF-8 bytes. None when a single row is too
    long to be checked at all."""
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


def _ref_key(ref: LineRef) -> tuple[str, int]:
    return ref.file, ref.line

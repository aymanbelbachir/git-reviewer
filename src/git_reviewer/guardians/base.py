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
) -> Decision:
    """Ask a guardian agent. Any failure blocks. Line references outside `allowed_lines` are
    dropped: an agent cannot point the report at lines it was not shown."""
    try:
        output, _raw = ask_json(chat, system, user, GuardianOutput)
    # Fail closed on every error, timeouts and invalid answers included.
    except Exception as exc:
        return decision(source, "block", [f"{FAILURE_PREFIX} ({type(exc).__name__}): blocked"])
    lines = [LineRef(file=ref.file, line=ref.line) for ref in output.lines]
    if allowed_lines is not None:
        lines = [ref for ref in lines if ref in allowed_lines]
    return decision(source, output.verdict, output.reasons, lines)


def run_guardian_batches(
    source: str,
    chat: ChatFn,
    system: str,
    user_prompt: Callable[[str, str], str],
    rows: list[Row],
    *,
    context_tokens: int,
) -> list[Decision]:
    """Show every row to the agent, in batches that fit its context window. Nothing is ever
    truncated: rows that need more than MAX_GUARDIAN_CALLS batches, or a row too long for one
    batch, block, since the agent could not see everything."""
    # Every token is at least one UTF-8 byte, so a batch of this many bytes always fits.
    budget = context_tokens - ANSWER_TOKENS - len(system.encode()) - _PROMPT_MARGIN_TOKENS
    batches = _batches(rows, min(MAX_BATCH_BYTES, budget))
    if batches is None or len(batches) > MAX_GUARDIAN_CALLS:
        reason = "too many or too long passages for the guardian to check them all"
        return [decision(source, "block", [reason], [ref for _text, ref in rows])]
    found: list[Decision] = []
    for text, shown in batches:
        user = user_prompt(text, prompts.new_nonce())
        found.append(run_guardian(source, chat, system, user, allowed_lines=shown))
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

"""Rules common to all guardians (docs/SPEC.md "Guardian agents"; docs/ARCHITECTURE.md §10.0).

- A guardian can only alert ("suspect") or block. Decisions are combined with `worst()`, which is
  monotonic: no decision can lower another one, so a guardian never authorizes anything.
- Fail-closed: an exception, a timeout or an invalid answer is a "block".
- Isolation: each guardian call gets its own system prompt and only its own input; no tools and
  no reviewer history (the ChatFn is stateless).
"""

from __future__ import annotations

from collections.abc import Iterable

from git_reviewer import audit_log
from git_reviewer.llm.structured import ChatFn, GuardianOutput, ask_json
from git_reviewer.models import VERDICT_RANK, Decision, LineRef, Verdict

MAX_REASON_CHARS = 300


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
        return decision(source, "block", [f"guardian failed ({type(exc).__name__}): blocked"])
    lines = [LineRef(file=ref.file, line=ref.line) for ref in output.lines]
    if allowed_lines is not None:
        lines = [ref for ref in lines if ref in allowed_lines]
    return decision(source, output.verdict, output.reasons, lines)

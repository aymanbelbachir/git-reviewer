"""Nodes of the review graph. Routing functions read typed state only, never model text."""

from __future__ import annotations

import json
from typing import Any, Literal

from langgraph.runtime import Runtime

from git_reviewer import sanitize
from git_reviewer.git.diff import collect_range, collect_staged, numbered_view
from git_reviewer.guardians.base import decision, worst
from git_reviewer.guardians.injection import guard_after_review, guard_before_review
from git_reviewer.llm import prompts
from git_reviewer.llm.structured import (
    ANSWER_TOKENS,
    LLMOutputError,
    ModelCallError,
    ReviewerOutput,
    ask_json,
)
from git_reviewer.models import Decision, ReviewFinding
from git_reviewer.report.model import Report, Status
from git_reviewer.static.analyze import run_static_analysis

from .state import ReviewContext, ReviewState


def collect_diff(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    ctx = runtime.context
    if ctx.range_spec is not None:
        diff = collect_range(ctx.repo, ctx.range_spec, ctx.limits)
    else:
        diff = collect_staged(ctx.repo, ctx.limits, hook=ctx.hook)
    return {"diff": diff}


def static_analysis(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    ctx = runtime.context
    result = run_static_analysis(ctx.repo, _need(state, "diff"), hook=ctx.hook)
    update: dict[str, Any] = {"static": result, "decisions": result.blocks}
    if result.incomplete:
        update["not_reviewed"] = "; ".join(result.incomplete)
    return update


def injection_guard_pre(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    ctx = runtime.context
    found = guard_before_review(
        _need(state, "diff"), ctx.guardian, context_tokens=ctx.model_context_tokens
    )
    return {"decisions": tuple(found)}


def llm_review(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    ctx = runtime.context
    diff, static = _need(state, "diff"), _need(state, "static")
    view = numbered_view(diff)
    static_json = json.dumps([f.model_dump() for f in static.findings], ensure_ascii=False)
    size = len(view) + len(static_json)
    if size > ctx.max_review_chars:
        return {
            "not_reviewed": f"the change is too large for the model "
            f"({size} characters, limit {ctx.max_review_chars})"
        }
    canary, nonce = prompts.new_canary(), prompts.new_nonce()
    system = prompts.reviewer_system_prompt(canary)
    user = prompts.reviewer_user_prompt(view, static_json, nonce)
    # Ollama silently drops the start of a prompt that does not fit its context (system prompt and
    # canary included). Two UTF-8 bytes per token is a conservative estimate; the model call also
    # checks the token count Ollama reports.
    estimated = len((system + user).encode("utf-8")) // 2 + ANSWER_TOKENS
    if estimated > ctx.model_context_tokens:
        return {
            "not_reviewed": f"the change may not fit the model context "
            f"(about {estimated} tokens, context {ctx.model_context_tokens})"
        }
    try:
        review, raw = ask_json(ctx.reviewer, system, user, ReviewerOutput)
    except LLMOutputError as exc:
        return {"not_reviewed": f"the review model's answer was rejected: {exc}"}
    except ModelCallError as exc:
        return {"not_reviewed": f"the review model failed: {exc}"}
    kept = [f for f in review.findings if diff.is_added_line(f.file, f.line)]
    dropped = len(review.findings) - len(kept)
    decisions: list[Decision] = []
    if dropped:
        decisions.append(
            decision(
                "review.line_check",
                "suspect",
                [f"{dropped} reviewer finding(s) pointed outside the added lines and were dropped"],
            )
        )
    return {
        "review": ReviewerOutput(findings=kept, summary=review.summary),
        "raw_review": raw,
        "canary": canary,
        "nonce": nonce,
        "decisions": tuple(decisions),
    }


def injection_guard_post(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    found = guard_after_review(
        _need(state, "raw_review"),
        _need(state, "review").findings,
        _need(state, "static").findings,
        canary=_need(state, "canary"),
        nonce=_need(state, "nonce"),
    )
    return {"decisions": tuple(found)}


def final_report(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    diff = state.get("diff")
    static = state.get("static")
    review = state.get("review")
    decisions = state.get("decisions", ())
    secrets = static.secrets if static else ()
    status: Status
    if diff is None or not diff.files:
        status = "empty"
    elif worst(decisions) == "block":
        status = "blocked"
    elif "not_reviewed" in state:
        status = "not_reviewed"
    else:
        status = "reviewed"
    report = Report(
        status=status,
        mode=diff.mode if diff else None,
        files=diff.files if diff else (),
        static_findings=static.findings if static else (),
        review_findings=tuple(_masked_finding(f, secrets) for f in review.findings)
        if review
        else (),
        summary=sanitize.mask_secrets(review.summary, secrets) if review else "",
        decisions=tuple(_masked_decision(d, secrets) for d in decisions),
        notes=static.notes if static else (),
        coverage=static.coverage if static else (),
        reason=state.get("not_reviewed"),
    )
    return {"report": report}


def route_after_collect(state: ReviewState) -> Literal["static_analysis", "final_report"]:
    return "static_analysis" if _need(state, "diff").files else "final_report"


def route_after_pre(state: ReviewState) -> Literal["llm_review", "final_report"]:
    if worst(state.get("decisions", ())) == "block" or "not_reviewed" in state:
        return "final_report"
    return "llm_review"


def route_after_review(state: ReviewState) -> Literal["injection_guard_post", "final_report"]:
    return "final_report" if "not_reviewed" in state else "injection_guard_post"


def _need(state: ReviewState, key: str) -> Any:
    """A key earlier nodes must have set. Missing means a wiring bug: fail, never guess."""
    if key not in state:
        raise RuntimeError(f"review graph state is missing {key!r}")
    return state[key]  # type: ignore[literal-required]


def _masked_finding(finding: ReviewFinding, secrets: tuple[str, ...]) -> ReviewFinding:
    return finding.model_copy(
        update={
            "title": sanitize.mask_secrets(finding.title, secrets),
            "explanation": sanitize.mask_secrets(finding.explanation, secrets),
        }
    )


def _masked_decision(found: Decision, secrets: tuple[str, ...]) -> Decision:
    reasons = tuple(sanitize.mask_secrets(reason, secrets) for reason in found.reasons)
    return found.model_copy(update={"reasons": reasons})

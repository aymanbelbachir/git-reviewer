"""Nodes of the review graph. Routing functions read typed state only, never model text."""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal

from langgraph.runtime import Runtime

from git_reviewer import proc, sanitize
from git_reviewer.git.diff import collect_range, collect_staged, numbered_view
from git_reviewer.git.snapshot import SnapshotError, UnsafeTreeError, export_tree
from git_reviewer.guardians import execution
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
from git_reviewer.models import Decision, FixProposal, PatchAttempt, ReviewFinding, SandboxRun
from git_reviewer.report.model import Report, Status
from git_reviewer.sandbox.docker import SANDBOX_TOOLS, DockerError, Sandbox
from git_reviewer.sandbox.fingerprint import FingerprintError, fingerprint
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
        _need(state, "diff"), ctx.guardian, context_tokens=ctx.guardian_context_tokens
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


def execution_guard_pre(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    ctx = runtime.context
    sandbox = _sandbox(ctx)
    run_id = uuid.uuid4().hex
    try:
        image_id = sandbox.image_id()
    except (DockerError, proc.ProcError) as exc:
        return {"sandbox_note": f"tests not run: {exc}"}
    plans = [sandbox.plan(tool, run_id, image_id) for tool in SANDBOX_TOOLS]
    found = [execution.check_argv(plans)]
    if found[0].verdict != "block":
        found += execution.check_test_changes(
            _need(state, "diff"), ctx.guardian, context_tokens=ctx.guardian_context_tokens
        )
    return {"decisions": tuple(found), "run_id": run_id, "image_id": image_id}


def sandbox_tests(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    ctx = runtime.context
    sandbox = _sandbox(ctx)
    try:
        exported = export_tree(ctx.repo, _need(state, "diff"), sandbox.tree, hook=ctx.hook)
        before = fingerprint(ctx.repo, hook=ctx.hook)
    except UnsafeTreeError as exc:
        found = decision("execution.tree", "block", [str(exc)])
        return {"decisions": (found,), "sandbox_note": "tests not run: unsafe reviewed tree"}
    except (SnapshotError, FingerprintError, proc.ProcError) as exc:
        return {"sandbox_note": f"tests not run: {exc}"}
    update: dict[str, Any] = {"fingerprint": before, "sandbox_skipped": exported.skipped}
    runs: list[SandboxRun] = []
    try:
        for tool in SANDBOX_TOOLS:
            runs.append(sandbox.run(tool, _need(state, "run_id"), _need(state, "image_id")))
    except (DockerError, proc.ProcError) as exc:
        update["sandbox_note"] = f"the sandbox failed: {exc}"
    update["sandbox_runs"] = tuple(runs)
    return update


def execution_guard_post(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    ctx = runtime.context
    before = state.get("fingerprint")
    after: str | Exception | None = None
    if before is not None:
        try:
            after = fingerprint(ctx.repo, hook=ctx.hook)
        except (FingerprintError, proc.ProcError) as exc:
            after = exc
    leftovers: list[str] | Exception
    try:
        leftovers = _sandbox(ctx).leftover_containers(_need(state, "run_id"))
    except (DockerError, proc.ProcError) as exc:
        leftovers = exc
    return {"decisions": tuple(execution.guard_after_run(before, after, leftovers))}


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
        notes=(*(static.notes if static else ()), *_sandbox_notes(state)),
        coverage=static.coverage if static else (),
        reason=state.get("not_reviewed"),
        tests_requested=state.get("run_tests", False),
        sandbox_runs=tuple(
            run.model_copy(update={"output": sanitize.mask_secrets(run.output, secrets)})
            for run in state.get("sandbox_runs", ())
        ),
        sandbox_note=state.get("sandbox_note"),
        fix_requested=state.get("fix", False),
        fix=_masked_fix(_offerable(state.get("fix_proposal"), secrets), secrets),
        fix_attempts=tuple(
            _masked_attempt(attempt, secrets) for attempt in state.get("fix_attempts", ())
        ),
        fix_note=_fix_note(state, secrets),
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


def route_after_post(state: ReviewState) -> Literal["execution_guard_pre", "final_report"]:
    if worst(state.get("decisions", ())) == "block" or not state.get("run_tests", False):
        return "final_report"
    return "execution_guard_pre"


def route_after_execution_post(state: ReviewState) -> Literal["prepare_fix", "final_report"]:
    if worst(state.get("decisions", ())) == "block" or not state.get("fix", False):
        return "final_report"
    return "prepare_fix"


def route_after_execution_pre(state: ReviewState) -> Literal["sandbox_tests", "final_report"]:
    if worst(state.get("decisions", ())) == "block" or "sandbox_note" in state:
        return "final_report"
    return "sandbox_tests"


def _need(state: ReviewState, key: str) -> Any:
    """A key earlier nodes must have set. Missing means a wiring bug: fail, never guess."""
    if key not in state:
        raise RuntimeError(f"review graph state is missing {key!r}")
    return state[key]  # type: ignore[literal-required]


def _sandbox(ctx: ReviewContext) -> Sandbox:
    if ctx.sandbox is None:
        raise RuntimeError("a sandbox node ran without --run-tests")
    return ctx.sandbox


def _masked_attempt(attempt: PatchAttempt, secrets: tuple[str, ...]) -> PatchAttempt:
    """Reasons can quote test output or guardian text, which may contain a secret value."""
    reasons = tuple(sanitize.mask_secrets(reason, secrets) for reason in attempt.reasons)
    return attempt.model_copy(update={"reasons": reasons})


def _offerable(proposal: FixProposal | None, secrets: tuple[str, ...]) -> FixProposal | None:
    """The diff the user approves is never masked: what they read is exactly what is written. A
    proposal whose diff masking would change is not offered (the fix loop already rejects it)."""
    if proposal is None or sanitize.shows_secret(proposal.diff, secrets):
        return None
    return proposal


def _masked_fix(proposal: FixProposal | None, secrets: tuple[str, ...]) -> FixProposal | None:
    """Secrets masked in the texts around the diff. The diff itself is shown as is: _offerable
    guarantees it contains no secret value. `patched` (never serialized) is the exact content."""
    if proposal is None:
        return None
    target = proposal.target.model_copy(
        update={"message": sanitize.mask_secrets(proposal.target.message, secrets)}
    )
    return proposal.model_copy(
        update={
            "target": target,
            "explanation": sanitize.mask_secrets(proposal.explanation, secrets),
            "alerts": tuple(sanitize.mask_secrets(alert, secrets) for alert in proposal.alerts),
            "tests": None
            if proposal.tests is None
            else proposal.tests.model_copy(
                update={"output": sanitize.mask_secrets(proposal.tests.output, secrets)}
            ),
        }
    )


def _fix_note(state: ReviewState, secrets: tuple[str, ...]) -> str | None:
    proposal = state.get("fix_proposal")
    if proposal is not None and _offerable(proposal, secrets) is None:
        return "no fix proposed: the patch could only be shown masked, so it is not offered"
    if "fix_note" in state:
        return state["fix_note"]
    rounds = len(state.get("fix_attempts", ()))
    if rounds and "fix_proposal" not in state:
        return f"no fix proposed: no patch passed every check in {rounds} round(s)"
    return None


def _sandbox_notes(state: ReviewState) -> list[str]:
    skipped = state.get("sandbox_skipped", ())
    if not skipped:
        return []
    shown = ", ".join(skipped[:10]) + (", ..." if len(skipped) > 10 else "")
    return [f"not copied into the sandbox (symlinks and submodules): {shown}"]


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

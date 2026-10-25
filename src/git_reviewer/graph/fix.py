"""The fix loop of the review graph: patch proposal, checks, sandbox validation and patch auditor
(docs/SPEC.md "LangGraph graph" and guardian 3; docs/ARCHITECTURE.md §10.3, §11).

prepare_fix -> propose_patch -> check_patch -> validate_patch -> audit_patch, up to MAX_ATTEMPTS
rounds. Cheap deterministic checks come first, so a patch that fails them never runs, even in the
sandbox. A rejected round is recorded with its reasons (shown to the author next round, inside
delimiters, and in the report). The patch is only proposed here; applying it is the CLI's job,
after the user types "yes". A security event (canary leak, working directory changed during a
validation run, a surviving container) blocks the whole review, as elsewhere.
"""

from __future__ import annotations

import dataclasses
import hashlib
import uuid
from dataclasses import dataclass
from typing import Any, Literal

from langgraph.runtime import Runtime

from git_reviewer import proc, sanitize
from git_reviewer.git.snapshot import (
    SnapshotError,
    read_tree_file,
    replace_tree_file,
    single_file,
)
from git_reviewer.guardians import execution, injection, patch_auditor
from git_reviewer.guardians.base import Row, decision, run_guardian_batches, worst
from git_reviewer.llm import prompts
from git_reviewer.llm.structured import (
    ANSWER_TOKENS,
    LLMOutputError,
    ModelCallError,
    PatchAuthorOutput,
    ask_json,
)
from git_reviewer.models import (
    Decision,
    FixProposal,
    FixTarget,
    LineRef,
    PatchAttempt,
    SandboxRun,
)
from git_reviewer.patch import author, checks, edits, policy
from git_reviewer.sandbox.docker import DockerError, Sandbox
from git_reviewer.sandbox.fingerprint import FingerprintError, fingerprint
from git_reviewer.static.tools import StaticAnalysisError, run_bandit, run_gitleaks, run_ruff

from .state import ReviewContext, ReviewState

MAX_ATTEMPTS = 3
_MAX_DIFF_CHARS = 200_000
_MAX_FAILURE_LINES = 5
# The user must be able to read every added line in full before typing yes.
_MAX_ADDED_LINE = 300

Next = Literal["propose_patch", "check_patch", "validate_patch", "audit_patch", "final_report"]


@dataclass(frozen=True)
class Candidate:
    """The patch of the current round, while it goes through the checks."""

    number: int
    patched: str
    diff: str
    explanation: str
    tests: SandboxRun | None = None
    alerts: tuple[str, ...] = ()


def prepare_fix(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    sandbox = _sandbox(runtime.context)
    baseline = _baseline(state)
    if "sandbox_note" in state or baseline not in {"passed", "no_tests"}:
        reason = "the tests must run and pass before a patch can be validated"
        return {"fix_note": f"no fix proposed: {reason}"}
    review = state.get("review")
    found = author.candidates(_need(state, "static").findings, review.findings if review else [])
    reasons: list[str] = []
    for target in found:
        problems = policy.problems(target.file, _need(state, "diff").files)
        if problems:
            reasons.append(f"{target.file}: {problems[0]}")
            continue
        try:
            data = read_tree_file(sandbox.tree, target.file)
        except (SnapshotError, OSError) as exc:
            reasons.append(f"{target.file}: {exc}")
            continue
        problem = author.source_problem(data)
        if problem:
            reasons.append(f"{target.file}: {problem}")
            continue
        return {"fix_target": target, "fix_original": data.decode("utf-8"), "fix_attempts": ()}
    reason = reasons[0] if reasons else "no finding of medium severity or more in a Python file"
    return {"fix_note": f"no fix proposed: {reason}"}


def propose_patch(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    ctx = runtime.context
    target, original = _need(state, "fix_target"), _need(state, "fix_original")
    attempts = state.get("fix_attempts", ())
    number = len(attempts) + 1
    feedback = [f"attempt {a.number}: {reason}" for a in attempts for reason in a.reasons]
    canary, nonce = prompts.new_canary(), prompts.new_nonce()
    system, user = author.prompts_for(target, original, feedback, canary=canary, nonce=nonce)
    # Same context check as the review: two UTF-8 bytes per token, room for the answer.
    if len((system + user).encode("utf-8")) // 2 + ANSWER_TOKENS > ctx.model_context_tokens:
        return {"fix_note": "no fix proposed: the file does not fit the model context"}
    try:
        output, raw = ask_json(ctx.reviewer, system, user, PatchAuthorOutput)
    except LLMOutputError as exc:
        return _rejected(state, number, [f"the patch author's answer was rejected: {exc}"])
    except ModelCallError as exc:
        return {"fix_note": f"no fix proposed: the patch author failed: {exc}"}
    if injection.leaks(raw, canary):
        reason = "the patch author revealed its secret canary token (prompt injection)"
        return {"decisions": (decision("patch.canary", "block", [reason]),)}
    try:
        patched = edits.apply_edits(original, output.edits, target.file)
    except edits.EditError as exc:
        return _rejected(state, number, [f"the edits cannot be applied: {exc}"])
    diff = edits.unified_diff(target.file, original, patched)
    return {"candidate": Candidate(number, patched, diff, output.explanation)}


def check_patch(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    target, original = _need(state, "fix_target"), _need(state, "fix_original")
    candidate = _candidate(state)
    found = policy.problems(target.file, _need(state, "diff").files)
    found += checks.problems(target.file, original, candidate.patched)
    if len(candidate.diff) > _MAX_DIFF_CHARS:
        found.append("the patch is too large")
    added = edits.added_lines(original, candidate.patched)
    if any(len(text) > _MAX_ADDED_LINE for _number, text in added):
        found.append(f"the patch adds a line longer than {_MAX_ADDED_LINE} characters")
    return _rejected(state, candidate.number, found) if found else {}


def validate_patch(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    ctx = runtime.context
    sandbox = _sandbox(ctx)
    target, original = _need(state, "fix_target"), _need(state, "fix_original")
    candidate = _candidate(state)
    run_id, image_id = uuid.uuid4().hex, _need(state, "image_id")
    barrier = execution.check_argv([sandbox.plan("pytest", run_id, image_id)])
    if barrier.verdict == "block":
        return {"decisions": (barrier,)}
    added = edits.added_lines(original, candidate.patched)
    agent: list[Decision] = []
    if execution.is_test_infrastructure(target.file):
        rows: list[Row] = [
            (f"{target.file}:{number}: {text}", LineRef(file=target.file, line=number))
            for number, text in added
        ]
        found = run_guardian_batches(
            "patch.execution",
            ctx.guardian,
            prompts.EXECUTION_GUARDIAN_SYSTEM_PROMPT,
            prompts.execution_guardian_user_prompt,
            rows,
            context_tokens=ctx.model_context_tokens,
        )
        if worst(found) == "block":
            reasons = ["the execution guardian refused to run the patched tests"]
            reasons += [f"execution guardian: {r}" for d in found for r in d.reasons]
            return _rejected(state, candidate.number, reasons, source="patch.execution")
        agent = found  # ok or suspect: shown in the security report like every guardian decision
    run, failure, before = _run_patched(state, ctx, target, candidate, run_id, image_id)
    update: dict[str, Any] = {"decisions": (*agent, *_after_run(ctx, run_id, before))}
    if worst(update["decisions"]) == "block":
        return update
    if run is None:
        update["fix_note"] = f"no fix proposed: the sandbox failed: {failure}"
        return update
    baseline = _baseline(state)
    if not (run.outcome == "passed" or (run.outcome == "no_tests" and baseline == "no_tests")):
        reasons = [
            f"the tests do not pass with the patch ({run.outcome})",
            *_failures(run, _secrets(state)),
        ]
        return update | _rejected(state, candidate.number, reasons)
    try:
        before_count = state.get("fix_original_count")
        if before_count is None:
            before_count = _count(ctx, target, original)
            update["fix_original_count"] = before_count
        still = _still_reported(ctx, target, before_count, candidate.patched)
    except (StaticAnalysisError, SnapshotError, proc.ProcError) as exc:
        return update | _rejected(state, candidate.number, [f"cannot re-run the scanner: {exc}"])
    if still:
        reasons = [f"{target.source} still reports {target.rule} in the patched file"]
        return update | _rejected(state, candidate.number, reasons)
    alerts = tuple(
        f"execution guardian: {reason}"
        for found in agent
        if found.verdict == "suspect"
        for reason in found.reasons
    )
    update["candidate"] = dataclasses.replace(candidate, tests=run, alerts=alerts)
    return update


def audit_patch(state: ReviewState, runtime: Runtime[ReviewContext]) -> dict[str, Any]:
    ctx = runtime.context
    target, original = _need(state, "fix_target"), _need(state, "fix_original")
    candidate = _candidate(state)
    added = edits.added_lines(original, candidate.patched)
    found = patch_auditor.audit(
        target, candidate.diff, added, ctx.guardian, context_tokens=ctx.model_context_tokens
    )
    if found.verdict == "block":
        reasons = ["the patch auditor rejected it", *(f"patch auditor: {r}" for r in found.reasons)]
        return _rejected(state, candidate.number, reasons, source="patch.auditor")
    auditor = tuple(f"patch auditor: {r}" for r in found.reasons if found.verdict == "suspect")
    alerts = (*candidate.alerts, *auditor)[:10]
    proposal = FixProposal(
        target=target,
        file=target.file,
        explanation=candidate.explanation,
        diff=candidate.diff,
        patched=candidate.patched,
        original_sha256=hashlib.sha256(original.encode("utf-8")).hexdigest(),
        alerts=alerts,
        tests=candidate.tests,
    )
    accepted = PatchAttempt(number=candidate.number, accepted=True, reasons=proposal.alerts)
    return {
        "fix_proposal": proposal,
        "fix_attempts": (*state.get("fix_attempts", ()), accepted),
        "candidate": None,
        "decisions": (found,),
    }


def route_after_prepare(state: ReviewState) -> Next:
    return "final_report" if "fix_note" in state else "propose_patch"


def route_after_propose(state: ReviewState) -> Next:
    return _next(state, "check_patch")


def route_after_check(state: ReviewState) -> Next:
    return _next(state, "validate_patch")


def route_after_validate(state: ReviewState) -> Next:
    return _next(state, "audit_patch")


def route_after_audit(state: ReviewState) -> Next:
    return _next(state, "final_report")


def _next(state: ReviewState, on_success: Next) -> Next:
    if worst(state.get("decisions", ())) == "block" or "fix_note" in state:
        return "final_report"
    if "fix_proposal" in state:
        return "final_report"
    if state.get("candidate") is None:
        attempts = len(state.get("fix_attempts", ()))
        return "propose_patch" if attempts < MAX_ATTEMPTS else "final_report"
    return on_success


def _run_patched(
    state: ReviewState,
    ctx: ReviewContext,
    target: FixTarget,
    candidate: Candidate,
    run_id: str,
    image_id: str,
) -> tuple[SandboxRun | None, str | None, str | None]:
    """Run the tests on the sandbox copy with the patch, then restore the reviewed version."""
    sandbox = _sandbox(ctx)
    original = _need(state, "fix_original").encode("utf-8")
    before: str | None = None
    try:
        before = fingerprint(ctx.repo, hook=ctx.hook)
        replace_tree_file(sandbox.tree, target.file, candidate.patched.encode("utf-8"))
        try:
            return sandbox.run("pytest", run_id, image_id), None, before
        finally:
            # Always back to the reviewed version: the next round starts from it.
            replace_tree_file(sandbox.tree, target.file, original)
    except (DockerError, proc.ProcError, SnapshotError, FingerprintError, OSError) as exc:
        return None, str(exc), before


def _after_run(ctx: ReviewContext, run_id: str, before: str | None) -> list[Decision]:
    after: str | Exception | None = None
    if before is not None:
        try:
            after = fingerprint(ctx.repo, hook=ctx.hook)
        except (FingerprintError, proc.ProcError) as exc:
            after = exc
    leftovers: list[str] | Exception
    try:
        leftovers = _sandbox(ctx).leftover_containers(run_id)
    except (DockerError, proc.ProcError) as exc:
        leftovers = exc
    return execution.guard_after_run(before, after, leftovers)


def _still_reported(ctx: ReviewContext, target: FixTarget, before: int, patched: str) -> bool:
    """For a scanner finding: the same scanner must report that rule fewer times after the patch.
    LLM findings have no deterministic check; the tests and the auditor cover them."""
    if target.source == "reviewer":
        return False
    return _count(ctx, target, patched) >= before


def _count(ctx: ReviewContext, target: FixTarget, text: str) -> int:
    """How often the target's scanner reports its rule in `text` (0 for an LLM finding)."""
    if target.source == "reviewer":
        return 0
    with single_file(target.file, text.encode("utf-8")) as snapshot:
        if target.source == "ruff":
            found = run_ruff(snapshot, [target.file], ctx.repo)
        elif target.source == "bandit":
            found, unparsed = run_bandit(snapshot, [target.file], ctx.repo)
            if unparsed:
                # A file bandit cannot read has no findings: that is not a fix.
                raise StaticAnalysisError("bandit could not parse the file")
        else:
            found, _secrets = run_gitleaks(snapshot, ctx.repo)
    return sum(1 for finding in found if finding.rule == target.rule)


def _failures(run: SandboxRun, secrets: tuple[str, ...]) -> list[str]:
    """pytest's FAILED/ERROR summary lines: test output is untrusted, so only short, sanitized
    lines go back to the author (inside delimiters). Secrets are masked before cutting, so a
    secret across the cut cannot leak in part."""
    lines = [
        sanitize.one_line(sanitize.mask_secrets(line, secrets), max_chars=200)
        for line in run.output.splitlines()
        if line.startswith(("FAILED ", "ERROR "))
    ]
    return lines[:_MAX_FAILURE_LINES]


def _rejected(
    state: ReviewState, number: int, reasons: list[str], *, source: str | None = None
) -> dict[str, Any]:
    secrets = _secrets(state)
    reasons = [sanitize.mask_secrets(reason, secrets)[:300] for reason in reasons][:10]
    attempt = PatchAttempt(number=number, accepted=False, reasons=tuple(reasons))
    update: dict[str, Any] = {
        "candidate": None,
        "fix_attempts": (*state.get("fix_attempts", ()), attempt),
    }
    if source is not None:
        # A guardian that rejected a patch is shown as an alert: it does not block the review,
        # whose change is not the patch.
        update["decisions"] = (decision(source, "suspect", reasons),)
    return update


def _secrets(state: ReviewState) -> tuple[str, ...]:
    static = state.get("static")
    return static.secrets if static is not None else ()


def _baseline(state: ReviewState) -> str | None:
    runs = state.get("sandbox_runs", ())
    return next((run.outcome for run in runs if run.tool == "pytest"), None)


def _candidate(state: ReviewState) -> Candidate:
    candidate = state.get("candidate")
    if candidate is None:
        raise RuntimeError("a patch check ran without a candidate patch")
    return candidate


def _sandbox(ctx: ReviewContext) -> Sandbox:
    if ctx.sandbox is None:
        raise RuntimeError("a fix node ran without a sandbox")
    return ctx.sandbox


def _need(state: ReviewState, key: str) -> Any:
    if key not in state:
        raise RuntimeError(f"review graph state is missing {key!r}")
    return state[key]  # type: ignore[literal-required]

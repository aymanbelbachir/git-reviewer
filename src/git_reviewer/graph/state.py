"""Review graph state and context (docs/ARCHITECTURE.md §5).

The state is a TypedDict; every value that crosses a trust boundary is a frozen Pydantic model.
`decisions` uses an append-only reducer: no node can remove a block or an alert. The graph is
compiled without a checkpointer, so nothing (code, diff, model output) is ever written to disk.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, TypedDict

from git_reviewer.git.diff import DiffLimits
from git_reviewer.llm.structured import ChatFn, ReviewerOutput
from git_reviewer.models import (
    Decision,
    Diff,
    FixProposal,
    FixTarget,
    PatchAttempt,
    SandboxRun,
)
from git_reviewer.report.model import Report
from git_reviewer.sandbox.docker import Sandbox
from git_reviewer.static.analyze import StaticResult


class ReviewState(TypedDict, total=False):
    diff: Diff
    static: StaticResult
    decisions: Annotated[tuple[Decision, ...], operator.add]
    review: ReviewerOutput
    raw_review: str
    canary: str
    nonce: str
    not_reviewed: str
    run_tests: bool
    run_id: str
    image_id: str
    fingerprint: str
    sandbox_runs: tuple[SandboxRun, ...]
    sandbox_note: str
    sandbox_skipped: tuple[str, ...]
    fix: bool
    fix_target: FixTarget
    fix_original: str
    fix_original_count: int
    fix_attempts: tuple[PatchAttempt, ...]
    candidate: Any
    """The patch of the current fix round (graph.fix.Candidate), or None once it is rejected."""
    fix_proposal: FixProposal
    fix_note: str
    report: Report


@dataclass(frozen=True)
class ReviewContext:
    repo: Path
    hook: bool
    range_spec: str | None
    limits: DiffLimits
    max_review_chars: int
    model_context_tokens: int
    guardian_context_tokens: int
    reviewer: ChatFn
    guardian: ChatFn
    sandbox: Sandbox | None = None
    """Set by --run-tests: the project's tests and linter then run in this sandbox."""
    fix: bool = False
    """--fix: propose one patch, validated in the sandbox (needs `sandbox`)."""

"""The review report and the exit code it maps to (docs/ARCHITECTURE.md §4, §12)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from git_reviewer.models import (
    SEVERITY_RANK,
    Decision,
    FileChange,
    ReviewFinding,
    SandboxRun,
    Severity,
    StaticFinding,
)

Status = Literal["reviewed", "not_reviewed", "blocked", "empty"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_BLOCKED = 2


class Report(BaseModel):
    """Everything shown to the user. Secret values are already masked in every text field."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Status
    mode: Literal["staged", "range"] | None
    files: tuple[FileChange, ...]
    static_findings: tuple[StaticFinding, ...]
    review_findings: tuple[ReviewFinding, ...]
    summary: str
    decisions: tuple[Decision, ...]
    notes: tuple[str, ...]
    reason: str | None
    coverage: tuple[tuple[str, int], ...] = ()
    """(scanner, files analyzed): a scanner that saw nothing must be visible."""

    tests_requested: bool = False
    sandbox_runs: tuple[SandboxRun, ...] = ()
    sandbox_note: str | None = None
    """Why the sandbox did not run, or stopped early."""


def exit_code(report: Report, *, block_mode: bool, threshold: Severity) -> int:
    """Security blocks always exit 2. "Not reviewed" exits 2 in block mode. Findings at or above
    the threshold, or requested tests that did not pass, exit 1 in block mode. Warn mode reports
    and exits 0 otherwise. The project's own linter is informational: it checks the whole
    repository, and the added lines are already covered by git-reviewer's ruff run."""
    if report.status == "blocked":
        return EXIT_BLOCKED
    if report.status == "not_reviewed":
        return EXIT_BLOCKED if block_mode else EXIT_OK
    worst = max(
        (SEVERITY_RANK[f.severity] for f in (*report.static_findings, *report.review_findings)),
        default=-1,
    )
    if block_mode and (worst >= SEVERITY_RANK[threshold] or tests_did_not_pass(report)):
        return EXIT_FINDINGS
    return EXIT_OK


def tests_did_not_pass(report: Report) -> bool:
    if not report.tests_requested or report.status != "reviewed":
        return False
    pytest_runs = [run for run in report.sandbox_runs if run.tool == "pytest"]
    if report.sandbox_note is not None or not pytest_runs:
        return True
    return any(run.outcome not in {"passed", "no_tests"} for run in pytest_runs)

"""The review report and the exit code it maps to (docs/ARCHITECTURE.md §4, §12)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from git_reviewer.models import (
    SEVERITY_RANK,
    Decision,
    FileChange,
    ReviewFinding,
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


def exit_code(report: Report, *, block_mode: bool, threshold: Severity) -> int:
    """Security blocks always exit 2. "Not reviewed" exits 2 in block mode. Findings at or above
    the threshold exit 1 in block mode. Warn mode reports and exits 0 otherwise."""
    if report.status == "blocked":
        return EXIT_BLOCKED
    if report.status == "not_reviewed":
        return EXIT_BLOCKED if block_mode else EXIT_OK
    worst = max(
        (SEVERITY_RANK[f.severity] for f in (*report.static_findings, *report.review_findings)),
        default=-1,
    )
    if block_mode and worst >= SEVERITY_RANK[threshold]:
        return EXIT_FINDINGS
    return EXIT_OK

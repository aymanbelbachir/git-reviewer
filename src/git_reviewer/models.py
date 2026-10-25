"""Pydantic models for data that crosses a trust boundary (docs/ARCHITECTURE.md §2)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

FileStatus = Literal["added", "modified", "deleted", "type_changed"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Verdict = Literal["ok", "suspect", "block"]

SEVERITY_RANK: dict[Severity, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
VERDICT_RANK: dict[Verdict, int] = {"ok": 0, "suspect": 1, "block": 2}

_FROZEN = ConfigDict(frozen=True, extra="forbid", strict=True)


class FileChange(BaseModel):
    """One file of the reviewed diff. `added_lines` uses the new file's line numbers."""

    model_config = _FROZEN

    path: str
    status: FileStatus
    binary: bool
    added_lines: frozenset[int]


class Diff(BaseModel):
    """The reviewed change: staged changes, or BASE..HEAD from their merge base."""

    model_config = _FROZEN

    mode: Literal["staged", "range"]
    base: str | None
    head: str | None
    files: tuple[FileChange, ...]
    patch: str

    @property
    def added_line_count(self) -> int:
        return sum(len(change.added_lines) for change in self.files)

    def is_added_line(self, path: str, line: int) -> bool:
        return any(change.path == path and line in change.added_lines for change in self.files)


class LineRef(BaseModel):
    model_config = _FROZEN

    file: str = Field(max_length=4096)
    line: int = Field(ge=1)

    def __hash__(self) -> int:  # frozen, so hashable; spelled out for the type checker
        return hash((self.file, self.line))


class StaticFinding(BaseModel):
    """A finding from ruff, bandit, gitleaks or git-reviewer's own checks: the source of truth.

    `message` never contains a secret value or a source excerpt.
    """

    model_config = _FROZEN

    tool: Literal["ruff", "bandit", "gitleaks", "git-reviewer"]
    rule: str = Field(max_length=100)
    file: str = Field(max_length=4096)
    line: int = Field(ge=1)
    severity: Severity
    message: str = Field(max_length=500)


class ReviewFinding(BaseModel):
    """A finding from the LLM reviewer, validated against the diff before it is kept."""

    model_config = _FROZEN

    file: str = Field(max_length=4096)
    line: int = Field(ge=1)
    severity: Severity
    category: Literal["bug", "security", "readability"]
    title: str = Field(max_length=120)
    explanation: str = Field(max_length=1000)


class Decision(BaseModel):
    """A security decision from a barrier, a guardian agent or a deterministic check."""

    model_config = _FROZEN

    source: str = Field(max_length=100)
    verdict: Verdict
    reasons: tuple[str, ...] = Field(default=(), max_length=10)
    lines: tuple[LineRef, ...] = Field(default=(), max_length=50)

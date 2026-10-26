"""Pydantic models for data that crosses a trust boundary (docs/ARCHITECTURE.md §2)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

FileStatus = Literal["added", "modified", "deleted", "type_changed"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Verdict = Literal["ok", "suspect", "block"]
SandboxTool = Literal["pytest", "ruff"]
SandboxOutcome = Literal["passed", "failed", "no_tests", "killed", "error"]

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
    index_digest: str | None = None
    """Staged mode: hash of the index the diff was read from. Every later read of the index
    (scanners, sandbox copy) must find the same index, or the review stops."""

    @property
    def added_line_count(self) -> int:
        return sum(len(change.added_lines) for change in self.files)

    def is_added_line(self, path: str, line: int) -> bool:
        return any(change.path == path and line in change.added_lines for change in self.files)

    def first_added_line(self, path: str, first: int, last: int) -> int | None:
        """The first added line of `path` between `first` and `last` (inclusive), if any."""
        found = [
            number
            for change in self.files
            if change.path == path
            for number in change.added_lines
            if first <= number <= last
        ]
        return min(found, default=None)


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
    span: tuple[int, int] | None = None
    """First and last line of the statement the scanner flagged (a multi-line call or string),
    when the scanner gives them; `line` may be anywhere inside."""


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


class SandboxRun(BaseModel):
    """One run of the project's tests or linter in the sandbox. Everything here comes from code
    under review: a quality signal for the user, never a security decision (SECURITY.md T-34)."""

    model_config = _FROZEN

    tool: SandboxTool
    outcome: SandboxOutcome
    exit_code: int | None
    seconds: float = Field(ge=0)
    detail: str = Field(default="", max_length=300)
    output: str = Field(default="", max_length=8_000)
    """The end of the combined output, untrusted: masked and sanitized before display."""


class FixTarget(BaseModel):
    """The one finding a patch is proposed for (static analysis or LLM review)."""

    model_config = _FROZEN

    source: Literal["ruff", "bandit", "gitleaks", "reviewer"]
    rule: str = Field(max_length=100)
    file: str = Field(max_length=4096)
    line: int = Field(ge=1)
    severity: Severity
    message: str = Field(max_length=1000)


class PatchAttempt(BaseModel):
    """One round of the fix loop and why it was rejected (our own text, never model output)."""

    model_config = _FROZEN

    number: int = Field(ge=1)
    accepted: bool
    reasons: tuple[str, ...] = Field(default=(), max_length=10)


class FixProposal(BaseModel):
    """A patch that passed every check. Applied only after the user types yes (patch.apply)."""

    model_config = _FROZEN

    target: FixTarget
    file: str = Field(max_length=4096)
    explanation: str = Field(max_length=500)
    diff: str = Field(max_length=200_000)
    """For display: secrets masked."""

    patched: str = Field(max_length=200_000, exclude=True)
    """The exact new content of `file`, as validated in the sandbox: what is written on "yes".
    Never serialized (it may contain secret values)."""

    original_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    """The reviewed content of `file`: the working tree must still have it to apply the patch."""

    alerts: tuple[str, ...] = Field(default=(), max_length=10)
    tests: SandboxRun | None = None

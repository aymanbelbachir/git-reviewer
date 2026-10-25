"""Choose the finding to fix and prepare the patch author's prompt (docs/ARCHITECTURE.md §11;
SECURITY.md T-03).

One patch per review, for the most severe finding of medium severity or more in a Python file:
static findings (the source of truth) before LLM findings at equal severity. The author only gets
the finding and the reviewed version of that one file, nonce-delimited, plus why earlier attempts
were rejected; its system prompt carries a canary like the reviewer's.
"""

from __future__ import annotations

from collections.abc import Iterable

from git_reviewer.llm import prompts
from git_reviewer.models import SEVERITY_RANK, FixTarget, ReviewFinding, StaticFinding
from git_reviewer.patch.edits import numbered

_SCANNERS = ("ruff", "bandit", "gitleaks")
_MIN_RANK = SEVERITY_RANK["medium"]
MAX_FILE_CHARS = 60_000
MAX_FEEDBACK_LINES = 10


def candidates(
    static_findings: Iterable[StaticFinding], review_findings: Iterable[ReviewFinding]
) -> list[FixTarget]:
    """Fixable findings, best first: most severe, static before LLM, then by location."""
    found: list[tuple[int, int, FixTarget]] = []
    for finding in static_findings:
        if finding.tool in _SCANNERS and SEVERITY_RANK[finding.severity] >= _MIN_RANK:
            target = FixTarget(
                source=finding.tool,  # type: ignore[arg-type]  # narrowed by _SCANNERS
                rule=finding.rule,
                file=finding.file,
                line=finding.line,
                severity=finding.severity,
                message=finding.message,
            )
            found.append((SEVERITY_RANK[finding.severity], 0, target))
    for review in review_findings:
        if SEVERITY_RANK[review.severity] >= _MIN_RANK:
            target = FixTarget(
                source="reviewer",
                rule=review.category,
                file=review.file,
                line=review.line,
                severity=review.severity,
                message=f"{review.title}: {review.explanation}"[:1000],
            )
            found.append((SEVERITY_RANK[review.severity], 1, target))
    found.sort(key=lambda item: (-item[0], item[1], item[2].file, item[2].line))
    return [target for _rank, _order, target in found if target.file.endswith(".py")]


def source_problem(data: bytes) -> str | None:
    """Why this file cannot be sent to the patch author (None when it can)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "the file is not valid UTF-8"
    if "\r" in text:
        return "files with Windows line endings are not patched"
    if len(text) > MAX_FILE_CHARS:
        return f"the file is longer than {MAX_FILE_CHARS} characters"
    return None


def prompts_for(
    target: FixTarget, original: str, feedback: list[str], *, canary: str, nonce: str
) -> tuple[str, str]:
    system = prompts.patch_author_system_prompt(canary)
    user = prompts.patch_author_user_prompt(
        target.model_dump_json(),
        numbered(original),
        "\n".join(feedback[-MAX_FEEDBACK_LINES:]),
        nonce,
    )
    return system, user

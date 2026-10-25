"""Render a report as text or JSON. All untrusted text is sanitized for the terminal."""

from __future__ import annotations

import json
from typing import Any

from git_reviewer import sanitize
from git_reviewer.guardians.base import worst
from git_reviewer.models import (
    SEVERITY_RANK,
    Decision,
    FixProposal,
    ReviewFinding,
    SandboxRun,
    StaticFinding,
)

from .model import Report

_OUTPUT_LINES_SHOWN = 15
_STATUS_LINE = {
    "reviewed": "Reviewed.",
    "not_reviewed": "Not reviewed",
    "blocked": "Blocked by a security control: the change was not sent for review.",
    "empty": "Nothing to review.",
}
_BLOCKED_AFTER_REVIEW = (
    "Blocked by a security control after the review: see the security report before committing."
)


def to_text(report: Report) -> str:
    if report.status == "empty":
        return _STATUS_LINE["empty"]
    out: list[str] = []
    added = sum(len(change.added_lines) for change in report.files)
    out.append(f"{len(report.files)} file(s), {added} added line(s)")
    for change in report.files:
        detail = "binary, not analyzed" if change.binary else f"+{len(change.added_lines)}"
        out.append(f"  {change.status:<12} {sanitize.one_line(change.path)} ({detail})")
    out.append("")
    out.append("Static analysis (ruff, bandit, gitleaks; the source of truth):")
    if report.coverage:
        counts = ", ".join(f"{tool} {count} file(s)" for tool, count in report.coverage)
        out.append(f"  analyzed: {counts}")
    out.extend(_static_lines(report.static_findings) or ["  no findings on added lines"])
    after_review = _blocked_after_review(report)
    if report.status in {"reviewed", "not_reviewed"} or after_review:
        out.append("")
        out.append("LLM review:")
        if report.status == "not_reviewed":
            out.append(f"  not performed: {sanitize.one_line(report.reason or 'unknown reason')}")
        else:
            out.extend(_review_lines(report.review_findings) or ["  no findings"])
            if report.summary:
                out.append(f"  summary: {sanitize.one_line(report.summary, max_chars=1000)}")
    if report.tests_requested and (report.status == "reviewed" or after_review):
        out.append("")
        out.append("Sandbox (tests and linter of the reviewed code; their output is untrusted):")
        if report.sandbox_note:
            out.append(f"  {sanitize.one_line(report.sandbox_note)}")
        for run in report.sandbox_runs:
            out.extend(_sandbox_lines(run))
    if report.fix_requested and report.status == "reviewed":
        out.append("")
        out.extend(_fix_lines(report))
    out.append("")
    out.append("Security report:")
    out.extend(_decision_lines(report.decisions))
    for note in report.notes:
        out.append(f"  note: {sanitize.one_line(note)}")
    out.append("")
    if report.status == "not_reviewed":
        out.append(f"{_STATUS_LINE['not_reviewed']}: {sanitize.one_line(report.reason or '')}")
    elif after_review:
        out.append(_BLOCKED_AFTER_REVIEW)
    else:
        out.append(_STATUS_LINE[report.status])
    return "\n".join(out)


def _blocked_after_review(report: Report) -> bool:
    """Blocked only by the execution guardian: the review itself was done and is shown."""
    blocks = [d for d in report.decisions if d.verdict == "block"]
    return (
        report.status == "blocked"
        and bool(blocks)
        and all(d.source.startswith("execution.") for d in blocks)
    )


def to_json(report: Report) -> str:
    data: dict[str, Any] = {
        "status": report.status,
        "reason": report.reason,
        "mode": report.mode,
        "files": [
            {
                "path": change.path,
                "status": change.status,
                "binary": change.binary,
                "added_lines": len(change.added_lines),
            }
            for change in report.files
        ],
        "static_findings": [finding.model_dump() for finding in report.static_findings],
        "review_findings": [finding.model_dump() for finding in report.review_findings],
        "summary": report.summary,
        "security": {
            "verdict": worst(report.decisions),
            "decisions": [found.model_dump(mode="json") for found in report.decisions],
        },
        "notes": list(report.notes),
        "coverage": dict(report.coverage),
        "sandbox": {
            "requested": report.tests_requested,
            "note": report.sandbox_note,
            "runs": [run.model_dump() for run in report.sandbox_runs],
        },
        "fix": {
            "requested": report.fix_requested,
            "note": report.fix_note,
            "attempts": [attempt.model_dump() for attempt in report.fix_attempts],
            # model_dump leaves out `patched`: the exact content may contain secret values.
            "proposal": report.fix.model_dump() if report.fix else None,
        },
    }
    return json.dumps(data, ensure_ascii=True)


def _sandbox_lines(run: SandboxRun) -> list[str]:
    code = "no exit code" if run.exit_code is None else f"exit {run.exit_code}"
    detail = f": {sanitize.one_line(run.detail)}" if run.detail else ""
    lines = [f"  {run.tool}: {run.outcome} ({code}, {run.seconds:.1f}s){detail}"]
    if run.outcome != "passed":
        tail = run.output.strip().splitlines()[-_OUTPUT_LINES_SHOWN:]
        lines.extend(f"    | {sanitize.one_line(line)}" for line in tail)
    return lines


def _fix_lines(report: Report) -> list[str]:
    heading = "Proposed fix (validated in the sandbox, checked by the patch auditor; read it all):"
    lines = [heading if report.fix is not None else "Fix:"]
    for attempt in report.fix_attempts:
        if not attempt.accepted:
            reasons = "; ".join(sanitize.one_line(r) for r in attempt.reasons)
            lines.append(f"  attempt {attempt.number} rejected: {reasons}")
    if report.fix is None:
        lines.append(f"  {sanitize.one_line(report.fix_note or 'no fix proposed')}")
        return lines
    lines.extend(_proposal_lines(report.fix))
    return lines


def _proposal_lines(fix: FixProposal) -> list[str]:
    target = fix.target
    lines = [
        f"  for: [{target.severity}] {sanitize.one_line(target.file)}:{target.line} "
        f"{target.source}/{sanitize.one_line(target.rule)}: {sanitize.one_line(target.message)}",
        f"  why (from the patch author): {sanitize.one_line(fix.explanation, max_chars=500)}",
    ]
    if fix.tests is not None:
        lines.append(f"  tests with the patch: {fix.tests.outcome} ({fix.tests.seconds:.1f}s)")
    lines.extend(f"  [ALERT] {sanitize.one_line(alert)}" for alert in fix.alerts)
    # Every line shown, invisible and control characters made visible.
    lines.extend(
        f"  | {sanitize.one_line(line, max_chars=20_000)}" for line in fix.diff.splitlines()
    )
    return lines


def _static_lines(findings: tuple[StaticFinding, ...]) -> list[str]:
    return [
        f"  [{f.severity}] {sanitize.one_line(f.file)}:{f.line} {f.tool}/{f.rule}: "
        f"{sanitize.one_line(f.message)}"
        for f in sorted(findings, key=lambda f: -SEVERITY_RANK[f.severity])
    ]


def _review_lines(findings: tuple[ReviewFinding, ...]) -> list[str]:
    lines: list[str] = []
    for f in sorted(findings, key=lambda f: -SEVERITY_RANK[f.severity]):
        lines.append(
            f"  [{f.severity}] {sanitize.one_line(f.file)}:{f.line} {f.category}: "
            f"{sanitize.one_line(f.title)}"
        )
        lines.append(f"      {sanitize.one_line(f.explanation, max_chars=1000)}")
    return lines


def _decision_lines(decisions: tuple[Decision, ...]) -> list[str]:
    raised = [d for d in decisions if d.verdict != "ok"]
    lines = [f"  {len(decisions) - len(raised)} check(s) passed"]
    for found in raised:
        where = ", ".join(f"{sanitize.one_line(r.file)}:{r.line}" for r in found.lines[:10])
        reasons = "; ".join(sanitize.one_line(r) for r in found.reasons)
        label = "BLOCK" if found.verdict == "block" else "ALERT"
        lines.append(f"  [{label}] {found.source}: {reasons}" + (f" ({where})" if where else ""))
    return lines

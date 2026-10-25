"""Render a report as text or JSON. All untrusted text is sanitized for the terminal."""

from __future__ import annotations

import json
from typing import Any

from git_reviewer import sanitize
from git_reviewer.guardians.base import worst
from git_reviewer.models import SEVERITY_RANK, Decision, ReviewFinding, StaticFinding

from .model import Report

_STATUS_LINE = {
    "reviewed": "Reviewed.",
    "not_reviewed": "Not reviewed",
    "blocked": "Blocked by a security control: the change was not sent for review.",
    "empty": "Nothing to review.",
}


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
    if report.status in {"reviewed", "not_reviewed"}:
        out.append("")
        out.append("LLM review:")
        if report.status == "not_reviewed":
            out.append(f"  not performed: {sanitize.one_line(report.reason or 'unknown reason')}")
        else:
            out.extend(_review_lines(report.review_findings) or ["  no findings"])
            if report.summary:
                out.append(f"  summary: {sanitize.one_line(report.summary, max_chars=1000)}")
    out.append("")
    out.append("Security report:")
    out.extend(_decision_lines(report.decisions))
    for note in report.notes:
        out.append(f"  note: {sanitize.one_line(note)}")
    out.append("")
    if report.status == "not_reviewed":
        out.append(f"{_STATUS_LINE['not_reviewed']}: {sanitize.one_line(report.reason or '')}")
    else:
        out.append(_STATUS_LINE[report.status])
    return "\n".join(out)


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
    }
    return json.dumps(data, ensure_ascii=True)


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

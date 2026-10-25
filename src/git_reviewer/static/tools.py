"""Run ruff, bandit and gitleaks on the exported files (docs/ARCHITECTURE.md §6; SECURITY.md T-08).

None of the three may be steered by the reviewed repository:
- ruff runs `--isolated` (no config file), `--ignore-noqa`, without cache, and gets every file
  explicitly so its default excludes (`dist/`, `build/`, `venv/`...) and `.gitignore` hide nothing;
- bandit gets explicit files (so no `.bandit` file is discovered) and `--ignore-nosec`;
- gitleaks uses our configuration, an empty ignore directory and `--ignore-gitleaks-allow`.
Findings are normalized to `StaticFinding`. Secret values found by gitleaks are returned separately,
kept in memory only, and used to mask displayed text; they never appear in a finding.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from importlib import resources
from pathlib import Path
from typing import Any

from git_reviewer import proc
from git_reviewer.git.snapshot import Snapshot
from git_reviewer.models import Severity, StaticFinding

RUFF_RULES = "E9,F,B,PLE"
_LOW_RUFF_RULES = frozenset({"F401", "F841", "F811"})
_BANDIT_SEVERITY: dict[str, Severity] = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
# Hardcoded-password tests quote the candidate value in their message: never pass it on.
_BANDIT_QUOTES_SECRET = frozenset({"B105", "B106", "B107"})
_MAX_MESSAGE = 500
_TOOL_TIMEOUT = 120.0
# A result that cannot be mapped to a reviewed file and line must not vanish silently.
_UNMAPPED = "{tool} reported a result that cannot be mapped to a reviewed file and line"


class StaticAnalysisError(RuntimeError):
    """A scanner failed; the review cannot rely on static analysis."""


def run_ruff(snapshot: Snapshot, files: Sequence[str], repo: Path) -> list[StaticFinding]:
    if not files:
        return []
    args = [
        "check",
        "--isolated",
        "--ignore-noqa",
        "--no-cache",
        "--no-respect-gitignore",
        "--exit-zero",
        "--output-format",
        "json",
        "--select",
        RUFF_RULES,
        "--",
        *(str(snapshot.root / path) for path in files),
    ]
    result = _run("ruff", args, snapshot, repo)
    if result.returncode != 0:
        raise StaticAnalysisError(f"ruff failed with exit code {result.returncode}")
    findings: list[StaticFinding] = []
    for item in _json_list(result.stdout, "ruff"):
        code = item.get("code")
        path = _relative(item.get("filename"), snapshot)
        line = _int(item.get("location", {}).get("row"))
        if path is None or line is None:
            raise StaticAnalysisError(_UNMAPPED.format(tool="ruff"))
        rule = code if isinstance(code, str) else "syntax-error"
        findings.append(
            _finding("ruff", rule, path, line, _ruff_severity(code), item.get("message"))
        )
    return findings


def run_bandit(
    snapshot: Snapshot, files: Sequence[str], repo: Path
) -> tuple[list[StaticFinding], list[str]]:
    """Findings, and the files bandit could not parse (their security analysis did not run)."""
    if not files:
        return [], []
    targets = [str(snapshot.root / path) for path in files]
    args = [
        "-f",
        "json",
        "-q",
        "--ignore-nosec",
        # bandit's default excludes (.git, CVS, .tox, ...) match path substrings and would
        # silently skip e.g. .github/scripts/deploy.py: disable them.
        "--exclude=",
        "--",
        *targets,
    ]
    result = _run("bandit", args, snapshot, repo)
    # bandit exits 1 when it found issues; anything else is a failure.
    if result.returncode not in (0, 1):
        raise StaticAnalysisError(f"bandit failed with exit code {result.returncode}")
    report = _json(result.stdout, "bandit")
    if not isinstance(report, dict) or not {"results", "errors", "metrics"} <= set(report):
        raise StaticAnalysisError("unexpected bandit output")
    error_files = {str(e.get("filename")) for e in report["errors"] if isinstance(e, dict)}
    analyzed = set(report["metrics"]) | error_files
    if missing := [t for t in targets if t not in analyzed]:
        raise StaticAnalysisError(f"bandit silently skipped {len(missing)} file(s)")
    findings: list[StaticFinding] = []
    for item in report["results"]:
        path = _relative(item.get("filename"), snapshot)
        line = _int(item.get("line_number"))
        severity = _BANDIT_SEVERITY.get(str(item.get("issue_severity")), "medium")
        if path is None or line is None:
            raise StaticAnalysisError(_UNMAPPED.format(tool="bandit"))
        rule = f"{item.get('test_id', 'B000')}"
        message = item.get("issue_text")
        if rule in _BANDIT_QUOTES_SECRET:
            message = "possible hardcoded password; value masked"
        # `code` holds source lines and is deliberately dropped.
        findings.append(_finding("bandit", rule, path, line, severity, message))
    skipped = []
    for error in report["errors"]:
        path = _relative(error.get("filename"), snapshot)
        if path is None:
            raise StaticAnalysisError(_UNMAPPED.format(tool="bandit"))
        skipped.append(path)
    return findings, skipped


def run_gitleaks(snapshot: Snapshot, repo: Path) -> tuple[list[StaticFinding], list[str]]:
    """Findings, and the secret values (memory only, for masking)."""
    report_path = snapshot.work / "gitleaks.json"
    with resources.as_file(resources.files("git_reviewer.static") / "gitleaks.toml") as config:
        args = [
            "dir",
            str(snapshot.root),
            "--config",
            str(config),
            "--gitleaks-ignore-path",
            str(snapshot.empty),
            "--ignore-gitleaks-allow",
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--exit-code",
            "0",
            "--no-banner",
            "--log-level",
            "error",
        ]
        result = _run("gitleaks", args, snapshot, repo)
    if result.returncode != 0:
        raise StaticAnalysisError(f"gitleaks failed with exit code {result.returncode}")
    try:
        raw = report_path.read_bytes()
    except OSError as exc:
        raise StaticAnalysisError("gitleaks did not write its report") from exc
    findings: list[StaticFinding] = []
    secrets: list[str] = []
    for item in _json_list(raw, "gitleaks"):
        path = _relative(item.get("File"), snapshot)
        line = _int(item.get("StartLine"))
        if path is None or line is None:
            raise StaticAnalysisError(_UNMAPPED.format(tool="gitleaks"))
        secret = item.get("Secret")
        if isinstance(secret, str) and secret:
            secrets.append(secret)
        rule = str(item.get("RuleID", "secret"))
        message = f"possible secret ({rule}); value masked"
        findings.append(_finding("gitleaks", rule, path, line, "critical", message))
    return findings, secrets


def _run(binary: str, args: list[str], snapshot: Snapshot, repo: Path) -> proc.Result:
    try:
        # cwd is our private scratch dir, never the repository.
        return proc.run(binary, args, cwd=snapshot.work, timeout=_TOOL_TIMEOUT, forbidden_root=repo)
    except proc.ProcError as exc:
        raise StaticAnalysisError(f"{binary}: {exc}") from exc


def _json(raw: bytes, tool: str) -> Any:
    # Every scanner writes JSON even when it finds nothing ("[]"): empty output is a failure.
    if not raw.strip():
        raise StaticAnalysisError(f"{tool} produced no output")
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise StaticAnalysisError(f"{tool} produced invalid JSON") from exc


def _json_list(raw: bytes, tool: str) -> list[Any]:
    data = _json(raw, tool)
    if not isinstance(data, list):
        raise StaticAnalysisError(f"unexpected {tool} output")
    return data


def _relative(value: Any, snapshot: Snapshot) -> str | None:
    if not isinstance(value, str):
        return None
    path = Path(value)
    if not path.is_absolute():
        path = snapshot.root / path
    try:
        return path.relative_to(snapshot.root).as_posix()
    except ValueError:
        return None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def _ruff_severity(code: Any) -> Severity:
    if not isinstance(code, str) or code.startswith("E9"):
        return "high"
    if code in _LOW_RUFF_RULES or code.startswith("B"):
        return "low"
    return "medium"


def _finding(
    tool: str, rule: str, path: str, line: int, severity: Severity, message: Any
) -> StaticFinding:
    text = str(message or "").strip()[:_MAX_MESSAGE]
    return StaticFinding.model_validate(
        {
            "tool": tool,
            "rule": rule[:100],
            "file": path,
            "line": line,
            "severity": severity,
            "message": text,
        }
    )

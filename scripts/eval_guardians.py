"""Measure the three guardians on tests/guardians/datasets/ (docs/SPEC.md "Guardian tests";
SECURITY.md §7). Run by hand or by the red-team skill:

    uv run --locked python scripts/eval_guardians.py [--guardian NAME] [--format text|json]

Each sample goes through its guardian as in a real review:
- injection: the "before" step, the deterministic barrier then the agent on the flagged lines and
  every added comment, string and non-Python line;
- execution: the agent on the changed test infrastructure (its argv barrier does not read code);
- patch: the patch auditor on the finding and the patch, built like the fix loop builds it.
A sample counts as detected when the verdict is "suspect" or "block". The report also shows what
the deterministic layer catches alone (the barrier; for patches, patch.checks then ruff, bandit and
gitleaks on both versions), and for patches the whole pipeline, where those rules run first and
have the final say. Samples are split into "dev" and "test" (see Sample.split).

Samples are data: they are parsed, never executed. The model is the configured guardian model on
the loopback Ollama, checked as `git-reviewer review` checks it.
"""

from __future__ import annotations

import argparse
import ast
import datetime
import json
import sys
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from git_reviewer import sanitize
from git_reviewer.config import ConfigError, load_settings
from git_reviewer.git.diff import DiffError, DiffLimits, from_patch
from git_reviewer.git.snapshot import SnapshotError
from git_reviewer.guardians import execution, injection, patch_auditor
from git_reviewer.guardians.base import FAILURE_PREFIX, worst
from git_reviewer.llm.ollama import OllamaError, check_model, exposure_warnings, validate_url
from git_reviewer.llm.structured import ChatFn, ollama_chat
from git_reviewer.models import Decision, FixTarget, Verdict
from git_reviewer.patch import checks, edits
from git_reviewer.proc import ProcError
from git_reviewer.static.analyze import added_findings
from git_reviewer.static.tools import StaticAnalysisError

DATASETS = Path(__file__).resolve().parents[1] / "tests" / "guardians" / "datasets"
GUARDIANS = ("injection", "execution", "patch")
_PREFIXES = {"injection": "inj", "execution": "exe", "patch": "pat"}
_LIMITS = DiffLimits(max_bytes=256 * 1024, max_files=50, max_line_chars=10_000)
# Stands for "the reviewed repository" when the scanners run on a patch sample: there is none,
# and git-reviewer's own .venv (where ruff and bandit live) must not count as one.
_SCRATCH_ROOT = Path(tempfile.gettempdir()) / "git-reviewer-eval-no-repository"

Guardian = Literal["injection", "execution", "patch"]
Split = Literal["dev", "test"]
Label = Literal["malicious", "clean"]


class DiffInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    diff: str = Field(min_length=1)


class PatchInput(BaseModel):
    """The file before and after the patch: the diff and its added lines are built from them
    exactly as the fix loop builds them, and patch.checks needs both."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    finding: FixTarget
    before: str
    after: str


class Sample(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: str = Field(pattern=r"^(inj|exe|pat)-[0-9]{4}$")
    guardian: Guardian
    label: Label
    technique: str = Field(min_length=1, max_length=60)
    description: str = Field(min_length=1, max_length=300)
    source: str = Field(min_length=1, max_length=60)
    created: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    input: dict[str, Any]
    expected: Literal["suspect_or_block", "ok"]

    @property
    def split(self) -> Split:
        """ "dev" (odd numbers): may guide changes to a guardian. "test" (even numbers): only
        scored. Rates measured on the samples a change was tuned on overstate it."""
        return "dev" if int(self.id[-4:]) % 2 else "test"

    @model_validator(mode="after")
    def _consistent(self) -> Sample:
        if not self.id.startswith(_PREFIXES[self.guardian] + "-"):
            raise ValueError(f"id {self.id} does not match guardian {self.guardian}")
        if (self.label == "malicious") != (self.expected == "suspect_or_block"):
            raise ValueError(f"{self.id}: expected does not match label")
        return self


@dataclass(frozen=True)
class Outcome:
    sample: Sample
    verdict: Verdict
    deterministic: Verdict | None
    """What the deterministic layer alone decided (None when the guardian has none for code)."""

    failed: bool = False
    """The guardian agent failed (timeout, invalid answer...). It blocks, fail closed, but that
    block is not a detection: the run's rates are not valid."""

    @property
    def detected(self) -> bool:
        return self.verdict != "ok"

    @property
    def pipeline_detected(self) -> bool:
        """Detected by the guardian or by the deterministic rules that run before it."""
        return self.detected or self.deterministic not in (None, "ok")


class DatasetError(ValueError):
    """A sample file is invalid: nothing is measured."""


def load_samples(root: Path = DATASETS) -> list[Sample]:
    samples: list[Sample] = []
    seen: set[str] = set()
    if not root.is_dir():
        raise DatasetError(f"no dataset directory at {root}")
    # Hidden files (.DS_Store written by the Finder) are not samples.
    files = [p for p in root.rglob("*") if not p.is_dir() and not p.name.startswith(".")]
    for path in sorted(files):
        parts = path.relative_to(root).parts
        if len(parts) != 3 or path.suffix != ".json":
            # A sample stored anywhere else would silently not be measured.
            raise DatasetError(f"{path.relative_to(root)}: not <guardian>/<label>/<id>.json")
        guardian, label = parts[0], parts[1]
        try:
            sample = Sample.model_validate_json(path.read_bytes())
            parse_input(sample)
        except (ValidationError, DiffError, ValueError) as exc:
            raise DatasetError(f"{path.relative_to(root)}: {exc}") from exc
        if (sample.guardian, sample.label) != (guardian, label):
            raise DatasetError(f"{path.relative_to(root)}: stored under the wrong directory")
        if path.stem != sample.id or sample.id in seen:
            raise DatasetError(f"{path.relative_to(root)}: file name or duplicate id {sample.id}")
        seen.add(sample.id)
        samples.append(sample)
    return samples


def parse_input(sample: Sample) -> DiffInput | PatchInput:
    """The sample's input, checked to reach its guardian: a sample the guardian never really sees
    would count as a miss or a clean pass for the wrong reason."""
    if sample.guardian == "patch":
        patch = PatchInput.model_validate(sample.input)
        if patch.before == patch.after:
            raise ValueError("the patch changes nothing")
        try:
            ast.parse(patch.after)
        except SyntaxError as exc:
            raise ValueError(f"the patched file is not valid Python: {exc.msg}") from exc
        return patch
    parsed = DiffInput.model_validate(sample.input)
    diff = from_patch(parsed.diff, _LIMITS)  # must be a valid unified diff
    lines = parsed.diff.splitlines()
    # Every "+" line but the "+++ b/<path>" headers, which follow a "--- " line.
    headers = sum(
        1
        for prev, line in zip(["", *lines], lines, strict=False)
        if line.startswith("+++ ") and prev.startswith("--- ")
    )
    raw_added = sum(line.startswith("+") for line in lines) - headers
    if raw_added == 0 or sum(len(c.added_lines) for c in diff.files) != raw_added:
        raise ValueError("the diff's added lines are not all inside hunks")
    if sample.guardian == "execution" and not any(
        execution.is_test_infrastructure(c.path) for c in diff.files
    ):
        raise ValueError("the diff touches no test infrastructure: the guardian would not read it")
    return parsed


def evaluate(sample: Sample, chat: ChatFn, *, context_tokens: int) -> Outcome:
    parsed = parse_input(sample)
    if isinstance(parsed, PatchInput):
        target = parsed.finding
        diff = edits.unified_diff(target.file, parsed.before, parsed.after)
        added = edits.added_lines(parsed.before, parsed.after)
        found = patch_auditor.audit(target, diff, added, chat, context_tokens=context_tokens)
        rules = checks.problems(target.file, parsed.before, parsed.after)
        if not rules:  # as in the fix loop: then the scanners on both versions
            try:
                rules = added_findings(target.file, parsed.before, parsed.after, _SCRATCH_ROOT)
            except (StaticAnalysisError, SnapshotError, ProcError, OSError):
                # Not measurable: the run is refused like any guardian failure.
                return Outcome(sample, found.verdict, "block", failed=True)
        return Outcome(sample, found.verdict, "block" if rules else "ok", _failed([found]))
    diff = from_patch(parsed.diff, _LIMITS)
    if sample.guardian == "injection":
        decisions = injection.guard_before_review(diff, chat, context_tokens=context_tokens)
        return Outcome(sample, worst(decisions), decisions[0].verdict, _failed(decisions))
    decisions = execution.check_test_changes(diff, chat, context_tokens=context_tokens)
    return Outcome(sample, worst(decisions), None, _failed(decisions))


def _failed(decisions: Iterable[Decision]) -> bool:
    return any(reason.startswith(FAILURE_PREFIX) for d in decisions for reason in d.reasons)


def summarize(outcomes: Iterable[Outcome]) -> dict[str, dict[str, Any]]:
    by_guardian: dict[str, list[Outcome]] = {}
    for outcome in outcomes:
        by_guardian.setdefault(outcome.sample.guardian, []).append(outcome)
    summary: dict[str, dict[str, Any]] = {}
    for guardian, found in by_guardian.items():
        malicious = [o for o in found if o.sample.label == "malicious"]
        clean = [o for o in found if o.sample.label == "clean"]
        has_rules = any(o.deterministic is not None for o in found)
        summary[guardian] = {
            "malicious": len(malicious),
            "detected": sum(o.detected for o in malicious),
            "detection_rate": _rate(sum(o.detected for o in malicious), len(malicious)),
            "clean": len(clean),
            "false_positives": sum(o.detected for o in clean),
            "fp_rate": _rate(sum(o.detected for o in clean), len(clean)),
            "deterministic": (
                {
                    "detected": sum(o.deterministic != "ok" for o in malicious),
                    "false_positives": sum(o.deterministic != "ok" for o in clean),
                }
                if has_rules
                else None
            ),
            "pipeline": (
                {
                    "detected": sum(o.pipeline_detected for o in malicious),
                    "false_positives": sum(o.pipeline_detected for o in clean),
                }
                if guardian == "patch"
                else None
            ),
            "splits": {
                split: _counts([o for o in found if o.sample.split == split])
                for split in ("dev", "test")
            },
            "results": [
                {
                    "id": o.sample.id,
                    "label": o.sample.label,
                    "split": o.sample.split,
                    "verdict": o.verdict,
                    "deterministic": o.deterministic,
                    "failed": o.failed,
                }
                for o in found
            ],
            "errors": [_brief(o.sample) for o in found if o.failed],
            "misses": [_brief(o.sample) for o in malicious if not o.detected],
            "false_positive_ids": [_brief(o.sample) for o in clean if o.detected],
        }
    return summary


def render_text(summary: dict[str, dict[str, Any]], model: str) -> str:
    lines = [
        f"guardian model: {model}",
        "",
        "| Guardian | Malicious | Detected | Detection rate | Clean | False positives | FP rate |",
        "|----------|-----------|----------|----------------|-------|-----------------|---------|",
    ]
    for guardian in GUARDIANS:
        if guardian in summary:
            s = summary[guardian]
            lines.append(
                f"| {guardian} | {s['malicious']} | {s['detected']} | {s['detection_rate']} "
                f"| {s['clean']} | {s['false_positives']} | {s['fp_rate']} |"
            )
    for guardian in GUARDIANS:
        s = summary.get(guardian)
        if s is None:
            continue
        lines.append("")
        if s["deterministic"] is not None:
            d = s["deterministic"]
            lines.append(
                f"{guardian}: deterministic layer alone: {d['detected']}/{s['malicious']} "
                f"detected, {d['false_positives']}/{s['clean']} false positives"
            )
        if s["pipeline"] is not None:
            p = s["pipeline"]
            lines.append(
                f"{guardian}: whole pipeline: {p['detected']}/{s['malicious']} detected, "
                f"{p['false_positives']}/{s['clean']} false positives"
            )
        for split, c in s["splits"].items():
            lines.append(
                f"{guardian}: {split} split: {c['detected']}/{c['malicious']} detected, "
                f"{c['false_positives']}/{c['clean']} false positives; whole pipeline "
                f"{c['pipeline_detected']}/{c['malicious']}, "
                f"{c['pipeline_false_positives']}/{c['clean']}"
            )
        for miss in s["misses"]:
            technique = sanitize.one_line(miss["technique"])
            lines.append(f"{guardian}: missed {miss['id']} ({technique})")
        for false in s["false_positive_ids"]:
            technique = sanitize.one_line(false["technique"])
            lines.append(f"{guardian}: false positive {false['id']} ({technique})")
        for error in s["errors"]:
            lines.append(f"{guardian}: ERROR, the guardian failed on {error['id']}")
    return "\n".join(lines)


def _counts(found: list[Outcome]) -> dict[str, int]:
    malicious = [o for o in found if o.sample.label == "malicious"]
    clean = [o for o in found if o.sample.label == "clean"]
    return {
        "malicious": len(malicious),
        "detected": sum(o.detected for o in malicious),
        "pipeline_detected": sum(o.pipeline_detected for o in malicious),
        "clean": len(clean),
        "false_positives": sum(o.detected for o in clean),
        "pipeline_false_positives": sum(o.pipeline_detected for o in clean),
    }


def _rate(part: int, whole: int) -> str:
    return f"{100 * part / whole:.0f}%" if whole else "n/a"


def _brief(sample: Sample) -> dict[str, str]:
    return {"id": sample.id, "technique": sample.technique, "description": sample.description}


def _guardian_chat() -> tuple[ChatFn, str, int]:
    settings = load_settings()
    endpoint = validate_url(settings.ollama_url)
    check_model(endpoint, settings.guardian_model, timeout=settings.ollama_timeout_seconds)
    for warning in exposure_warnings(endpoint):
        print(f"warning: {warning}", file=sys.stderr)
    chat = ollama_chat(
        endpoint,
        settings.guardian_model,
        timeout=settings.ollama_timeout_seconds,
        num_ctx=settings.model_context_tokens,
    )
    return chat, settings.guardian_model, settings.model_context_tokens


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--guardian", choices=[*GUARDIANS, "all"], default="all")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)
    try:
        samples = load_samples()
        chat, model, context_tokens = _guardian_chat()
    except (DatasetError, ConfigError, OllamaError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    chosen = [s for s in samples if args.guardian in ("all", s.guardian)]
    targeted = GUARDIANS if args.guardian == "all" else (args.guardian,)
    for guardian in targeted:
        labels = {s.label for s in chosen if s.guardian == guardian}
        if labels != {"malicious", "clean"}:
            # Without both kinds, a rate would be missing or meaningless.
            print(f"error: {guardian} needs malicious and clean samples", file=sys.stderr)
            return 1
    outcomes = []
    for number, sample in enumerate(chosen, 1):
        print(f"[{number}/{len(chosen)}] {sample.id}", file=sys.stderr)
        outcomes.append(evaluate(sample, chat, context_tokens=context_tokens))
    summary = summarize(outcomes)
    failed = [o.sample.id for o in outcomes if o.failed]
    if args.format == "json":
        today = datetime.date.today().isoformat()
        print(json.dumps({"date": today, "model": model, "guardians": summary}, indent=2))
    else:
        print(render_text(summary, model))
    if failed:
        # A failure blocks, which would count as a detection: these rates must not be published.
        message = f"the guardian failed on {len(failed)} sample(s); rates are not valid"
        print(f"error: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

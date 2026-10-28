from __future__ import annotations

import hashlib
import json

import pytest

from git_reviewer.models import (
    Decision,
    FixProposal,
    FixTarget,
    ReviewFinding,
    SandboxRun,
    StaticFinding,
)
from git_reviewer.patch.edits import unified_diff
from git_reviewer.report import render
from git_reviewer.report.model import Report, exit_code

ESC = chr(0x1B)


def make(status: str = "reviewed", severity: str | None = None, **extra: object) -> Report:
    findings = ()
    if severity:
        findings = (
            StaticFinding.model_validate(
                {
                    "tool": "ruff",
                    "rule": "F821",
                    "file": "a.py",
                    "line": 1,
                    "severity": severity,
                    "message": "undefined",
                }
            ),
        )
    fields: dict[str, object] = {
        "status": status,
        "mode": "staged",
        "files": (),
        "static_findings": findings,
        "review_findings": (),
        "summary": "",
        "decisions": (),
        "notes": (),
        "reason": None,
    }
    fields.update(extra)
    return Report.model_validate(fields)


@pytest.mark.parametrize(
    ("status", "severity", "block_mode", "expected"),
    [
        ("blocked", None, False, 2),
        ("blocked", None, True, 2),
        ("not_reviewed", None, True, 2),
        ("not_reviewed", None, False, 0),
        ("reviewed", "high", True, 1),
        ("reviewed", "high", False, 0),
        ("reviewed", "medium", True, 0),
        ("reviewed", None, True, 0),
        ("empty", None, True, 0),
    ],
)
def test_exit_codes(status: str, severity: str | None, block_mode: bool, expected: int) -> None:
    assert exit_code(make(status, severity), block_mode=block_mode, threshold="high") == expected


def test_model_text_is_sanitized_in_the_terminal() -> None:
    finding = ReviewFinding.model_validate(
        {
            "file": "a.py",
            "line": 1,
            "severity": "low",
            "category": "bug",
            "title": f"x{ESC}]52;c;ZXZpbA=={chr(7)}",
            "explanation": f"see {chr(0x202E)}txt.exe",
        }
    )
    decision = Decision(source="injection.agent", verdict="suspect", reasons=(f"r{ESC}[2J",))
    text = render.to_text(make(review_findings=(finding,), decisions=(decision,)))
    assert ESC not in text and chr(0x202E) not in text
    assert "<U+001B>" in text and "<U+202E>" in text


def preview(original: str) -> list[str]:
    """The terminal lines of a report proposing to change `return 1` into `return 2`."""
    patched = original.replace("return 1", "return 2")
    target = FixTarget(
        source="reviewer", rule="bug", file="a.py", line=3, severity="high", message="m"
    )
    fix = FixProposal(
        target=target,
        file="a.py",
        explanation="return 2",
        diff=unified_diff("a.py", original, patched),
        patched=patched,
        original_sha256=hashlib.sha256(original.encode()).hexdigest(),
    )
    return render.to_text(make(fix_requested=True, fix=fix)).split("\n")


@pytest.mark.parametrize("separator", ["\x1c", "\x0b", "\x0c", "\x85", "\u2028", "\u2029"])
def test_patch_preview_cannot_be_forged_with_line_separators(separator: str) -> None:
    # The original file comes from the reviewed branch: a separator in a comment must not show
    # up as a fake removed line in the diff the user approves (T-06).
    shown = preview(f"def run(cmd):\n    # note{separator}-    os.system(cmd)\n    return 1\n")
    assert "  | -    os.system(cmd)" not in shown
    marker = f"<U+{ord(separator):04X}>"
    assert f"  |      # note{marker}-    os.system(cmd)" in shown
    assert "  | -    return 1" in shown and "  | +    return 2" in shown


def test_patch_preview_of_a_crlf_file_hides_only_the_line_ending_cr() -> None:
    shown = preview("def run(cmd):\r\n    x = 1  # a\rb\r\n    return 1\r\n")
    assert "  | -    return 1" in shown and "  | +    return 2" in shown
    assert "  |      x = 1  # a<U+000D>b" in shown


def test_json_is_ascii_and_complete() -> None:
    data = json.loads(render.to_json(make(severity="high")))
    assert data["status"] == "reviewed"
    assert data["static_findings"][0]["rule"] == "F821"
    assert data["security"]["verdict"] == "ok"
    assert render.to_json(make(summary=f"é{ESC}")).isascii()


def sandbox_run(outcome: str = "failed", output: str = "") -> SandboxRun:
    return SandboxRun.model_validate(
        {"tool": "pytest", "outcome": outcome, "exit_code": 1, "seconds": 2.5, "output": output}
    )


def test_sandbox_section_shows_the_end_of_failing_output_sanitized() -> None:
    output = "\n".join(f"line {i}" for i in range(40)) + f"\n{ESC}[2Jboom"
    report = make(tests_requested=True, sandbox_runs=(sandbox_run(output=output),))
    text = render.to_text(report)
    assert "pytest: failed (exit 1, 2.5s)" in text
    assert "line 39" in text and "line 10" not in text
    assert ESC not in text
    assert "output is untrusted" in text


def test_passing_runs_hide_their_output() -> None:
    report = make(tests_requested=True, sandbox_runs=(sandbox_run("passed", "noise"),))
    assert "noise" not in render.to_text(report)


def test_sandbox_note_is_shown_and_in_json() -> None:
    report = make(tests_requested=True, sandbox_note="tests not run: Docker stopped")
    assert "tests not run: Docker stopped" in render.to_text(report)
    data = json.loads(render.to_json(report))
    note = "tests not run: Docker stopped"
    assert data["sandbox"] == {"requested": True, "note": note, "runs": []}


def test_tests_requested_with_nothing_to_review_exits_0() -> None:
    report = make("empty", tests_requested=True)
    assert exit_code(report, block_mode=True, threshold="high") == 0


def test_a_block_after_the_review_still_shows_the_review_and_the_tests() -> None:
    block = Decision.model_validate(
        {"source": "execution.fingerprint", "verdict": "block", "reasons": ("changed",)}
    )
    report = make(
        "blocked",
        summary="looks fine",
        decisions=(block,),
        tests_requested=True,
        sandbox_runs=(sandbox_run("passed"),),
    )
    text = render.to_text(report)
    assert "summary: looks fine" in text
    assert "pytest: passed" in text
    assert "after the review" in text
    assert "not sent for review" not in text


def test_a_block_before_the_review_says_so() -> None:
    block = Decision.model_validate({"source": "injection.barrier", "verdict": "block"})
    text = render.to_text(make("blocked", decisions=(block,)))
    assert "not sent for review" in text
    assert "LLM review" not in text

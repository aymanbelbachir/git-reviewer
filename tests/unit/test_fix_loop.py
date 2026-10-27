"""The fix loop in the review graph, with a fake model and a fake sandbox."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer.models import SandboxTool
from git_reviewer.report.model import Report
from tests.helpers import FakeLLM, FakeSandbox, guardian_json, patch_json, run_graph
from tests.helpers import stage as staged

VULNERABLE = (
    "import subprocess\n\n\ndef run(name):\n    return subprocess.run('ls ' + name, shell=True)\n"
)
GOOD_LINE = "    return subprocess.run(['ls', '--', name], check=True)\n"
GOOD = patch_json("app.py", 5, 5, GOOD_LINE, why="pass the arguments as a list")


@pytest.fixture
def repo(make_repo: Callable[..., Path]) -> Path:
    return staged(make_repo, {"app.py": VULNERABLE})


def fix(repo: Path, llm: FakeLLM, sandbox: FakeSandbox | None = None) -> Report:
    return run_graph(repo, llm, sandbox=sandbox or FakeSandbox(), fix=True)


def sources(report: Report) -> dict[str, str]:
    return {d.source: d.verdict for d in report.decisions}


def test_a_good_patch_is_validated_audited_and_proposed(repo: Path) -> None:
    sandbox = FakeSandbox()
    llm = FakeLLM(patch=GOOD)
    report = fix(repo, llm, sandbox)
    assert report.fix is not None
    assert report.fix.file == "app.py"
    assert report.fix.target.rule == "B602"
    assert "+    return subprocess.run(['ls', '--', name], check=True)" in report.fix.diff
    assert report.fix.tests is not None and report.fix.tests.outcome == "passed"
    assert [a.accepted for a in report.fix_attempts] == [True]
    # Baseline run, then the run with the patch; the sandbox copy is restored afterwards.
    assert sandbox.runs == ["pytest", "ruff", "pytest"]
    assert b"check=True" in sandbox.contents[2]["app.py"]
    assert (sandbox.tree / "app.py").read_text() == VULNERABLE
    assert report.status == "reviewed"


def test_the_auditor_sees_only_the_finding_and_the_patch(repo: Path) -> None:
    llm = FakeLLM(patch=GOOD)
    fix(repo, llm)
    (_system, user) = llm.guardian_calls[-1]
    assert "B602" in user and "check=True" in user
    assert "pass the arguments as a list" not in user  # never the author's explanation


def test_a_patch_failing_the_checks_never_runs(repo: Path) -> None:
    evil = patch_json("app.py", 1, 1, "import subprocess\nimport socket\n")
    sandbox = FakeSandbox()
    llm = FakeLLM(patch=evil)
    report = fix(repo, llm, sandbox)
    assert report.fix is None
    assert len(llm.patch_calls) == 3
    assert sandbox.runs == ["pytest", "ruff"]  # only the baseline
    assert all("import of socket" in " ".join(a.reasons) for a in report.fix_attempts)
    assert "no patch passed every check in 3 round(s)" in (report.fix_note or "")


def test_rejections_are_fed_back_inside_delimiters(repo: Path) -> None:
    llm = FakeLLM(patch=patch_json("app.py", 1, 1, "import subprocess\nimport socket\n"))
    fix(repo, llm)
    (_system, second) = llm.patch_calls[1]
    assert "<untrusted_rejections" in second
    assert "attempt 1: adds an import of socket" in second


def test_patch_that_breaks_the_tests_is_rejected(repo: Path) -> None:
    sandbox = FakeSandbox(pytest_outcomes=["passed", "failed", "failed", "failed"])
    report = fix(repo, FakeLLM(patch=GOOD), sandbox)
    assert report.fix is None
    assert all("do not pass" in a.reasons[0] for a in report.fix_attempts)


def test_patch_that_does_not_remove_the_finding_is_rejected(repo: Path) -> None:
    unrelated = patch_json("app.py", 4, 3, "# runs ls\n")
    report = fix(repo, FakeLLM(patch=unrelated))
    assert report.fix is None
    assert "bandit still reports B602" in report.fix_attempts[0].reasons[0]


@pytest.mark.parametrize(("guardian_context", "too_large"), [(12_288, True), (32_768, False)])
def test_a_patch_the_auditor_cannot_read_whole_never_runs(
    repo: Path, guardian_context: int, too_large: bool
) -> None:
    # About 9 kB of added comments (two edits: one edit holds at most 5,000 characters): more
    # than the auditor reads at 12,288 tokens (about 5.8 kB), less than at 32,768. Rejected
    # before the sandbox, not after a wasted run.
    notes = "".join(f"# note {n:03}: {'keep the arguments as a list ' * 2}\n" for n in range(60))
    indented = "".join(f"    {line}\n" for line in notes.splitlines())
    padded = json.dumps(
        {
            "edits": [
                {"path": "app.py", "start_line": 4, "end_line": 3, "replacement": notes},
                {
                    "path": "app.py",
                    "start_line": 5,
                    "end_line": 5,
                    "replacement": indented + GOOD_LINE,
                },
            ],
            "explanation": "pass the arguments as a list",
        }
    )
    sandbox = FakeSandbox()
    report = run_graph(
        repo,
        FakeLLM(patch=padded),
        sandbox=sandbox,
        fix=True,
        guardian_context_tokens=guardian_context,
    )
    reasons = " ".join(r for a in report.fix_attempts for r in a.reasons)
    assert ("too large for the patch auditor" in reasons) is too_large
    assert (sandbox.runs == ["pytest", "ruff"]) is too_large  # only the baseline
    assert (report.fix is not None) is not too_large


def auditor_says(answer: str) -> Callable[[str, str], str]:
    """A fake guardian model whose answer only the patch auditor gets; the other guardians,
    which also read the reviewed code, see nothing wrong."""

    def chat(system: str, user: str) -> str:
        return answer if "auditing a patch" in system else guardian_json("ok")

    return chat


def test_auditor_block_rejects_and_is_shown_as_an_alert(repo: Path) -> None:
    llm = FakeLLM(
        patch=GOOD, guardian=auditor_says(guardian_json("block", ["changes unrelated code"]))
    )
    report = fix(repo, llm)
    assert report.fix is None
    assert sources(report)["patch.auditor"] == "suspect"
    assert report.status == "reviewed"  # a rejected patch does not block the review


def test_auditor_alert_is_attached_to_the_proposal(repo: Path) -> None:
    llm = FakeLLM(patch=GOOD, guardian=guardian_json("suspect", ["check=True changes behavior"]))
    report = fix(repo, llm)
    assert report.fix is not None
    assert report.fix.alerts == ("patch auditor: check=True changes behavior",)


def test_canary_leak_by_the_author_blocks(repo: Path) -> None:
    def leaking(system: str, user: str) -> str:
        return patch_json("app.py", 5, 5, GOOD_LINE, why=system.split()[-1])

    report = fix(repo, FakeLLM(patch=leaking))
    assert report.status == "blocked"
    assert sources(report)["patch.canary"] == "block"


def test_edits_outside_the_file_are_rejected(repo: Path) -> None:
    report = fix(repo, FakeLLM(patch=patch_json("../.git/hooks/pre-commit", 1, 1, "x\n")))
    assert report.fix is None
    assert "only app.py may be changed" in report.fix_attempts[0].reasons[0]


def test_no_patch_when_the_tests_already_fail(repo: Path) -> None:
    llm = FakeLLM(patch=GOOD)
    report = fix(repo, llm, FakeSandbox(pytest_outcomes=["failed"]))
    assert report.fix is None
    assert "tests must run and pass" in (report.fix_note or "")
    assert llm.patch_calls == []


def test_no_patch_without_a_fixable_finding(make_repo: Callable[..., Path]) -> None:
    repo = staged(make_repo, {"app.py": "def add(a, b):\n    return a + b\n"})
    report = fix(repo, FakeLLM(patch=GOOD))
    assert "no finding of medium severity" in (report.fix_note or "")


def test_denied_files_are_never_patched(make_repo: Callable[..., Path]) -> None:
    repo = staged(make_repo, {"tests/conftest.py": VULNERABLE})
    llm = FakeLLM(patch=GOOD)
    report = fix(repo, llm)
    assert "never patched" in (report.fix_note or "")
    assert llm.patch_calls == []


def test_working_directory_changed_during_validation_blocks(repo: Path) -> None:
    calls: list[SandboxTool] = []

    def escape(tool: SandboxTool) -> None:
        calls.append(tool)
        if len(calls) == 3:  # the validation run
            (repo / "app.py").write_text("tampered\n")

    report = fix(repo, FakeLLM(patch=GOOD), FakeSandbox(on_run=escape))
    assert report.status == "blocked"
    assert report.fix is None


def test_patched_tests_go_through_the_execution_guardian(make_repo: Callable[..., Path]) -> None:
    repo = staged(make_repo, {"tests/test_tool.py": VULNERABLE})
    patch = patch_json("tests/test_tool.py", 5, 5, GOOD_LINE)

    def guardian(system: str, user: str) -> str:
        # The review's own checks pass; only the patched test is refused.
        verdict = "block" if "check=True" in user else "ok"
        return guardian_json(verdict, ["runs a subprocess"] if verdict == "block" else [])

    llm = FakeLLM(patch=patch, guardian=guardian)
    report = fix(repo, llm)
    assert report.fix is None
    assert sources(report)["patch.execution"] == "suspect"
    (_system, user) = llm.guardian_calls[-1]
    assert "tests/test_tool.py:5:" in user


def test_secrets_quoted_in_rejection_reasons_are_masked(make_repo: Callable[..., Path]) -> None:
    from tests.helpers import random_token

    token = random_token()
    # In a non-Python file: gitleaks finds it (so it is masked), but it is not the fix target.
    repo = staged(make_repo, {"app.py": VULNERABLE, "settings.toml": f'token = "{token}"\n'})
    answer = guardian_json("block", [f"the patch keeps {token}"])
    llm = FakeLLM(patch=GOOD, guardian=auditor_says(answer))
    report = fix(repo, llm)
    reasons = [reason for attempt in report.fix_attempts for reason in attempt.reasons]
    assert reasons and all(token not in reason for reason in reasons)
    assert any("[secret masked]" in reason for reason in reasons)


def test_a_suspect_verdict_on_patched_tests_is_kept(make_repo: Callable[..., Path]) -> None:
    repo = staged(make_repo, {"tests/test_tool.py": VULNERABLE})
    patch = patch_json("tests/test_tool.py", 5, 5, GOOD_LINE)

    def guardian(system: str, user: str) -> str:
        if "check=True" in user and "untrusted_changes" in user:
            return guardian_json("suspect", ["starts a subprocess"])
        return guardian_json("ok")

    report = fix(repo, FakeLLM(patch=patch, guardian=guardian))
    assert report.fix is not None
    assert sources(report)["patch.execution"] == "suspect"


def test_the_patched_test_output_is_masked_in_json(make_repo: Callable[..., Path]) -> None:
    import json

    from git_reviewer.report import render
    from tests.helpers import random_token

    token = random_token()
    repo = staged(make_repo, {"app.py": VULNERABLE, "settings.toml": f'token = "{token}"\n'})
    sandbox = FakeSandbox()
    original_run = sandbox.run

    def printing_run(tool, run_id, image_id):  # type: ignore[no-untyped-def]
        return original_run(tool, run_id, image_id).model_copy(update={"output": f"warn {token}"})

    sandbox.run = printing_run  # type: ignore[method-assign]
    report = fix(repo, FakeLLM(patch=GOOD), sandbox)
    assert report.fix is not None
    data = json.loads(render.to_json(report))
    assert token not in json.dumps(data)


def test_a_patch_line_too_long_to_read_is_rejected(repo: Path) -> None:
    long_line = "    return subprocess.run(['ls', '--', name], check=True)  # " + "x" * 400 + "\n"
    report = fix(repo, FakeLLM(patch=patch_json("app.py", 5, 5, long_line)))
    assert report.fix is None
    assert "longer than 300 characters" in report.fix_attempts[0].reasons[0]


def test_bandit_unable_to_parse_is_not_a_fix(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from git_reviewer.graph import fix as fix_module

    monkeypatch.setattr(fix_module, "run_bandit", lambda snapshot, files, repo: ([], files))
    report = fix(repo, FakeLLM(patch=GOOD))
    assert report.fix is None
    assert "cannot re-run the scanner" in report.fix_attempts[0].reasons[0]


def test_failure_lines_are_masked_before_being_cut() -> None:
    from git_reviewer.graph.fix import _failures
    from git_reviewer.models import SandboxRun

    secret = "ghp_" + "A" * 36
    line = "FAILED tests/test_x.py::test - " + "x" * 160 + secret
    run = SandboxRun(tool="pytest", outcome="failed", exit_code=1, seconds=1.0, output=line)
    (shown,) = _failures(run, (secret,))
    assert "ghp_" not in shown


def test_no_fix_heading_when_nothing_is_proposed(repo: Path) -> None:
    from git_reviewer.report import render

    text = render.to_text(fix(repo, FakeLLM(patch=GOOD), FakeSandbox(pytest_outcomes=["failed"])))
    assert "Proposed fix" not in text
    assert "Fix:" in text


# --- a diff is never offered for approval in masked form -------------------------------------


def test_a_patch_that_would_show_a_secret_is_never_offered(make_repo: Callable[..., Path]) -> None:
    from tests.helpers import random_token

    token = random_token()
    repo = staged(make_repo, {"app.py": VULNERABLE, "settings.toml": f'token = "{token}"\n'})
    leaking = patch_json("app.py", 5, 5, f"{GOOD_LINE}    # was {token}\n")
    report = fix(repo, FakeLLM(patch=leaking))
    assert report.fix is None
    assert "could only be shown masked" in report.fix_attempts[0].reasons[-1]


def test_a_file_holding_a_secret_is_not_sent_to_the_author(make_repo: Callable[..., Path]) -> None:
    from tests.helpers import random_token

    repo = staged(make_repo, {"app.py": VULNERABLE + f'TOKEN = "{random_token()}"\n'})
    llm = FakeLLM(patch=GOOD)
    report = fix(repo, llm)
    assert report.fix is None
    assert "detected as a secret" in (report.fix_note or "")
    assert llm.patch_calls == []


def test_the_final_report_never_offers_a_diff_masking_would_change() -> None:
    from git_reviewer.graph.nodes import _fix_note, _offerable
    from git_reviewer.models import FixProposal, FixTarget

    diff = "diff --git a/a.py b/a.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n+run_hidden()\n"
    target = FixTarget(
        source="reviewer", rule="bug", file="a.py", line=1, severity="high", message="m"
    )
    proposal = FixProposal(
        target=target,
        file="a.py",
        explanation="e",
        diff=diff,
        patched="x = 2\nrun_hidden()\n",
        original_sha256="0" * 64,
    )
    crafted = ("x = 2\n+run_hidden()",)  # a multi-line "secret" spanning an added line
    assert _offerable(proposal, ()) is proposal
    assert _offerable(proposal, crafted) is None
    state = {"fix_proposal": proposal, "fix_attempts": ()}
    assert "shown masked" in (_fix_note(state, crafted) or "")  # type: ignore[arg-type]

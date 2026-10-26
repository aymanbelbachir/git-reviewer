"""scripts/eval_guardians.py: sample validation and the metrics it reports (SECURITY.md §7).

The samples here are harmless placeholders: a label is only metadata, and the fake model decides
the verdict, so these tests check the measuring, not the guardians.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import eval_guardians as ev
from tests.helpers import FakeLLM, guardian_json

DIFF = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
TEST_DIFF = DIFF.replace("app.py", "tests/test_app.py")
FINDING = {
    "source": "bandit",
    "rule": "B602",
    "file": "app.py",
    "line": 1,
    "severity": "high",
    "message": "subprocess call with shell=True",
}


def sample(sample_id: str, guardian: str, label: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": sample_id,
        "guardian": guardian,
        "label": label,
        "technique": "placeholder",
        "description": "harmless test placeholder",
        "source": "unit-test",
        "created": "2026-10-26",
        "input": payload,
        "expected": "suspect_or_block" if label == "malicious" else "ok",
    }


def store(root: Path, data: dict[str, Any], name: str | None = None) -> None:
    path = root / data["guardian"] / data["label"] / f"{name or data['id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_valid_samples_load(tmp_path: Path) -> None:
    store(tmp_path, sample("inj-0001", "injection", "malicious", {"diff": DIFF}))
    store(tmp_path, sample("exe-0001", "execution", "clean", {"diff": TEST_DIFF}))
    patch = {"finding": FINDING, "before": "x = 1\n", "after": "x = 2\n"}
    store(tmp_path, sample("pat-0001", "patch", "clean", patch))
    assert [s.id for s in ev.load_samples(tmp_path)] == ["exe-0001", "inj-0001", "pat-0001"]


@pytest.mark.parametrize(
    ("data", "name", "problem"),
    [
        (sample("inj-0001", "injection", "clean", {"diff": "not a diff"}), None, "file header"),
        (sample("inj-0001", "injection", "clean", {"diff": DIFF, "x": 1}), None, "Extra"),
        (sample("exe-0001", "injection", "clean", {"diff": DIFF}), None, "does not match"),
        (sample("inj-0001", "injection", "clean", {"diff": DIFF}), "inj-0002", "file name"),
        (
            {**sample("inj-0001", "injection", "clean", {"diff": DIFF}), "expected": "ok_or_x"},
            None,
            "expected",
        ),
        (sample("pat-0001", "patch", "clean", {"finding": FINDING, "before": "x"}), None, "after"),
    ],
)
def test_invalid_samples_stop_the_measurement(
    tmp_path: Path, data: dict[str, Any], name: str | None, problem: str
) -> None:
    store(tmp_path, data, name)
    with pytest.raises(ev.DatasetError, match=problem):
        ev.load_samples(tmp_path)


def test_sample_stored_in_the_wrong_directory_is_refused(tmp_path: Path) -> None:
    data = sample("inj-0001", "injection", "clean", {"diff": DIFF})
    path = tmp_path / "injection" / "malicious" / "inj-0001.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ev.DatasetError, match="wrong directory"):
        ev.load_samples(tmp_path)


def test_execution_and_patch_samples_reach_their_guardian(tmp_path: Path) -> None:
    store(tmp_path, sample("exe-0001", "execution", "malicious", {"diff": TEST_DIFF}))
    patch = {"finding": FINDING, "before": "x = 1\n", "after": "x = 2\n"}
    store(tmp_path, sample("pat-0001", "patch", "malicious", patch))
    llm = FakeLLM(guardian=guardian_json("block", ["placeholder"]))
    outcomes = [ev.evaluate(s, llm, context_tokens=32_768) for s in ev.load_samples(tmp_path)]
    assert [o.verdict for o in outcomes] == ["block", "block"]
    assert outcomes[1].deterministic == "ok"  # patch.checks found nothing in x = 2
    assert "tests/test_app.py:1: x = 2" in llm.guardian_calls[0][1]


def test_metrics_count_detections_false_positives_and_misses(tmp_path: Path) -> None:
    for number, label in enumerate(["malicious", "malicious", "clean", "clean"], 1):
        store(tmp_path, sample(f"exe-{number:04d}", "execution", label, {"diff": TEST_DIFF}))
    answers = iter(
        [guardian_json("block"), guardian_json("ok"), guardian_json("suspect"), guardian_json("ok")]
    )
    llm = FakeLLM(guardian=lambda system, user: next(answers))
    outcomes = [ev.evaluate(s, llm, context_tokens=32_768) for s in ev.load_samples(tmp_path)]
    summary = ev.summarize(outcomes)["execution"]
    assert (summary["detected"], summary["detection_rate"]) == (1, "50%")
    assert (summary["false_positives"], summary["fp_rate"]) == (1, "50%")
    assert [m["id"] for m in summary["misses"]] == ["exe-0002"]
    assert [f["id"] for f in summary["false_positive_ids"]] == ["exe-0003"]
    assert "| execution | 2 | 1 | 50% | 2 | 1 | 50% |" in ev.render_text(
        ev.summarize(outcomes), "m"
    )


def test_guardian_failure_is_reported_as_an_error_not_a_detection(tmp_path: Path) -> None:
    # Fail closed: a model error blocks. That block must not pass for a detection.
    store(tmp_path, sample("exe-0001", "execution", "malicious", {"diff": TEST_DIFF}))
    llm = FakeLLM(guardian=TimeoutError("slow"))
    outcomes = [ev.evaluate(s, llm, context_tokens=32_768) for s in ev.load_samples(tmp_path)]
    assert outcomes[0].verdict == "block" and outcomes[0].failed
    assert [e["id"] for e in ev.summarize(outcomes)["execution"]["errors"]] == ["exe-0001"]


def test_a_run_with_guardian_failures_exits_with_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store(tmp_path, sample("exe-0001", "execution", "malicious", {"diff": TEST_DIFF}))
    store(tmp_path, sample("exe-0002", "execution", "clean", {"diff": TEST_DIFF}))
    samples = ev.load_samples(tmp_path)
    monkeypatch.setattr(ev, "load_samples", lambda: samples)
    failing = FakeLLM(guardian=TimeoutError("slow"))
    monkeypatch.setattr(ev, "_guardian_chat", lambda: (failing, "model", 32_768))
    assert ev.main(["--guardian", "execution", "--format", "json"]) == 1
    assert "rates are not valid" in capsys.readouterr().err


def test_a_guardian_without_both_kinds_of_samples_is_not_measured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store(tmp_path, sample("exe-0001", "execution", "malicious", {"diff": TEST_DIFF}))
    samples = ev.load_samples(tmp_path)
    monkeypatch.setattr(ev, "load_samples", lambda: samples)
    monkeypatch.setattr(ev, "_guardian_chat", lambda: (FakeLLM(), "model", 32_768))
    assert ev.main(["--guardian", "execution"]) == 1
    assert "needs malicious and clean samples" in capsys.readouterr().err


@pytest.mark.parametrize(
    "relative",
    ["injection/inj-0001.json", "injection/clean/x/inj-0001.json", "injection/clean/inj-0001.txt"],
)
def test_files_outside_the_layout_are_refused(tmp_path: Path, relative: str) -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ev.DatasetError, match="not <guardian>"):
        ev.load_samples(tmp_path)


def test_a_missing_dataset_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ev.DatasetError, match="no dataset directory"):
        ev.load_samples(tmp_path / "missing")


def test_hidden_files_are_not_samples(tmp_path: Path) -> None:
    store(tmp_path, sample("inj-0001", "injection", "clean", {"diff": DIFF}))
    (tmp_path / ".DS_Store").write_bytes(b"\x00")
    (tmp_path / "injection" / ".DS_Store").write_bytes(b"\x00")
    assert [s.id for s in ev.load_samples(tmp_path)] == ["inj-0001"]


@pytest.mark.parametrize(
    ("data", "problem"),
    [
        # Header without a hunk: the "+" line would never reach the guardian.
        (
            sample(
                "inj-0001",
                "injection",
                "clean",
                {"diff": "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n+x = 1\n"},
            ),
            "not all inside hunks",
        ),
        (sample("exe-0001", "execution", "clean", {"diff": DIFF}), "no test infrastructure"),
        (
            sample(
                "pat-0001",
                "patch",
                "clean",
                {"finding": FINDING, "before": "x = 1\n", "after": "x = 1\n"},
            ),
            "changes nothing",
        ),
        (
            sample(
                "pat-0001",
                "patch",
                "clean",
                {"finding": FINDING, "before": "x = 1\n", "after": "x = (\n"},
            ),
            "not valid Python",
        ),
    ],
)
def test_samples_that_would_not_reach_their_guardian_are_refused(
    tmp_path: Path, data: dict[str, Any], problem: str
) -> None:
    store(tmp_path, data)
    with pytest.raises(ev.DatasetError, match=problem):
        ev.load_samples(tmp_path)


def test_committed_dataset_is_valid_and_large_enough() -> None:
    # The spec asks for at least 20 malicious samples per guardian, and clean ones to measure
    # false positives. Loading also checks every diff parses and every patch is complete.
    samples = ev.load_samples()
    for guardian in ev.GUARDIANS:
        found = [s for s in samples if s.guardian == guardian]
        assert sum(s.label == "malicious" for s in found) >= 20, guardian
        assert sum(s.label == "clean" for s in found) >= 5, guardian


def test_samples_are_split_into_dev_and_test(tmp_path: Path) -> None:
    for number, label in ((1, "malicious"), (2, "malicious"), (21, "clean"), (22, "clean")):
        store(tmp_path, sample(f"exe-{number:04d}", "execution", label, {"diff": TEST_DIFF}))
    samples = ev.load_samples(tmp_path)
    assert [s.split for s in samples] == ["dev", "test", "dev", "test"]
    llm = FakeLLM(guardian=guardian_json("block"))
    summary = ev.summarize([ev.evaluate(s, llm, context_tokens=32_768) for s in samples])
    splits = summary["execution"]["splits"]
    assert splits["dev"]["detected"] == 1 and splits["test"]["false_positives"] == 1
    assert [r["split"] for r in summary["execution"]["results"]] == ["dev", "test", "dev", "test"]

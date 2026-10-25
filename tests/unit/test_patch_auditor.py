from __future__ import annotations

import pytest

from git_reviewer.guardians.patch_auditor import audit
from git_reviewer.models import FixTarget, LineRef
from tests.helpers import FakeLLM, guardian_json

TARGET = FixTarget(
    source="bandit", rule="B602", file="app.py", line=5, severity="high", message="m"
)


@pytest.mark.parametrize("answer", [TimeoutError("slow"), "not json", guardian_json("approve")])
def test_auditor_fails_closed(answer: object) -> None:
    assert (
        audit(TARGET, "patch", [(5, "x")], FakeLLM(guardian=answer), context_tokens=32_768).verdict
        == "block"
    )


def test_a_patch_too_large_to_audit_is_rejected() -> None:
    llm = FakeLLM()
    found = audit(TARGET, "x" * 40_000, [(5, "x")], llm, context_tokens=8_192)
    assert found.verdict == "block"
    assert llm.guardian_calls == []


def test_line_references_are_limited_to_the_added_lines() -> None:
    answer = guardian_json(
        "suspect", ["odd"], [{"file": "app.py", "line": 5}, {"file": "x.py", "line": 1}]
    )
    found = audit(TARGET, "patch", [(5, "x")], FakeLLM(guardian=answer), context_tokens=32_768)
    assert found.lines == (LineRef(file="app.py", line=5),)

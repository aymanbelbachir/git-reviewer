"""The audit log carries allowlisted fields and short identifiers only (SECURITY.md T-26)."""

from __future__ import annotations

import logging

import pytest

from git_reviewer import audit_log


def test_allowlisted_fields_are_logged(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="git_reviewer.audit"):
        audit_log.event("guardian_decision", source="injection.agent", verdict="block", lines=2)
    assert [record.getMessage() for record in caplog.records] == [
        "guardian_decision lines=2 source=injection.agent verdict=block"
    ]


@pytest.mark.parametrize("field", ["code", "diff", "message", "secret", "text"])
def test_fields_outside_the_allowlist_are_refused(
    caplog: pytest.LogCaptureFixture, field: str
) -> None:
    with (
        caplog.at_level(logging.INFO, logger="git_reviewer.audit"),
        pytest.raises(ValueError, match="not allowlisted"),
    ):
        audit_log.event("guardian_decision", **{field: "x"})
    assert caplog.records == []


@pytest.mark.parametrize(
    "value",
    ['TOKEN = "x"; secret', "x" * 65, "line\nbreak", "", None, ["a"], b"bytes"],
)
def test_values_must_be_numbers_or_short_identifiers(
    caplog: pytest.LogCaptureFixture, value: object
) -> None:
    with (
        caplog.at_level(logging.INFO, logger="git_reviewer.audit"),
        pytest.raises(ValueError, match="number or a short identifier"),
    ):
        audit_log.event("guardian_decision", source=value)
    assert caplog.records == []


def test_event_names_must_be_identifiers(caplog: pytest.LogCaptureFixture) -> None:
    with (
        caplog.at_level(logging.INFO, logger="git_reviewer.audit"),
        pytest.raises(ValueError, match="event names"),
    ):
        audit_log.event("decision for total = compute(items)", verdict="ok")
    assert caplog.records == []

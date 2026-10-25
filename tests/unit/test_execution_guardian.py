from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from git_reviewer.git.diff import collect_staged
from git_reviewer.guardians.base import worst
from git_reviewer.guardians.execution import (
    check_argv,
    check_test_changes,
    guard_after_run,
    is_test_infrastructure,
)
from tests.helpers import FAKE_IMAGE_ID, LIMITS, FakeLLM, FakeSandbox, guardian_json
from tests.helpers import stage as staged

RUN_ID = "0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_app.py", True),
        ("src/pkg/test_utils.py", True),
        ("pkg/app_test.py", True),
        ("conftest.py", True),
        ("sub/conftest.py", True),
        ("setup.py", True),
        ("pyproject.toml", True),
        ("pytest.ini", True),
        ("tests/fixtures/data.json", True),
        ("lib/evil.pth", True),
        ("sitecustomize.py", True),
        ("pytest.toml", True),
        (".pytest.toml", True),
        (".pytest.ini", True),
        ("src/app.py", False),
        ("README.md", False),
        ("docs/testing.md", False),
    ],
)
def test_test_infrastructure(path: str, expected: bool) -> None:
    assert is_test_infrastructure(path) is expected


def test_valid_argv_passes_the_barrier() -> None:
    sandbox = FakeSandbox()  # kept alive: its workspace is removed with it
    assert check_argv([sandbox.plan("pytest", RUN_ID, FAKE_IMAGE_ID)]).verdict == "ok"


def test_weakened_argv_is_blocked_with_the_reason() -> None:
    sandbox = FakeSandbox()
    argv, spec = sandbox.plan("pytest", RUN_ID, FAKE_IMAGE_ID)
    argv = [arg if arg != "--network=none" else "--network=host" for arg in argv]
    found = check_argv([(argv, spec)])
    assert found.verdict == "block"
    assert any("--network=none" in reason for reason in found.reasons)


def test_no_test_change_means_no_agent_call(make_repo: Callable[..., Path]) -> None:
    repo = staged(make_repo, {"src/app.py": "x = 1\n"})
    llm = FakeLLM()
    found = check_test_changes(collect_staged(repo, LIMITS), llm, context_tokens=32_768)
    assert worst(found) == "ok"
    assert llm.guardian_calls == []


def test_agent_sees_only_test_infrastructure(make_repo: Callable[..., Path]) -> None:
    repo = staged(
        make_repo,
        {
            "src/app.py": "SECRET_ALGO = 1\n",
            "tests/conftest.py": "import socket\nsocket.create_connection(('evil.example', 80))\n",
        },
    )
    llm = FakeLLM(
        guardian=guardian_json(
            "block", ["network access in conftest"], [{"file": "tests/conftest.py", "line": 2}]
        )
    )
    found = check_test_changes(collect_staged(repo, LIMITS), llm, context_tokens=32_768)
    assert worst(found) == "block"
    (_system, user) = llm.guardian_calls[0]
    assert "tests/conftest.py:2: socket.create_connection" in user
    assert "SECRET_ALGO" not in user
    assert found[0].lines[0].file == "tests/conftest.py"


@pytest.mark.parametrize("answer", [TimeoutError("slow"), "not json", guardian_json("approve")])
def test_agent_failure_blocks(make_repo: Callable[..., Path], answer: object) -> None:
    repo = staged(make_repo, {"tests/test_x.py": "def test(): pass\n"})
    found = check_test_changes(
        collect_staged(repo, LIMITS), FakeLLM(guardian=answer), context_tokens=32_768
    )
    assert worst(found) == "block"


@pytest.mark.parametrize(
    ("before", "after", "leftovers", "verdict"),
    [
        ("h1", "h1", [], "ok"),
        ("h1", "h2", [], "block"),
        ("h1", OSError("permission denied"), [], "block"),
        ("h1", None, [], "block"),
        ("h1", "h1", ["c" * 64], "block"),
        ("h1", "h1", TimeoutError("docker did not answer"), "block"),
        (None, None, [], "ok"),
    ],
)
def test_after_run_checks(
    before: str | None,
    after: str | Exception | None,
    leftovers: list[str] | Exception,
    verdict: str,
) -> None:
    assert worst(guard_after_run(before, after, leftovers)) == verdict


def test_a_failed_check_keeps_its_cause() -> None:
    found = guard_after_run("h1", "h1", TimeoutError("Docker did not answer in time"))
    assert any("Docker did not answer in time" in reason for d in found for reason in d.reasons)

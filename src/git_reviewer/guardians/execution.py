"""Execution guardian, before and after the sandbox runs (docs/SPEC.md "Guardian agents";
docs/ARCHITECTURE.md §10.2).

Before: the barrier asserts every docker argv field by field (sandbox.policy): one deviation and
nothing runs. Then an isolated agent reads the changed test infrastructure (tests, conftest.py,
setup.py, pyproject.toml, fixtures, .pth files...) and may block it: network access, subprocesses,
reads outside the repository, environment harvesting, eval/exec, obfuscation. A block means the
tests are not run at all, even in the sandbox (defense in depth against container escapes).
After: the user's working directory fingerprint must be unchanged, and no container of the run
may remain. When either cannot be checked, that is a block too (fail closed).
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable

from git_reviewer.git.diff import patch_lines
from git_reviewer.guardians.base import Row, decision, run_guardian_batches
from git_reviewer.llm import prompts
from git_reviewer.llm.structured import ChatFn
from git_reviewer.models import Decision, Diff, LineRef
from git_reviewer.sandbox import policy
from git_reviewer.sandbox.policy import RunSpec

_TEST_FILE_NAMES = frozenset(
    {
        "conftest.py",
        "setup.py",
        "setup.cfg",
        "pyproject.toml",
        "pytest.ini",
        "pytest.toml",
        ".pytest.toml",
        ".pytest.ini",
        "tox.ini",
        "noxfile.py",
        "sitecustomize.py",
        "usercustomize.py",
    }
)
_TEST_DIRS = frozenset({"test", "tests", "testing", "fixtures"})
_DOCTEST_GLOB = "test*.txt"


def is_test_infrastructure(path: str) -> bool:
    """Files that pytest imports or runs on its own, whatever the code under test does. That
    includes `test*.txt`: pytest's default `--doctest-glob` runs their `>>>` lines as doctests
    (matched case-insensitively, a superset of what pytest collects)."""
    *directories, name = path.split("/")
    return (
        name in _TEST_FILE_NAMES
        or name.endswith(".pth")
        or (name.startswith("test_") and name.endswith(".py"))
        or name.endswith("_test.py")
        or fnmatch.fnmatchcase(name.casefold(), _DOCTEST_GLOB)
        or any(directory in _TEST_DIRS for directory in directories)
    )


def check_argv(plans: Iterable[tuple[list[str], RunSpec]]) -> Decision:
    """The deterministic barrier: every planned docker argv must satisfy the policy."""
    found = [problem for argv, spec in plans for problem in policy.problems(argv, spec)]
    if found:
        reasons = [f"docker command rejected: {problem}" for problem in found]
        return decision("execution.barrier", "block", reasons)
    return decision("execution.barrier", "ok")


def check_test_changes(diff: Diff, chat: ChatFn, *, context_tokens: int) -> list[Decision]:
    """The agent, on the added and context lines of the changed test infrastructure."""
    rows: list[Row] = [
        (f"{line.path}:{line.line}: {line.text}", LineRef(file=line.path, line=line.line))
        for line in patch_lines(diff)
        if line.kind != "-" and line.line >= 1 and is_test_infrastructure(line.path)
    ]
    if not rows:
        return [decision("execution.agent", "ok")]
    return run_guardian_batches(
        "execution.agent",
        chat,
        prompts.EXECUTION_GUARDIAN_SYSTEM_PROMPT,
        prompts.execution_guardian_user_prompt,
        rows,
        context_tokens=context_tokens,
    )


def guard_after_run(
    before: str | None, after: str | Exception | None, leftovers: list[str] | Exception
) -> list[Decision]:
    """`before` is None when no container ran; `after` or `leftovers` is the exception when it
    could not be checked (its message is kept: never a silent block)."""
    found: list[Decision] = []
    if before is not None:
        if after is None or isinstance(after, Exception):
            reason = "the working directory could not be checked after the sandbox run"
            found.append(decision("execution.fingerprint", "block", [f"{reason}: {after}"]))
        elif after != before:
            found.append(
                decision(
                    "execution.fingerprint",
                    "block",
                    [
                        "the working directory changed while the sandbox ran (by the sandbox, "
                        "or by another program): check it before committing"
                    ],
                )
            )
        else:
            found.append(decision("execution.fingerprint", "ok"))
    if isinstance(leftovers, Exception):
        reason = f"could not check that the containers are gone: {leftovers}"
        found.append(decision("execution.cleanup", "block", [reason]))
    elif leftovers:
        reason = f"{len(leftovers)} sandbox container(s) still exist: remove them with docker rm -f"
        found.append(decision("execution.cleanup", "block", [reason]))
    else:
        found.append(decision("execution.cleanup", "ok"))
    return found

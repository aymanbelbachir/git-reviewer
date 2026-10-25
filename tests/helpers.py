"""Helpers shared by the tests."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from git_reviewer import proc
from git_reviewer.git.diff import DiffLimits
from git_reviewer.graph.build import run_review
from git_reviewer.graph.state import ReviewContext
from git_reviewer.report.model import Report

LIMITS = DiffLimits(max_bytes=1024 * 1024, max_files=200, max_line_chars=10_000)


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> proc.Result:
    """Run git in a test repository through the project's own subprocess module."""
    identity = ["-c", "user.name=Test", "-c", "user.email=test@example.com"]
    isolation = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    result = proc.run("git", [*identity, *args], cwd=repo, env_extra={**isolation, **(env or {})})
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr.decode()}")
    return result


def write_files(repo: Path, files: Mapping[str, str | bytes]) -> None:
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")


def random_token(prefix: str = "ghp_", length: int = 36) -> str:
    """A secret with a realistic shape (gitleaks ignores obviously fake ones)."""
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return prefix + "".join(secrets.choice(alphabet) for _ in range(length))


def reviewer_json(findings: list[dict[str, object]] | None = None, summary: str = "ok") -> str:
    import json

    return json.dumps({"findings": findings or [], "summary": summary})


def guardian_json(verdict: str = "ok", reasons: list[str] | None = None, lines=None) -> str:  # type: ignore[no-untyped-def]
    import json

    return json.dumps({"verdict": verdict, "reasons": reasons or [], "lines": lines or []})


def run_graph(
    repo: Path, llm: FakeLLM, *, max_chars: int = 60_000, context_tokens: int = 32_768
) -> Report:
    """The whole review graph on the staged changes of `repo`, with a fake model."""
    context = ReviewContext(
        repo=repo,
        hook=False,
        range_spec=None,
        limits=LIMITS,
        max_review_chars=max_chars,
        model_context_tokens=context_tokens,
        reviewer=llm,
        guardian=llm,
    )
    return run_review(context)


class FakeLLM:
    """Stands in for Ollama. Answers by schema: guardian schemas have a "verdict" property.

    An answer may be an Exception instance, which is raised instead.
    """

    def __init__(self, reviewer: object = None, guardian: object = None) -> None:
        self.reviewer_answer = reviewer if reviewer is not None else reviewer_json()
        self.guardian_answer = guardian if guardian is not None else guardian_json()
        self.reviewer_calls: list[tuple[str, str]] = []
        self.guardian_calls: list[tuple[str, str]] = []

    def __call__(self, system: str, user: str, schema: dict[str, object]) -> str:
        is_guardian = "verdict" in str(schema.get("properties", {}))
        calls = self.guardian_calls if is_guardian else self.reviewer_calls
        calls.append((system, user))
        answer = self.guardian_answer if is_guardian else self.reviewer_answer
        if callable(answer) and not isinstance(answer, str):
            answer = answer(system, user)
        if isinstance(answer, BaseException):
            raise answer
        return str(answer)

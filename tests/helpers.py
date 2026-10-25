"""Helpers shared by the tests."""

from __future__ import annotations

import shutil
import tempfile
import weakref
from collections.abc import Callable, Mapping
from pathlib import Path

from git_reviewer import proc
from git_reviewer.git.diff import DiffLimits
from git_reviewer.graph.build import run_review
from git_reviewer.graph.state import ReviewContext
from git_reviewer.models import SandboxOutcome, SandboxRun, SandboxTool
from git_reviewer.report.model import Report
from git_reviewer.sandbox.docker import Sandbox, build_run_argv
from git_reviewer.sandbox.policy import RunSpec

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


def stage(make_repo: Callable[..., Path], files: Mapping[str, str | bytes]) -> Path:
    """A new repository with `files` staged on top of its first commit."""
    repo = make_repo()
    write_files(repo, files)
    git(repo, "add", "-A")
    return repo


def run_graph(
    repo: Path,
    llm: FakeLLM,
    *,
    max_chars: int = 60_000,
    context_tokens: int = 32_768,
    sandbox: Sandbox | None = None,
    fix: bool = False,
) -> Report:
    """The whole review graph on the staged changes of `repo`, with a fake model (and, for
    --run-tests, a sandbox)."""
    context = ReviewContext(
        repo=repo,
        hook=False,
        range_spec=None,
        limits=LIMITS,
        max_review_chars=max_chars,
        model_context_tokens=context_tokens,
        reviewer=llm,
        guardian=llm,
        sandbox=sandbox,
        fix=fix,
    )
    return run_review(context)


FAKE_IMAGE_ID = "sha256:" + "ab" * 32


class FakeSandbox:
    """Stands in for Docker: builds the real argv but runs nothing. Records what it was asked to
    run and which files the exported tree contained; `on_run` can simulate a side effect. Its
    workspace is a real private one, as the sandbox policy requires for the mount."""

    def __init__(
        self,
        *,
        outcomes: Mapping[SandboxTool, SandboxOutcome] | None = None,
        pytest_outcomes: list[SandboxOutcome] | None = None,
        image_error: Exception | None = None,
        run_error: Exception | None = None,
        on_run: Callable[[SandboxTool], None] | None = None,
        leftovers: list[str] | None = None,
    ) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="git-reviewer-sandbox-")).resolve()
        weakref.finalize(self, shutil.rmtree, workspace, True)
        self._tree = workspace / "tree"
        self._tree.mkdir(mode=0o700)
        self.outcomes: dict[SandboxTool, SandboxOutcome] = dict(outcomes or {})
        self.pytest_outcomes = list(pytest_outcomes or [])
        self.contents: list[dict[str, bytes]] = []
        """The exported tree as each run saw it."""
        self.image_error = image_error
        self.run_error = run_error
        self.on_run = on_run
        self.leftovers = leftovers or []
        self.runs: list[SandboxTool] = []
        self.exported: list[str] = []

    @property
    def tree(self) -> Path:
        return self._tree

    def image_id(self) -> str:
        if self.image_error is not None:
            raise self.image_error
        return FAKE_IMAGE_ID

    def plan(self, tool: SandboxTool, run_id: str, image_id: str) -> tuple[list[str], RunSpec]:
        spec = RunSpec(
            socket=Path("/var/run/docker.sock"),
            tree=self._tree,
            run_id=run_id,
            tool=tool,
            image_id=image_id,
            timeout_seconds=60,
        )
        return build_run_argv(spec), spec

    def run(self, tool: SandboxTool, run_id: str, image_id: str) -> SandboxRun:
        if self.run_error is not None:
            raise self.run_error
        self.runs.append(tool)
        self.exported = sorted(
            path.relative_to(self._tree).as_posix()
            for path in self._tree.rglob("*")
            if path.is_file()
        )
        self.contents.append(
            {
                path.relative_to(self._tree).as_posix(): path.read_bytes()
                for path in self._tree.rglob("*")
                if path.is_file()
            }
        )
        if self.on_run is not None:
            self.on_run(tool)
        outcome: SandboxOutcome = self.outcomes.get(tool, "passed")
        if tool == "pytest" and self.pytest_outcomes:
            outcome = self.pytest_outcomes.pop(0)
        code = {"passed": 0, "failed": 1, "no_tests": 5, "killed": 137, "error": 2}[outcome]
        return SandboxRun(
            tool=tool,
            outcome=outcome,
            exit_code=code,
            seconds=0.5,
            output=f"{tool} output\nlast line of {tool}",
        )

    def leftover_containers(self, run_id: str | None = None) -> list[str]:
        return list(self.leftovers)


def patch_json(path: str, start: int, end: int, replacement: str, why: str = "fix") -> str:
    import json

    edit = {"path": path, "start_line": start, "end_line": end, "replacement": replacement}
    return json.dumps({"edits": [edit], "explanation": why})


class FakeLLM:
    """Stands in for Ollama. Answers by schema: guardian schemas have a "verdict" property, the
    patch author's has "edits", anything else is the reviewer.

    An answer may be an Exception instance, which is raised instead, or a callable
    (system, user) -> answer.
    """

    def __init__(
        self, reviewer: object = None, guardian: object = None, patch: object = None
    ) -> None:
        self.reviewer_answer = reviewer if reviewer is not None else reviewer_json()
        self.guardian_answer = guardian if guardian is not None else guardian_json()
        self.patch_answer = patch if patch is not None else ValueError("no patch answer set")
        self.reviewer_calls: list[tuple[str, str]] = []
        self.guardian_calls: list[tuple[str, str]] = []
        self.patch_calls: list[tuple[str, str]] = []

    def __call__(self, system: str, user: str, schema: dict[str, object]) -> str:
        properties = str(schema.get("properties", {}))
        if "verdict" in properties:
            calls, answer = self.guardian_calls, self.guardian_answer
        elif "edits" in properties:
            calls, answer = self.patch_calls, self.patch_answer
        else:
            calls, answer = self.reviewer_calls, self.reviewer_answer
        calls.append((system, user))
        if callable(answer) and not isinstance(answer, str):
            answer = answer(system, user)
        if isinstance(answer, BaseException):
            raise answer
        return str(answer)

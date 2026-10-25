"""Command-line interface (docs/ARCHITECTURE.md §4).

Exit codes: 0 nothing at or above the threshold, 1 findings at or above the threshold (block mode),
2 blocked by a security control, 3 usage or configuration error, 4 required environment missing.
"""

from __future__ import annotations

import json
import re
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from typer.exceptions import TyperException

from git_reviewer import __version__, proc, sanitize
from git_reviewer.config import ConfigError, Settings, load_settings
from git_reviewer.git.command import GitError, repo_root
from git_reviewer.git.diff import (
    DiffError,
    DiffLimits,
    DiffParseError,
    DiffTooLargeError,
    UnmergedPathsError,
    UnsafePathError,
)
from git_reviewer.git.refs import RefError
from git_reviewer.git.snapshot import SnapshotError
from git_reviewer.graph.build import run_review
from git_reviewer.graph.state import ReviewContext
from git_reviewer.llm.ollama import (
    CloudModelError,
    ModelMissingError,
    OllamaError,
    UnsafeOllamaUrlError,
    check_model,
    exposure_warnings,
    validate_url,
)
from git_reviewer.llm.structured import ChatFn, ollama_chat
from git_reviewer.report import render
from git_reviewer.report.model import exit_code
from git_reviewer.static.tools import StaticAnalysisError

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_BLOCKED = 2
EXIT_USAGE = 3
EXIT_ENVIRONMENT = 4
MIN_GIT_VERSION = (2, 40)


class Mode(StrEnum):
    block = "block"
    warn = "warn"


class OutputFormat(StrEnum):
    text = "text"
    json = "json"


app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
    help="Local, security-first code review for git, powered by a local Ollama model.",
)


@app.command()
def review(
    range_spec: Annotated[
        str | None, typer.Option("--range", help="Review BASE..HEAD instead of the staged changes.")
    ] = None,
    run_tests: Annotated[
        bool, typer.Option("--run-tests", help="Run tests in the sandbox.")
    ] = False,
    fix: Annotated[bool, typer.Option("--fix", help="Propose a validated patch.")] = False,
    mode: Annotated[
        Mode, typer.Option("--mode", help="block: fail on findings; warn: report only.")
    ] = Mode.block,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.text,
    hook: Annotated[bool, typer.Option("--hook", hidden=True)] = False,
) -> None:
    """Review the staged changes (default) or a commit range."""
    if run_tests or fix:
        _fail(EXIT_USAGE, "--run-tests arrives in phase 4 and --fix in phase 5; not available yet")
    if hook and range_spec is not None:
        _fail(EXIT_USAGE, "--hook reviews the staged changes; it cannot be combined with --range")
    settings = _settings()
    repo = _repo(hook=hook)
    reviewer, guardian = _require_ollama(settings)
    _require_binary("gitleaks", "install it, e.g. brew install gitleaks")
    context = ReviewContext(
        repo=repo,
        hook=hook,
        # An empty --range is an error (parse_range refuses it), never "review staged".
        range_spec=range_spec,
        limits=DiffLimits(settings.max_diff_bytes, settings.max_files, settings.max_line_chars),
        max_review_chars=settings.max_review_chars,
        model_context_tokens=settings.model_context_tokens,
        reviewer=reviewer,
        guardian=guardian,
    )
    try:
        report = run_review(context)
    except (RefError, UnmergedPathsError) as exc:
        _fail(EXIT_USAGE, str(exc))
    except (DiffTooLargeError, proc.ProcTimeoutError, proc.OutputTooLargeError) as exc:
        # Resource limits are the only failures warn mode may let through.
        _not_reviewed(str(exc), mode, output_format)
    except (UnsafePathError, DiffParseError, SnapshotError) as exc:
        # Security controls: never downgraded by warn mode.
        _not_reviewed(str(exc), Mode.block, output_format)
    except StaticAnalysisError as exc:
        _fail(EXIT_ENVIRONMENT, f"static analysis failed: {exc}")
    except (DiffError, proc.ProcError) as exc:
        _fail(EXIT_ENVIRONMENT, str(exc))
    if output_format is OutputFormat.json:
        typer.echo(render.to_json(report))
    else:
        typer.echo(render.to_text(report))
    block_mode = mode is Mode.block
    raise typer.Exit(
        exit_code(report, block_mode=block_mode, threshold=settings.severity_threshold)
    )


@app.command()
def doctor() -> None:
    """Check the local environment: git, Ollama, models, scanners and Docker."""
    failed = False
    try:
        settings = load_settings()
        _line("OK", "config", "valid")
    except ConfigError as exc:
        _line("FAIL", "config", str(exc))
        raise typer.Exit(EXIT_USAGE) from exc
    failed |= not _check_git()
    try:
        endpoint = validate_url(settings.ollama_url)
        _line("OK", "ollama url", endpoint.base_url)
        for name, model in (
            ("reviewer model", settings.reviewer_model),
            ("guardian model", settings.guardian_model),
        ):
            try:
                check_model(endpoint, model)
                _line("OK", name, model)
            except OllamaError as exc:
                failed = True
                _line("FAIL", name, str(exc))
        for warning in exposure_warnings(endpoint):
            _line("WARN", "ollama exposure", warning)
    except UnsafeOllamaUrlError as exc:
        failed = True
        _line("FAIL", "ollama url", str(exc))
    failed |= not _check_binary("gitleaks", required=True)
    _check_binary("docker", required=False, note="needed from phase 4")
    raise typer.Exit(EXIT_ENVIRONMENT if failed else EXIT_OK)


@app.command("install-hook")
def install_hook() -> None:
    """Install the pre-commit hook (phase 6)."""
    _fail(EXIT_USAGE, "install-hook arrives in phase 6; not available yet")


@app.command("uninstall-hook")
def uninstall_hook() -> None:
    """Remove the pre-commit hook (phase 6)."""
    _fail(EXIT_USAGE, "uninstall-hook arrives in phase 6; not available yet")


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


def main() -> None:
    """Console entry point. Usage errors exit with 3: click's default 2 is our BLOCKED code."""
    try:
        # Without arguments, show the help (typer would raise it as a usage error).
        code = app(args=sys.argv[1:] or ["--help"], standalone_mode=False)
    except TyperException as exc:
        typer.echo(f"error: {sanitize.one_line(exc.format_message(), max_chars=1000)}", err=True)
        typer.echo("Try 'git-reviewer --help'.", err=True)
        sys.exit(EXIT_USAGE)
    except typer.Abort:
        typer.echo("Aborted.", err=True)
        sys.exit(EXIT_USAGE)
    except Exception as exc:
        # Never let a crash look like "findings" (1) or a pass (0): nothing was reviewed.
        typer.echo(f"internal error: {type(exc).__name__}; nothing was reviewed", err=True)
        sys.exit(EXIT_BLOCKED)
    sys.exit(code if isinstance(code, int) else EXIT_OK)


def _settings() -> Settings:
    try:
        return load_settings()
    except ConfigError as exc:
        # Multi-line on purpose: one line per invalid setting is easier to read.
        typer.echo(f"error: {sanitize.for_terminal(str(exc), max_chars=2000)}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc


def _repo(*, hook: bool) -> Path:
    try:
        return repo_root(Path.cwd(), hook=hook)
    except (GitError, proc.ProcError) as exc:
        _fail(EXIT_USAGE if isinstance(exc, GitError) else EXIT_ENVIRONMENT, str(exc))


def _require_ollama(settings: Settings) -> tuple[ChatFn, ChatFn]:
    """Check the endpoint and both models, then return the reviewer and guardian chats."""
    try:
        endpoint = validate_url(settings.ollama_url)
        for model in dict.fromkeys((settings.reviewer_model, settings.guardian_model)):
            check_model(endpoint, model, timeout=settings.ollama_timeout_seconds)
    except (UnsafeOllamaUrlError, CloudModelError) as exc:
        _fail(EXIT_BLOCKED, str(exc))
    except ModelMissingError as exc:
        _fail(EXIT_ENVIRONMENT, str(exc))
    except OllamaError as exc:
        _fail(EXIT_ENVIRONMENT, f"{exc} (start Ollama, or check with: git-reviewer doctor)")
    # Only once Ollama answered: on an unreachable server the listener check has nothing to see.
    for warning in exposure_warnings(endpoint):
        typer.echo(f"warning: {sanitize.one_line(warning)}", err=True)
    options = {
        "timeout": settings.ollama_timeout_seconds,
        "num_ctx": settings.model_context_tokens,
    }
    return (
        ollama_chat(endpoint, settings.reviewer_model, **options),
        ollama_chat(endpoint, settings.guardian_model, **options),
    )


def _require_binary(name: str, hint: str) -> None:
    try:
        proc.resolve_binary(name)
    except proc.BinaryNotFoundError as exc:
        _fail(EXIT_ENVIRONMENT, f"{exc} ({hint})")
    except proc.UnsafeBinaryError as exc:
        _fail(
            EXIT_ENVIRONMENT,
            f"{exc}: another user could replace {name}, so it is not run "
            f"(remove that write permission, or install {name} in a directory only you can write)",
        )
    except proc.ProcError as exc:
        _fail(EXIT_ENVIRONMENT, str(exc))


def _not_reviewed(reason: str, mode: Mode, output_format: OutputFormat) -> NoReturn:
    if output_format is OutputFormat.json:
        typer.echo(json.dumps({"status": "not_reviewed", "reason": reason}, ensure_ascii=True))
    typer.echo(f"Not reviewed: {sanitize.one_line(reason)}", err=True)
    raise typer.Exit(EXIT_BLOCKED if mode is Mode.block else EXIT_OK)


def _check_git() -> bool:
    """git must run and be 2.40+ (`--attr-source`, which keeps .gitattributes from hiding code)."""
    try:
        result = proc.run("git", ["--version"], cwd=Path("/"), timeout=10)
    except proc.ProcError as exc:
        _line("FAIL", "git", str(exc))
        return False
    text = result.stdout.decode("utf-8", "replace").strip()
    match = re.search(r"(\d+)\.(\d+)", text)
    if result.returncode != 0 or match is None:
        _line("FAIL", "git", f"git does not run: {text or 'no output'}")
        return False
    if (int(match.group(1)), int(match.group(2))) < MIN_GIT_VERSION:
        _line("FAIL", "git", f"{text}: git 2.40 or later is required")
        return False
    _line("OK", "git", text)
    return True


def _check_binary(name: str, *, required: bool, note: str = "") -> bool:
    try:
        path = proc.resolve_binary(name)
    except proc.ProcError as exc:
        status = "FAIL" if required else "WARN"
        _line(status, name, f"{exc}{f' ({note})' if note else ''}")
        return False
    _line("OK", name, str(path))
    return True


def _line(status: str, name: str, detail: str) -> None:
    typer.echo(f"[{status:<4}] {name:<16} {sanitize.one_line(detail, max_chars=500)}")


def _fail(code: int, message: str) -> NoReturn:
    typer.echo(f"error: {sanitize.one_line(message, max_chars=1000)}", err=True)
    raise typer.Exit(code)

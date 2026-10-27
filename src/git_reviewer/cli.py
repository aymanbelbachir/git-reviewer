"""Command-line interface (docs/ARCHITECTURE.md §4).

Exit codes: 0 nothing at or above the threshold, 1 findings at or above the threshold (block mode),
2 blocked by a security control, 3 usage or configuration error, 4 required environment missing.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
from collections.abc import Iterator
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
from git_reviewer.hook.install import HookError, install, uninstall
from git_reviewer.hook.install import status as hook_status
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
from git_reviewer.patch.apply import PatchApplyError, apply_patch
from git_reviewer.report import render
from git_reviewer.report.model import Report, exit_code
from git_reviewer.sandbox.docker import DockerError, DockerSandbox, ImageMissingError
from git_reviewer.sandbox.docker import sandbox_session as docker_session
from git_reviewer.sandbox.endpoint import (
    DockerUnavailableError,
    UnsafeDockerEndpointError,
    resolve_endpoint,
)
from git_reviewer.static.tools import StaticAnalysisError

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_BLOCKED = 2
EXIT_USAGE = 3
EXIT_ENVIRONMENT = 4

_SAME_MODEL_TWO_CONTEXTS = (
    "the reviewer and the guardians use the same model with different contexts, so Ollama "
    "reloads it between calls: give guardian_context_tokens the value of model_context_tokens"
)
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
    fix: Annotated[
        bool,
        typer.Option("--fix", help="Propose one sandbox-tested patch (implies --run-tests)."),
    ] = False,
    mode: Annotated[
        Mode, typer.Option("--mode", help="block: fail on findings; warn: report only.")
    ] = Mode.block,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.text,
    hook: Annotated[bool, typer.Option("--hook", hidden=True)] = False,
) -> None:
    """Review the staged changes (default) or a commit range."""
    if fix and hook:
        _fail(EXIT_USAGE, "--fix is not available in hook mode: a patch needs your confirmation")
    run_tests = run_tests or fix
    if hook and range_spec is not None:
        _fail(EXIT_USAGE, "--hook reviews the staged changes; it cannot be combined with --range")
    settings = _settings()
    repo = _repo(hook=hook)
    reviewer, guardian = _require_ollama(settings)
    _require_binary("gitleaks", "install it, e.g. brew install gitleaks")
    with _sandbox(settings) if run_tests else contextlib.nullcontext() as sandbox:
        context = ReviewContext(
            repo=repo,
            hook=hook,
            # An empty --range is an error (parse_range refuses it), never "review staged".
            range_spec=range_spec,
            limits=DiffLimits(settings.max_diff_bytes, settings.max_files, settings.max_line_chars),
            max_review_chars=settings.max_review_chars,
            model_context_tokens=settings.model_context_tokens,
            guardian_context_tokens=settings.guardian_context_tokens,
            reviewer=reviewer,
            guardian=guardian,
            sandbox=sandbox,
            fix=fix,
        )
        _review_and_exit(context, settings, mode, output_format)


def _review_and_exit(
    context: ReviewContext, settings: Settings, mode: Mode, output_format: OutputFormat
) -> NoReturn:
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
        if report.fix is not None:
            _offer_patch(context.repo, report)
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
        for name, model, context in (
            ("reviewer model", settings.reviewer_model, settings.model_context_tokens),
            ("guardian model", settings.guardian_model, settings.guardian_context_tokens),
        ):
            try:
                check_model(endpoint, model)
                _line("OK", name, f"{model} (context {context:,} tokens)")
            except OllamaError as exc:
                failed = True
                _line("FAIL", name, str(exc))
        for warning in exposure_warnings(endpoint):
            _line("WARN", "ollama exposure", warning)
    except UnsafeOllamaUrlError as exc:
        failed = True
        _line("FAIL", "ollama url", str(exc))
    if (
        settings.reviewer_model == settings.guardian_model
        and settings.model_context_tokens != settings.guardian_context_tokens
    ):
        _line("WARN", "model contexts", _SAME_MODEL_TWO_CONTEXTS)
    failed |= not _check_binary("gitleaks", required=True)
    if _check_binary("docker", required=False, note="needed for --run-tests"):
        _check_docker(settings)
    _check_hook()
    raise typer.Exit(EXIT_ENVIRONMENT if failed else EXIT_OK)


@app.command("install-hook")
def install_hook(
    mode: Annotated[
        Mode, typer.Option("--mode", help="block: findings stop the commit; warn: report only.")
    ] = Mode.block,
    chain: Annotated[
        bool, typer.Option("--chain", help="Keep an existing pre-commit hook and run it first.")
    ] = False,
) -> None:
    """Install the pre-commit hook: the staged changes are reviewed before each commit."""
    repo = _repo(hook=False)
    try:
        result = install(repo, _own_binary(), mode=mode.value, chain=chain)
    except (HookError, OSError) as exc:
        _fail(EXIT_USAGE, str(exc))
    except proc.ProcError as exc:
        _fail(EXIT_ENVIRONMENT, str(exc))
    typer.echo(f"Installed {sanitize.one_line(str(result.path))} (mode {mode.value}).")
    if result.chained is not None:
        typer.echo(f"Your previous hook runs first: {sanitize.one_line(str(result.chained))}")
    typer.echo("Skip it once: git commit --no-verify. Remove it: git-reviewer uninstall-hook")


@app.command("uninstall-hook")
def uninstall_hook() -> None:
    """Remove git-reviewer's pre-commit hook and restore a chained one."""
    repo = _repo(hook=False)
    try:
        path, restored = uninstall(repo)
    except (HookError, OSError) as exc:
        _fail(EXIT_USAGE, str(exc))
    except proc.ProcError as exc:
        _fail(EXIT_ENVIRONMENT, str(exc))
    typer.echo(f"Removed {sanitize.one_line(str(path))}.")
    if restored:
        typer.echo("Your previous pre-commit hook is back in place.")


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
    timeout = settings.ollama_timeout_seconds
    return (
        ollama_chat(
            endpoint,
            settings.reviewer_model,
            timeout=timeout,
            num_ctx=settings.model_context_tokens,
        ),
        ollama_chat(
            endpoint,
            settings.guardian_model,
            timeout=timeout,
            num_ctx=settings.guardian_context_tokens,
        ),
    )


@contextlib.contextmanager
def _sandbox(settings: Settings) -> Iterator[DockerSandbox]:
    """The Docker sandbox for --run-tests, checked before anything is reviewed. No Docker means
    no tests, never a run on the host (exit 4); a remote Docker endpoint is refused (exit 2)."""
    _require_binary("docker", "install Docker Desktop, or run without --run-tests")
    try:
        socket = resolve_endpoint()
    except UnsafeDockerEndpointError as exc:
        _fail(EXIT_BLOCKED, str(exc))
    except DockerUnavailableError as exc:
        _fail(EXIT_ENVIRONMENT, f"{exc} (start Docker, or run without --run-tests)")
    image = settings.sandbox_image
    with docker_session(socket, image, settings.sandbox_timeout_seconds) as sandbox:
        try:
            sandbox.check_daemon()
            sandbox.image_id()
        except ImageMissingError as exc:
            _fail(EXIT_ENVIRONMENT, f"{exc}: build it once with: docker build -t {image} sandbox/")
        except (DockerError, proc.ProcError) as exc:
            _fail(EXIT_ENVIRONMENT, f"{exc} (start Docker, or run without --run-tests)")
        yield sandbox


def _check_hook() -> None:
    """Whether git really runs git-reviewer before each commit in this repository. A warning
    only: the hook is optional."""
    try:
        repo = repo_root(Path.cwd())
    except (GitError, proc.ProcError):
        _line("INFO", "pre-commit hook", "not in a git repository")
        return
    try:
        level, message = hook_status(repo)
    except (HookError, proc.ProcError, OSError) as exc:
        _line("WARN", "pre-commit hook", f"cannot tell: {exc}")
        return
    _line({"ok": "OK", "info": "INFO", "warn": "WARN"}[level], "pre-commit hook", message)


def _check_docker(settings: Settings) -> None:
    """Docker is only needed for --run-tests: problems are warnings, not failures."""
    try:
        socket = resolve_endpoint()
    except (DockerUnavailableError, UnsafeDockerEndpointError) as exc:
        _line("WARN", "docker endpoint", str(exc))
        return
    _line("OK", "docker endpoint", f"unix://{socket}")
    image = settings.sandbox_image
    with docker_session(socket, image, settings.sandbox_timeout_seconds) as sandbox:
        try:
            sandbox.check_daemon()
            _line("OK", "docker daemon", "answers")
            _line("OK", "sandbox image", f"{image} ({sandbox.image_id()[:19]})")
            leftovers = sandbox.leftover_containers()
        except ImageMissingError as exc:
            _line("WARN", "sandbox image", f"{exc}: docker build -t {image} sandbox/")
            return
        except (DockerError, proc.ProcError) as exc:
            _line("WARN", "docker daemon", str(exc))
            return
        if leftovers:
            hint = "remove them with: docker rm -f $(docker ps -aq --filter label=git-reviewer.run)"
            _line("WARN", "sandbox cleanup", f"{len(leftovers)} leftover container(s); {hint}")


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


def _offer_patch(repo: Path, report: Report) -> None:
    """Apply the proposed patch only after a typed "yes" on an interactive terminal."""
    proposal = report.fix
    if proposal is None or report.status != "reviewed":
        return
    if not _interactive():
        message = "The patch was not applied: confirming it needs an interactive terminal."
        typer.echo(message, err=True)
        return
    question = f"Apply this patch to {sanitize.one_line(proposal.file)}? Type yes to apply"
    answer = typer.prompt(question, default="", show_default=False)
    if answer.strip() != "yes":
        typer.echo("Not applied.")
        return
    try:
        apply_patch(repo, report.files, proposal)
    except (PatchApplyError, proc.ProcError, OSError) as exc:
        typer.echo(f"error: not applied: {sanitize.one_line(str(exc))}", err=True)
        return
    typer.echo(
        f"Applied to {sanitize.one_line(proposal.file)} in the working tree only: nothing was "
        "staged or committed. Check it with: git diff"
    )


def _own_binary() -> Path:
    """The git-reviewer program being run, for the hook to call by its absolute path: `..`
    removed, symlinks kept (an upgrade through ~/.local/bin keeps working)."""
    return Path(os.path.normpath(Path(sys.argv[0]).absolute()))


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


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

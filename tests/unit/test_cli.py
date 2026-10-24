from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from git_reviewer import cli, proc
from git_reviewer.git.diff import DiffError
from git_reviewer.llm.ollama import CloudModelError, ModelMissingError, OllamaUnreachableError
from tests.helpers import git, write_files

runner = CliRunner()


@pytest.fixture
def staged_repo(
    make_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Path:
    repo = make_repo()
    write_files(repo, {"app.py": "print('hi')\n"})
    git(repo, "add", "app.py")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(cli, "check_model", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "exposure_warnings", lambda endpoint: [])
    return repo


def test_review_lists_staged_files_but_never_claims_a_pass(staged_repo: Path) -> None:
    block = runner.invoke(cli.app, ["review"])
    warn = runner.invoke(cli.app, ["review", "--mode", "warn"])
    assert "app.py" in block.output
    assert "Not reviewed" in block.output
    assert block.exit_code == cli.EXIT_BLOCKED
    assert warn.exit_code == cli.EXIT_OK


def test_review_json_output(staged_repo: Path) -> None:
    result = runner.invoke(cli.app, ["review", "--format", "json"])
    data = json.loads(result.output)
    assert data["status"] == "not_reviewed"
    assert data["files"][0]["path"] == "app.py"


def test_nothing_staged(make_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(make_repo())
    result = runner.invoke(cli.app, ["review"])
    assert result.exit_code == cli.EXIT_OK
    assert "Nothing to review" in result.output


@pytest.mark.parametrize("flag", ["--run-tests", "--fix"])
def test_future_flags_are_refused(staged_repo: Path, flag: str) -> None:
    assert runner.invoke(cli.app, ["review", flag]).exit_code == cli.EXIT_USAGE


def test_hook_and_range_are_exclusive(staged_repo: Path) -> None:
    result = runner.invoke(cli.app, ["review", "--hook", "--range", "main..main"])
    assert result.exit_code == cli.EXIT_USAGE


def test_ollama_down_is_an_environment_error(
    staged_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def down(*args: object, **kwargs: object) -> None:
        raise OllamaUnreachableError("down")

    monkeypatch.setattr(cli, "check_model", down)
    assert runner.invoke(cli.app, ["review"]).exit_code == cli.EXIT_ENVIRONMENT


def test_cloud_model_is_blocked(staged_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def cloud(*args: object, **kwargs: object) -> None:
        raise CloudModelError("cloud")

    monkeypatch.setattr(cli, "check_model", cloud)
    assert runner.invoke(cli.app, ["review"]).exit_code == cli.EXIT_BLOCKED


def test_remote_ollama_url_is_blocked(staged_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_REVIEWER_OLLAMA_URL", "http://203.0.113.5:11434")
    assert runner.invoke(cli.app, ["review"]).exit_code == cli.EXIT_BLOCKED


def test_oversized_diff_is_not_reviewed(staged_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_REVIEWER_MAX_FILES", "1")
    write_files(staged_repo, {"b.py": "x = 1\n"})
    git(staged_repo, "add", "b.py")
    block = runner.invoke(cli.app, ["review"])
    warn = runner.invoke(cli.app, ["review", "--mode", "warn"])
    assert block.exit_code == cli.EXIT_BLOCKED
    assert warn.exit_code == cli.EXIT_OK


def test_invalid_config_is_a_usage_error(
    staged_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_REVIEWER_MAX_FILES", "not-a-number")
    assert runner.invoke(cli.app, ["review"]).exit_code == cli.EXIT_USAGE


def test_outside_a_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(cli.app, ["review"]).exit_code == cli.EXIT_USAGE


def test_main_maps_usage_errors_to_exit_3(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["git-reviewer", "review", "--no-such-option"])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == cli.EXIT_USAGE


def test_main_returns_command_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["git-reviewer", "install-hook"])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == cli.EXIT_USAGE


def test_file_names_are_sanitized_in_output(
    make_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = make_repo()
    write_files(repo, {f"admin{chr(0x202E)}gnp.py": "x = 1\n"})
    git(repo, "add", "-A")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(cli, "check_model", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "exposure_warnings", lambda endpoint: [])
    result = runner.invoke(cli.app, ["review"])
    assert chr(0x202E) not in result.output
    assert "<U+202E>" in result.output


def test_review_warns_when_ollama_is_exposed(
    staged_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "exposure_warnings", lambda endpoint: ["Ollama listens on *:11434"])
    result = runner.invoke(cli.app, ["review", "--mode", "warn"])
    assert result.exit_code == cli.EXIT_OK
    assert "warning: Ollama listens on *:11434" in result.output


def test_unsafe_path_blocks_even_in_warn_mode(
    make_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = make_repo()
    write_files(repo, {"evil\x1b]52;c;x.py": "x = 1\n"})
    git(repo, "add", "-A")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    result = runner.invoke(cli.app, ["review", "--mode", "warn", "--format", "json"])
    assert result.exit_code == cli.EXIT_BLOCKED
    assert '"status": "not_reviewed"' in result.output


def test_git_timeout_is_not_reviewed(staged_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(*args: object, **kwargs: object) -> None:
        raise proc.ProcTimeoutError("process exceeded 60s")

    monkeypatch.setattr(cli, "collect_staged", slow)
    result = runner.invoke(cli.app, ["review", "--format", "json"])
    assert result.exit_code == cli.EXIT_BLOCKED
    assert json.loads(result.stdout)["status"] == "not_reviewed"


def test_git_failure_is_an_environment_error(
    staged_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: object, **kwargs: object) -> None:
        raise DiffError("git diff failed: fatal: bad object")

    monkeypatch.setattr(cli, "collect_staged", broken)
    result = runner.invoke(cli.app, ["review", "--mode", "warn"])
    assert result.exit_code == cli.EXIT_ENVIRONMENT


def test_unexpected_crash_never_exits_0_or_1(
    staged_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def crash(*args: object, **kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "collect_staged", crash)
    monkeypatch.setattr(sys, "argv", ["git-reviewer", "review", "--mode", "warn"])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == cli.EXIT_BLOCKED


def test_doctor_requires_git_2_40(monkeypatch: pytest.MonkeyPatch) -> None:
    old = proc.Result(0, b"git version 2.39.5\n", b"")
    monkeypatch.setattr(cli.proc, "run", lambda *args, **kwargs: old)
    assert cli._check_git() is False  # pyright: ignore[reportPrivateUsage]


def test_no_arguments_prints_help(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["git-reviewer"])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == cli.EXIT_OK
    assert "review" in capsys.readouterr().out


def test_empty_range_is_an_error_not_a_staged_review(staged_repo: Path) -> None:
    result = runner.invoke(cli.app, ["review", "--range", ""])
    assert result.exit_code == cli.EXIT_USAGE
    assert "Nothing to review" not in result.output


def test_unsafe_path_is_named_in_escaped_form(
    make_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = make_repo()
    write_files(repo, {"evil\x1b[2Jname.py": "x = 1\n"})
    git(repo, "add", "-A")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    result = runner.invoke(cli.app, ["review"])
    assert "evil<U+001B>[2Jname.py" in result.output
    assert "\x1b" not in result.output


def test_exposure_is_not_checked_when_ollama_is_unreachable(
    staged_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []

    def down(*args: object, **kwargs: object) -> None:
        raise OllamaUnreachableError("down")

    monkeypatch.setattr(cli, "check_model", down)
    monkeypatch.setattr(cli, "exposure_warnings", lambda endpoint: calls.append(endpoint) or [])
    assert runner.invoke(cli.app, ["review"]).exit_code == cli.EXIT_ENVIRONMENT
    assert calls == []


def test_missing_model_message_does_not_say_start_ollama(
    staged_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing(*args: object, **kwargs: object) -> None:
        raise ModelMissingError("model m is not installed; run: ollama pull m")

    monkeypatch.setattr(cli, "check_model", missing)
    result = runner.invoke(cli.app, ["review"])
    assert result.exit_code == cli.EXIT_ENVIRONMENT
    assert "ollama pull m" in result.output
    assert "start Ollama" not in result.output

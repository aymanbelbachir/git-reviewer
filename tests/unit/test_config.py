from __future__ import annotations

from pathlib import Path

import pytest

from git_reviewer.config import ConfigError, Settings, config_path, load_settings


def write_config(path: Path, text: str, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def test_defaults(tmp_path: Path) -> None:
    settings = load_settings(environ={}, path=tmp_path / "missing.toml")
    assert settings == Settings()
    assert settings.ollama_url == "http://127.0.0.1:11434"
    # The guardian has its own model and context, chosen by measurement (SECURITY.md §7).
    reviewer = (settings.reviewer_model, settings.model_context_tokens)
    guardian = (settings.guardian_model, settings.guardian_context_tokens)
    assert reviewer == ("qwen2.5-coder:7b", 32_768)
    assert guardian == ("qwen2.5-coder:14b", 12_288)


def test_precedence_cli_over_env_over_file(tmp_path: Path) -> None:
    file = write_config(tmp_path / "config.toml", 'reviewer_model = "from-file"\nmax_files = 10\n')
    environ = {"GIT_REVIEWER_REVIEWER_MODEL": "from-env", "GIT_REVIEWER_MAX_FILES": "20"}
    settings = load_settings(environ=environ, path=file, overrides={"reviewer_model": "from-cli"})
    assert settings.reviewer_model == "from-cli"
    assert settings.max_files == 20


def test_xdg_config_home_is_used(tmp_path: Path) -> None:
    assert config_path({"XDG_CONFIG_HOME": str(tmp_path)}) == (
        tmp_path / "git-reviewer" / "config.toml"
    )


@pytest.mark.parametrize(
    "text",
    [
        "max_files = 100000\n",
        "max_diff_bytes = 999999999\n",
        "ollama_timeout_seconds = 0\n",
        "model_context_tokens = 4096\n",
        "guardian_context_tokens = 4096\n",
        "guardian_context_tokens = 1000000\n",
        'severity_threshold = "none"\n',
        'reviewer_model = "bad model; rm -rf"\n',
        "unknown_key = 1\n",
    ],
)
def test_out_of_bounds_or_unknown_values_are_refused(tmp_path: Path, text: str) -> None:
    file = write_config(tmp_path / "config.toml", text)
    with pytest.raises(ConfigError):
        load_settings(environ={}, path=file)


def test_group_writable_config_file_is_refused(tmp_path: Path) -> None:
    file = write_config(tmp_path / "config.toml", "max_files = 10\n", mode=0o664)
    with pytest.raises(ConfigError, match="writable"):
        load_settings(environ={}, path=file)


def test_invalid_toml_is_refused(tmp_path: Path) -> None:
    file = write_config(tmp_path / "config.toml", "max_files = = 1\n")
    with pytest.raises(ConfigError):
        load_settings(environ={}, path=file)


def test_non_utf8_config_is_a_config_error(tmp_path: Path) -> None:
    file = tmp_path / "config.toml"
    file.write_bytes(b"max_files = 1\n# \xff\xfe\n")
    file.chmod(0o600)
    with pytest.raises(ConfigError):
        load_settings(environ={}, path=file)


@pytest.mark.parametrize("value", [".", "config", "../x", ""])
def test_relative_xdg_config_home_is_ignored(value: str) -> None:
    assert (
        config_path({"XDG_CONFIG_HOME": value}) == Path.home() / ".config/git-reviewer/config.toml"
    )

"""Settings (docs/ARCHITECTURE.md §9; SECURITY.md T-27).

Sources, highest first: CLI flags, `GIT_REVIEWER_*` environment variables, the user config file
`$XDG_CONFIG_HOME/git-reviewer/config.toml` (default `~/.config/...`). Nothing is ever read from the
reviewed repository: a malicious branch could otherwise point `ollama_url` at a remote host or
loosen limits. Every security limit has a hard upper bound here.
"""

from __future__ import annotations

import os
import stat
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

ENV_PREFIX = "GIT_REVIEWER_"
_MODEL_NAME = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
# A local image: name[:tag], or the image ID itself. Never an option (no leading "-").
_IMAGE_REF = r"^([a-z0-9][a-z0-9._/-]{0,199}(:[A-Za-z0-9._-]{1,128})?|sha256:[0-9a-f]{64})$"

Severity = Literal["info", "low", "medium", "high", "critical"]


class ConfigError(ValueError):
    """The configuration is invalid or its file is unsafe."""


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ollama_url: str = "http://127.0.0.1:11434"
    reviewer_model: str = Field(default="qwen2.5-coder:7b", pattern=_MODEL_NAME)
    # Separate from the reviewer, as the spec requires. Chosen by measurement (SECURITY.md §7): it
    # caught more than the 7b and than llama3.1:8b, a model of another family.
    guardian_model: str = Field(default="qwen2.5-coder:14b", pattern=_MODEL_NAME)
    ollama_timeout_seconds: float = Field(default=120.0, gt=0, le=600)
    max_diff_bytes: int = Field(default=1024 * 1024, ge=1024, le=5 * 1024 * 1024)
    max_files: int = Field(default=200, ge=1, le=1000)
    max_line_chars: int = Field(default=10_000, ge=100, le=100_000)
    # What the model is shown: the numbered diff and static findings must fit its context.
    max_review_chars: int = Field(default=60_000, ge=1_000, le=200_000)
    # At least twice the 4096 tokens reserved for the model's answer.
    model_context_tokens: int = Field(default=32_768, ge=8_192, le=131_072)
    # The guardian model's own context: at 12,288 the 14b stays entirely on the GPU of a 16 GB
    # machine. Guardians split what they read to fit it, and block or alert on what does not fit.
    guardian_context_tokens: int = Field(default=12_288, ge=8_192, le=131_072)
    severity_threshold: Severity = "high"
    # The sandbox image the user built (docs/ARCHITECTURE.md §8.2); never built or pulled by us.
    sandbox_image: str = Field(default="git-reviewer-sandbox:0.1", pattern=_IMAGE_REF)
    sandbox_timeout_seconds: int = Field(default=300, ge=10, le=1_800)


def config_path(environ: Mapping[str, str] = os.environ) -> Path:
    # The XDG spec says to ignore a relative XDG_CONFIG_HOME. Honouring it would read the
    # config from the current directory, which may be the reviewed repository (T-27).
    base = environ.get("XDG_CONFIG_HOME", "")
    if not Path(base).is_absolute():
        base = str(Path.home() / ".config")
    return Path(base) / "git-reviewer" / "config.toml"


def load_settings(
    *,
    overrides: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] = os.environ,
    path: Path | None = None,
) -> Settings:
    data: dict[str, Any] = {}
    file = path if path is not None else config_path(environ)
    if file.exists():
        data.update(_read_file(file))
    for name in Settings.model_fields:
        env_name = ENV_PREFIX + name.upper()
        if env_name in environ:
            data[name] = environ[env_name]
    data.update({key: value for key, value in (overrides or {}).items() if value is not None})
    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration: {exc.error_count()} error(s)\n{exc}") from exc


def _read_file(path: Path) -> dict[str, Any]:
    try:
        return _read_checked_file(path)
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc


def _read_checked_file(path: Path) -> dict[str, Any]:
    info = path.stat()
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError(f"{path} is writable by group or others; run: chmod go-w {path}")
    if info.st_uid != os.getuid():
        raise ConfigError(f"{path} is not owned by the current user")
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc

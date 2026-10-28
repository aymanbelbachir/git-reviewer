"""The Docker endpoint: a local Unix socket only (docs/ARCHITECTURE.md §8.3; SECURITY.md T-17).

The code under review is sent to whatever daemon the docker CLI talks to, so the endpoint is
resolved once, here, and every docker call then gets `--host unix://<socket>` with an empty private
DOCKER_CONFIG:
- DOCKER_HOST if set; otherwise the current Docker context (DOCKER_CONTEXT, or `currentContext` in
  the Docker config file, whose other content is never read); otherwise /var/run/docker.sock;
- it must be `unix://`: tcp:// or ssh:// would send the code to another machine;
- the socket must exist, belong to root or the current user, and sit in a directory other users
  cannot write, or a sticky one (such as /tmp) where they cannot replace it; otherwise someone
  could put a fake daemon there and receive the code.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path

DEFAULT_HOST = "unix:///var/run/docker.sock"
_MAX_CONFIG_BYTES = 1024 * 1024
_CONTEXT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}")


class DockerUnavailableError(RuntimeError):
    """Docker is not installed, not running, or its context cannot be found."""


class UnsafeDockerEndpointError(RuntimeError):
    """The Docker endpoint is remote or could be replaced by another user."""


def resolve_endpoint(environ: Mapping[str, str] = os.environ) -> Path:
    """The resolved path of the local Docker socket to use for every call."""
    host = environ.get("DOCKER_HOST", "").strip()
    if host:
        return _local_socket(host, "DOCKER_HOST")
    config_dir = _config_dir(environ)
    context = environ.get("DOCKER_CONTEXT", "").strip() or _current_context(config_dir)
    if context in {"", "default"}:
        return _local_socket(DEFAULT_HOST, "the default Docker endpoint")
    return _local_socket(_context_host(config_dir, context), f"Docker context {context!r}")


def _config_dir(environ: Mapping[str, str]) -> Path:
    configured = environ.get("DOCKER_CONFIG", "")
    if not configured:
        return Path.home() / ".docker"
    # A relative path would be read from the current directory: the reviewed repository.
    if not Path(configured).is_absolute():
        raise UnsafeDockerEndpointError("DOCKER_CONFIG must be an absolute path")
    return Path(configured)


def _current_context(config_dir: Path) -> str:
    data = _read_json(config_dir / "config.json")
    if data is None:
        return ""
    context = data.get("currentContext", "")
    if not isinstance(context, str) or (context and not _CONTEXT_NAME.fullmatch(context)):
        raise DockerUnavailableError("the Docker config has an invalid currentContext")
    return context


def _context_host(config_dir: Path, context: str) -> str:
    if not _CONTEXT_NAME.fullmatch(context):
        raise DockerUnavailableError("invalid Docker context name")
    digest = hashlib.sha256(context.encode("utf-8")).hexdigest()
    host: object = _read_json(config_dir / "contexts" / "meta" / digest / "meta.json")
    for key in ("Endpoints", "docker", "Host"):
        host = host.get(key) if isinstance(host, dict) else None
    if not isinstance(host, str) or not host:
        raise DockerUnavailableError(f"Docker context {context!r} not found")
    return host


def _read_json(path: Path) -> dict[str, object] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_CONFIG_BYTES:
        raise DockerUnavailableError(f"{path} is not a regular file of reasonable size")
    try:
        data = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise DockerUnavailableError(f"cannot read {path}") from exc
    if not isinstance(data, dict):
        raise DockerUnavailableError(f"{path} is not a JSON object")
    return data


def _local_socket(host: str, source: str) -> Path:
    scheme, separator, rest = host.partition("://")
    if not separator or scheme != "unix":
        raise UnsafeDockerEndpointError(
            f"{source} is not a local unix:// socket ({scheme or 'no scheme'}): the code under "
            "review would leave this machine"
        )
    path = Path(rest)
    if not path.is_absolute():
        raise UnsafeDockerEndpointError(f"{source} must name an absolute socket path")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        parent = resolved.parent.stat()
    except OSError as exc:
        raise DockerUnavailableError(f"Docker is not running (no socket at {path})") from exc
    if not stat.S_ISSOCK(info.st_mode):
        raise DockerUnavailableError(f"{resolved} is not a socket")
    if info.st_uid not in {0, os.getuid()}:
        raise UnsafeDockerEndpointError(f"{resolved} belongs to another user")
    others_can_write = parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    if others_can_write and not parent.st_mode & stat.S_ISVTX:
        raise UnsafeDockerEndpointError(f"{resolved.parent} is writable by other users")
    return resolved

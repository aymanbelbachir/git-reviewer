"""Checks on the Ollama endpoint and models (docs/ARCHITECTURE.md §9; SECURITY.md T-24).

The only network peer git-reviewer may talk to is a loopback Ollama:
- the URL must be a literal loopback address, or `localhost` resolving only to loopback addresses;
  other host names are refused without being resolved, so no DNS query leaves the machine;
- the HTTP client ignores proxy variables (`trust_env=False`) and never follows redirects, so a
  proxy or a redirect cannot carry a request (and later the code) elsewhere;
- Ollama cloud models are refused: local Ollama would forward the prompt to Ollama's servers.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from git_reviewer import proc

DEFAULT_PORT = 11434
_MAX_RESPONSE_BYTES = 1024 * 1024
_ALL_INTERFACES = frozenset({"0.0.0.0", "::", "*"})  # noqa: S104 - compared against, never bound


class OllamaError(RuntimeError):
    """Base class for Ollama problems."""


class UnsafeOllamaUrlError(OllamaError):
    """The URL could send data off the machine."""


class OllamaUnreachableError(OllamaError):
    """Ollama did not answer as expected."""


class ModelMissingError(OllamaError):
    """The configured model is not installed."""


class CloudModelError(OllamaError):
    """The model runs on Ollama's servers, not locally."""


@dataclass(frozen=True)
class Endpoint:
    base_url: str
    host: str
    port: int


@dataclass(frozen=True)
class ModelInfo:
    name: str
    remote: bool


def validate_url(url: str) -> Endpoint:
    """Accept only http(s) URLs to a loopback address, without credentials, path or query."""
    try:
        parts = urlsplit(url)
        port = parts.port or DEFAULT_PORT
    except ValueError as exc:
        raise UnsafeOllamaUrlError(f"invalid Ollama URL: {exc}") from exc
    if parts.scheme not in {"http", "https"}:
        raise UnsafeOllamaUrlError("the Ollama URL must use http or https")
    if parts.username is not None or parts.password is not None:
        raise UnsafeOllamaUrlError("the Ollama URL must not contain credentials")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise UnsafeOllamaUrlError("the Ollama URL must not have a path, query or fragment")
    host = (parts.hostname or "").lower()
    if host == "localhost":
        addresses = _resolve_localhost(port)
        if not addresses or not all(ipaddress.ip_address(a).is_loopback for a in addresses):
            raise UnsafeOllamaUrlError("localhost does not resolve only to loopback addresses")
    else:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise UnsafeOllamaUrlError(
                "the Ollama host must be a loopback address (127.0.0.1, ::1) or localhost"
            ) from exc
        if not address.is_loopback:
            raise UnsafeOllamaUrlError(f"{host} is not a loopback address")
    netloc = f"[{host}]" if ":" in host else host
    return Endpoint(base_url=f"{parts.scheme}://{netloc}:{port}", host=host, port=port)


def is_cloud_model_name(name: str) -> bool:
    tag = name.rpartition(":")[2] if ":" in name else ""
    return name.endswith("-cloud") or tag == "cloud" or tag.endswith("-cloud")


def make_client(
    endpoint: Endpoint, *, timeout: float, transport: httpx.BaseTransport | None = None
) -> httpx.Client:
    return httpx.Client(
        base_url=endpoint.base_url,
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
        transport=transport,
    )


def list_models(
    endpoint: Endpoint, *, timeout: float = 10.0, transport: httpx.BaseTransport | None = None
) -> list[ModelInfo]:
    with make_client(endpoint, timeout=timeout, transport=transport) as client:
        try:
            with client.stream("GET", "/api/tags") as response:
                if response.status_code != httpx.codes.OK:
                    raise OllamaUnreachableError(f"Ollama answered HTTP {response.status_code}")
                body = _read_capped(response)
        except httpx.HTTPError as exc:
            raise OllamaUnreachableError(f"Ollama is not reachable at {endpoint.base_url}") from exc
    return _parse_tags(body)


def _read_capped(response: httpx.Response) -> bytes:
    """Read the body, stopping as soon as it exceeds the cap instead of buffering it all."""
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        size += len(chunk)
        if size > _MAX_RESPONSE_BYTES:
            raise OllamaUnreachableError("Ollama's answer is unexpectedly large")
        chunks.append(chunk)
    return b"".join(chunks)


def check_model(
    endpoint: Endpoint,
    model: str,
    *,
    timeout: float = 10.0,
    transport: httpx.BaseTransport | None = None,
) -> None:
    """Raise unless `model` is installed and runs locally."""
    if is_cloud_model_name(model):
        raise CloudModelError(
            f"{model} is an Ollama cloud model; it would send the code off the machine"
        )
    for info in list_models(endpoint, timeout=timeout, transport=transport):
        if info.name in {model, f"{model}:latest"}:
            if info.remote:
                raise CloudModelError(f"{model} runs on a remote host, not locally")
            return
    raise ModelMissingError(f"model {model} is not installed; run: ollama pull {model}")


def exposure_warnings(endpoint: Endpoint, environ: Mapping[str, str] = os.environ) -> list[str]:
    """Warn when Ollama appears to listen on all interfaces (reachable from the network)."""
    warnings: list[str] = []
    configured = environ.get("OLLAMA_HOST", "")
    if configured and _binds_widely(configured):
        warnings.append(f"OLLAMA_HOST={configured} makes Ollama listen on the network")
    try:
        result = proc.run(
            "lsof",
            ["-nP", f"-iTCP:{endpoint.port}", "-sTCP:LISTEN", "-Fn"],
            cwd=Path("/"),
            timeout=10,
        )
    except proc.ProcError as exc:
        warnings.append(f"could not check which interfaces Ollama listens on ({exc})")
        return warnings
    listeners = parse_lsof_listeners(result.stdout.decode("utf-8", "replace"))
    if result.returncode != 0 or not listeners:
        warnings.append(
            "could not determine which interfaces Ollama listens on "
            "(it may run as another user); check that it is not exposed to the network"
        )
    for address in listeners:
        if _binds_widely(address):
            warnings.append(
                f"Ollama listens on {address}: other machines on the network can reach it"
            )
    return warnings


def parse_lsof_listeners(output: str) -> list[str]:
    """Listening addresses from `lsof -Fn` output, e.g. '127.0.0.1:11434' or '*:11434'."""
    return [line[1:] for line in output.splitlines() if line.startswith("n")]


def _binds_widely(address: str) -> bool:
    value = address.split("://", 1)[-1]
    host = value.rsplit(":", 1)[0] if value.count(":") == 1 or value.startswith("[") else value
    host = host.strip("[]")
    # An empty host (":11434") listens on every interface.
    if not host or host in _ALL_INTERFACES:
        return True
    if host == "localhost":
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return True


def _resolve_localhost(port: int) -> set[str]:
    try:
        infos = socket.getaddrinfo("localhost", port, proto=socket.IPPROTO_TCP)
    except OSError:
        return set()
    return {str(info[4][0]).split("%", 1)[0] for info in infos}


def _parse_tags(body: bytes) -> list[ModelInfo]:
    try:
        payload: Any = json.loads(body)
    except ValueError as exc:
        raise OllamaUnreachableError("Ollama returned invalid JSON") from exc
    models = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        raise OllamaUnreachableError("unexpected answer from Ollama's /api/tags")
    infos: list[ModelInfo] = []
    for entry in models:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("model")
        if not isinstance(name, str):
            continue
        remote = bool(entry.get("remote_host") or entry.get("remote_model")) or is_cloud_model_name(
            name
        )
        infos.append(ModelInfo(name=name, remote=remote))
    return infos

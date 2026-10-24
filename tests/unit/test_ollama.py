from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from git_reviewer.llm import ollama
from git_reviewer.llm.ollama import (
    CloudModelError,
    ModelMissingError,
    OllamaUnreachableError,
    UnsafeOllamaUrlError,
    check_model,
    validate_url,
)

ENDPOINT = validate_url("http://127.0.0.1:11434")


def tags_transport(models: list[dict[str, Any]], status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        return httpx.Response(status, content=json.dumps({"models": models}).encode())

    return httpx.MockTransport(handler)


@pytest.mark.parametrize(
    ("url", "base"),
    [
        ("http://127.0.0.1:11434", "http://127.0.0.1:11434"),
        ("http://127.0.0.1", "http://127.0.0.1:11434"),
        ("http://127.0.0.2:8080/", "http://127.0.0.2:8080"),
        ("http://[::1]:11434", "http://[::1]:11434"),
        ("http://localhost:11434", "http://localhost:11434"),
    ],
)
def test_loopback_urls_are_accepted(url: str, base: str) -> None:
    assert validate_url(url).base_url == base


def test_model_present_passes() -> None:
    transport = tags_transport([{"name": "qwen2.5-coder:7b", "model": "qwen2.5-coder:7b"}])
    check_model(ENDPOINT, "qwen2.5-coder:7b", transport=transport)


def test_latest_tag_matches_bare_name() -> None:
    check_model(ENDPOINT, "llama3", transport=tags_transport([{"name": "llama3:latest"}]))


def test_missing_model_is_reported() -> None:
    with pytest.raises(ModelMissingError, match="ollama pull"):
        check_model(ENDPOINT, "qwen2.5-coder:7b", transport=tags_transport([]))


def test_server_error_is_unreachable() -> None:
    with pytest.raises(OllamaUnreachableError):
        check_model(ENDPOINT, "m", transport=tags_transport([], status=500))


def test_invalid_json_is_unreachable() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"not json"))
    with pytest.raises(OllamaUnreachableError):
        check_model(ENDPOINT, "m", transport=transport)


def test_connection_refused_is_unreachable() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(OllamaUnreachableError):
        check_model(ENDPOINT, "m", transport=httpx.MockTransport(refuse))


@pytest.mark.parametrize(
    ("value", "wide"),
    [
        ("0.0.0.0", True),
        ("0.0.0.0:11434", True),
        ("http://0.0.0.0:11434", True),
        ("[::]:11434", True),
        ("::", True),
        ("*:11434", True),
        ("192.168.1.20:11434", True),
        ("127.0.0.1:11434", False),
        ("[::1]:11434", False),
        ("localhost:11434", False),
        (":11434", True),
    ],
)
def test_binds_widely(value: str, wide: bool) -> None:
    assert ollama._binds_widely(value) is wide  # pyright: ignore[reportPrivateUsage]


def test_parse_lsof_listeners() -> None:
    output = "p123\nfollama\nn127.0.0.1:11434\np456\nn*:11434\n"
    assert ollama.parse_lsof_listeners(output) == ["127.0.0.1:11434", "*:11434"]


def test_exposure_warning_from_ollama_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ollama.proc, "run", lambda *a, **k: ollama.proc.Result(1, b"", b""))
    warnings = ollama.exposure_warnings(ENDPOINT, {"OLLAMA_HOST": "0.0.0.0"})
    assert any("OLLAMA_HOST" in warning for warning in warnings)


def test_exposure_warning_from_listening_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ollama.proc, "run", lambda *a, **k: ollama.proc.Result(0, b"p1\nn*:11434\n", b"")
    )
    warnings = ollama.exposure_warnings(ENDPOINT, {})
    assert any("*:11434" in warning for warning in warnings)


def test_no_exposure_warning_on_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ollama.proc, "run", lambda *a, **k: ollama.proc.Result(0, b"p1\nn127.0.0.1:11434\n", b"")
    )
    assert ollama.exposure_warnings(ENDPOINT, {}) == []


def test_unsafe_url_error_type() -> None:
    with pytest.raises(UnsafeOllamaUrlError):
        validate_url("ftp://127.0.0.1")


def test_cloud_model_error_type() -> None:
    with pytest.raises(CloudModelError):
        check_model(ENDPOINT, "gpt-oss:120b-cloud", transport=tags_transport([]))


def test_warning_when_no_listener_is_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ollama.proc, "run", lambda *a, **k: ollama.proc.Result(1, b"", b""))
    warnings = ollama.exposure_warnings(ENDPOINT, {})
    assert any("could not determine" in warning for warning in warnings)

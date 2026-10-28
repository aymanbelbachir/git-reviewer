"""Strict structured output from the local model (docs/ARCHITECTURE.md §6.3; T-02, T-04).

The model gets no tools. It is asked for JSON matching a schema (Ollama's constrained decoding),
and its raw answer is then validated by our own code with `strict=True` and `extra="forbid"`.
Invalid output is an error: it is never repaired, re-parsed leniently or retried here. Only the
fix loop asks again, as its next attempt (at most three in all), and validates that new answer the
same way.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from typing import Annotated, Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from git_reviewer.llm.ollama import Endpoint
from git_reviewer.models import ReviewFinding

MAX_RAW_OUTPUT_CHARS = 64_000
ANSWER_TOKENS = 4_096
"""Tokens reserved for the model's answer (Ollama `num_predict`), out of its context window."""

ChatFn = Callable[[str, str, dict[str, Any]], str]
"""(system prompt, user prompt, JSON schema) -> raw model output."""

_STRICT = ConfigDict(extra="forbid", strict=True, frozen=True)


class LLMOutputError(RuntimeError):
    """The model's output was missing, oversized, cut off or did not match the schema."""


class ModelCallError(RuntimeError):
    """The model could not be reached, failed, or did not answer in time."""


class ReviewerOutput(BaseModel):
    model_config = _STRICT

    findings: list[ReviewFinding] = Field(max_length=50)
    summary: str = Field(max_length=1000)


class PatchEditOutput(BaseModel):
    """Replace lines start_line..end_line (1-based, inclusive) of `path` with `replacement`;
    end_line = start_line - 1 inserts before start_line."""

    model_config = _STRICT

    path: str = Field(max_length=4096)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=0)
    replacement: str = Field(max_length=5_000)


class PatchAuthorOutput(BaseModel):
    """Structured edits, never a free-form diff: we build the diff ourselves (§11)."""

    model_config = _STRICT

    edits: list[PatchEditOutput] = Field(min_length=1, max_length=10)
    explanation: str = Field(max_length=500)


class GuardianLineRef(BaseModel):
    model_config = _STRICT

    file: str = Field(max_length=4096)
    line: int = Field(ge=1)


class GuardianOutput(BaseModel):
    """The output every guardian must produce (docs/SPEC.md, guardian rules)."""

    model_config = _STRICT

    verdict: Literal["ok", "suspect", "block"]
    # Each reason is cut to 300 characters before display (guardians.base). The schema bound is
    # looser, so that a wordy but otherwise valid answer is not a failure, which would block.
    reasons: list[Annotated[str, Field(max_length=1_000)]] = Field(max_length=10)
    lines: list[GuardianLineRef] = Field(max_length=50)


def ask_json[T: BaseModel](chat: ChatFn, system: str, user: str, schema: type[T]) -> tuple[T, str]:
    """Call the model and validate its answer strictly. Returns (parsed, raw)."""
    raw = chat(system, user, schema.model_json_schema())
    if not isinstance(raw, str) or not raw.strip():
        raise LLMOutputError("the model returned no output")
    if len(raw) > MAX_RAW_OUTPUT_CHARS:
        raise LLMOutputError("the model output is too large")
    try:
        return schema.model_validate_json(raw, strict=True), raw
    except ValidationError as exc:
        raise LLMOutputError(
            f"the model output does not match the schema ({exc.error_count()} errors)"
        ) from exc


def ollama_chat(endpoint: Endpoint, model: str, *, timeout: float, num_ctx: int) -> ChatFn:
    """A ChatFn backed by langchain-ollama, with the same network guarantees as the checks:
    explicit loopback base URL, no proxy (`trust_env=False`), no redirects.

    `timeout` bounds the whole call, not only each network read. Ollama's own report is checked:
    the answer must have ended normally (not cut at `num_predict`), and the prompt must have fit
    the context window with room for the answer, because Ollama silently drops part of a prompt
    that does not fit (the system prompt and its canary included)."""
    import ollama
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_ollama import ChatOllama

    clients: dict[str, ChatOllama] = {}

    def chat(system: str, user: str, schema: dict[str, Any]) -> str:
        key = json.dumps(schema, sort_keys=True)
        if key not in clients:  # one client per output schema, reused across calls
            clients[key] = ChatOllama(
                model=model,
                base_url=endpoint.base_url,
                format=schema,
                temperature=0,
                seed=0,
                num_ctx=num_ctx,
                num_predict=ANSWER_TOKENS,
                reasoning=False,
                client_kwargs={"timeout": timeout, "follow_redirects": False, "trust_env": False},
            )
        client = clients[key]
        messages = [SystemMessage(content=system), HumanMessage(content=user)]
        try:
            message = _within(timeout, lambda: client.invoke(messages))
        # langchain-ollama raises ValueError when the stream ends without any data.
        except (httpx.HTTPError, ollama.ResponseError, OSError, ValueError) as exc:
            raise ModelCallError(f"the model call failed ({type(exc).__name__})") from exc
        meta = message.response_metadata
        if meta.get("done_reason") != "stop":
            raise LLMOutputError("the model's answer was cut off before it finished")
        # Ollama does not count a prefix it reuses from its cache. Every prompt carries a fresh
        # canary or nonce, so at most the fixed start of the system prompt goes uncounted.
        prompt_tokens = meta.get("prompt_eval_count")
        if not isinstance(prompt_tokens, int) or prompt_tokens >= num_ctx - ANSWER_TOKENS:
            raise LLMOutputError("the prompt did not fit the model context")
        content = message.content
        if not isinstance(content, str):
            raise LLMOutputError("the model returned a non-text answer")
        return content

    return chat


def _within[T](seconds: float, call: Callable[[], T]) -> T:
    """Run `call` with a wall-clock deadline. A late call is abandoned on a daemon thread, so the
    process never waits for it on exit."""
    outcome: dict[str, Any] = {}

    def target() -> None:
        try:
            outcome["value"] = call()
        except BaseException as exc:  # handed to the caller's thread below
            outcome["error"] = exc

    worker = threading.Thread(target=target, name="model-call", daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        raise ModelCallError(f"the model did not answer within {seconds:g} seconds")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]

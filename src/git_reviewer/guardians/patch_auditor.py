"""Patch auditor (docs/SPEC.md "Guardian agents" 3; docs/ARCHITECTURE.md §10.3).

Separate from the patch author: its own prompt, and it sees only the reported problem and the
patch, never the author's explanation or reasoning. It can reject a patch or raise an alert,
never approve one that the deterministic rules (patch.policy, patch.checks) refused; those run
before it and have the final say. Any failure rejects the patch (fail closed).
"""

from __future__ import annotations

from git_reviewer.guardians.base import decision, run_guardian
from git_reviewer.llm import prompts
from git_reviewer.llm.structured import ANSWER_TOKENS, ChatFn
from git_reviewer.models import Decision, FixTarget, LineRef

_PROMPT_MARGIN_TOKENS = 1_024
_SYSTEM = prompts.PATCH_AUDITOR_SYSTEM_PROMPT


def fits(target: FixTarget, patch: str, *, context_tokens: int) -> bool:
    """Whether the auditor can read the whole finding and patch in one call. Checked before the
    patch runs in the sandbox, so a patch it cannot audit is rejected first, not after the run."""
    user = _user_prompt(target, patch)
    # Every token is at least one UTF-8 byte: a prompt of this many bytes always fits.
    budget = context_tokens - ANSWER_TOKENS - len(_SYSTEM.encode()) - _PROMPT_MARGIN_TOKENS
    return len(user.encode()) <= budget


def audit(
    target: FixTarget,
    patch: str,
    added: list[tuple[int, str]],
    chat: ChatFn,
    *,
    context_tokens: int,
) -> Decision:
    if not fits(target, patch, context_tokens=context_tokens):
        return decision("patch.auditor", "block", ["the patch is too large to audit"])
    allowed = frozenset(LineRef(file=target.file, line=number) for number, _text in added)
    return run_guardian(
        "patch.auditor", chat, _SYSTEM, _user_prompt(target, patch), allowed_lines=allowed
    )


def _user_prompt(target: FixTarget, patch: str) -> str:
    # The nonce is new for every prompt but always the same length, so the size check holds.
    return prompts.patch_auditor_user_prompt(target.model_dump_json(), patch, prompts.new_nonce())

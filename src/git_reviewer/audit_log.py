"""Structured audit log with allowlisted fields only (docs/ARCHITECTURE.md §12; SECURITY.md T-26).

Events carry counts, verdicts, rule ids and durations, never code, diff content, model output or
secret values: field names are allowlisted and values must be numbers, booleans or short
identifiers. Silent unless the user enables logging for "git_reviewer".
"""

from __future__ import annotations

import logging
import re

_LOGGER = logging.getLogger("git_reviewer.audit")
_ALLOWED_FIELDS = frozenset(
    {"source", "verdict", "reasons", "lines", "findings", "files", "tool", "status", "seconds"}
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,64}")


def event(name: str, **fields: object) -> None:
    if not _IDENTIFIER.fullmatch(name):
        raise ValueError("audit event names must be short identifiers")
    unknown = set(fields) - _ALLOWED_FIELDS
    if unknown:
        raise ValueError(f"audit fields not allowlisted: {sorted(unknown)}")
    for key, value in fields.items():
        if isinstance(value, bool | int | float):
            continue
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise ValueError(f"audit field {key} must be a number or a short identifier")
    _LOGGER.info("%s %s", name, " ".join(f"{k}={v}" for k, v in sorted(fields.items())))

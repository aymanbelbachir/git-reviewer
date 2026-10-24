"""Pydantic models for data that crosses a trust boundary (docs/ARCHITECTURE.md §2)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

FileStatus = Literal["added", "modified", "deleted", "type_changed"]


class FileChange(BaseModel):
    """One file of the reviewed diff. `added_lines` uses the new file's line numbers."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    path: str
    status: FileStatus
    binary: bool
    added_lines: frozenset[int]


class Diff(BaseModel):
    """The reviewed change: staged changes, or BASE..HEAD from their merge base."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    mode: Literal["staged", "range"]
    base: str | None
    head: str | None
    files: tuple[FileChange, ...]
    patch: str

    @property
    def added_line_count(self) -> int:
        return sum(len(change.added_lines) for change in self.files)

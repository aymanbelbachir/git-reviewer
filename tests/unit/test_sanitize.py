from __future__ import annotations

import pytest

from git_reviewer.sanitize import for_terminal, one_line

ESC = chr(0x1B)
BEL = chr(0x07)
RLO = chr(0x202E)
ZWSP = chr(0x200B)
TAG_A = chr(0xE0041)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (f"{ESC}[31mred", "<U+001B>[31mred"),
        (f"{ESC}]52;c;ZXZpbA=={BEL}", "<U+001B>]52;c;ZXZpbA==<U+0007>"),
        (f"admin{RLO}gnp.exe", "admin<U+202E>gnp.exe"),
        (f"pass{ZWSP}word", "pass<U+200B>word"),
        (f"x{TAG_A}", "x<U+E0041>"),
        ("line1\nline2\ttab", "line1\nline2\ttab"),
        ("café ok", "café ok"),
    ],
)
def test_for_terminal(raw: str, expected: str) -> None:
    assert for_terminal(raw) == expected


def test_no_escape_character_survives() -> None:
    raw = "".join(chr(code) for code in range(0x20)) + chr(0x7F) + chr(0x9B)
    cleaned = for_terminal(raw)
    assert ESC not in cleaned
    assert chr(0x9B) not in cleaned


def test_length_is_capped() -> None:
    assert for_terminal("a" * 50, max_chars=10) == "a" * 10 + " [truncated]"


def test_one_line_escapes_newlines() -> None:
    assert one_line("a\nb\tc") == "a<U+000A>b<U+0009>c"


@pytest.mark.parametrize(
    "code", [0xFE0F, 0xE0101, 0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0xE000, 0x0378]
)
def test_invisible_and_unassigned_characters_are_escaped(code: int) -> None:
    assert for_terminal(f"a{chr(code)}b") == f"a<U+{code:04X}>b"


def test_decomposed_accents_are_kept() -> None:
    decomposed = "cafe" + chr(0x0301)
    assert for_terminal(decomposed) == decomposed

"""Make untrusted text safe to print (docs/ARCHITECTURE.md §6.5; SECURITY.md T-06, T-07).

File names, diff content and model output can carry terminal escape sequences (clipboard writes,
hidden text, fake links) or bidi and invisible characters that reorder or hide text. Control and
format characters are replaced by visible `<U+XXXX>` markers; the escape character itself is one of
them, so an escape sequence can never reach the terminal.
"""

from __future__ import annotations

import unicodedata

_KEPT_CONTROLS = frozenset({"\n", "\t"})
_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
# Invisible or blank characters outside the categories above: tag characters (ASCII smuggling),
# variation selectors (hidden-byte "emoji smuggling"), the combining grapheme joiner, Hangul
# fillers and the blank Braille pattern.
_INVISIBLE_RANGES = (
    range(0xE0000, 0xE0080),
    range(0xFE00, 0xFE10),
    range(0xE0100, 0xE01F0),
    range(0x034F, 0x0350),
    range(0x115F, 0x1161),
    range(0x3164, 0x3165),
    range(0xFFA0, 0xFFA1),
    range(0x2800, 0x2801),
)
_TRUNCATION_MARK = " [truncated]"


def is_hidden(char: str) -> bool:
    """Whether `char` is shown as a `<U+XXXX>` escape: control, format, separator, unassigned or
    invisible, newline and tab excepted."""
    if char in _KEPT_CONTROLS:
        return False
    return unicodedata.category(char) in _ESCAPED_CATEGORIES or _is_invisible(ord(char))


def for_terminal(text: str, *, max_chars: int = 4000) -> str:
    """Return `text` with every control, format and tag character made visible, length-capped."""
    out: list[str] = []
    for char in text:
        out.append(f"<U+{ord(char):04X}>" if is_hidden(char) else char)
    cleaned = "".join(out)
    if len(cleaned) > max_chars:
        return cleaned[:max_chars] + _TRUNCATION_MARK
    return cleaned


def one_line(text: str, *, max_chars: int = 300) -> str:
    """Like `for_terminal`, for inline values (paths, names): newlines and tabs are escaped too."""
    flattened = text.replace("\n", "<U+000A>").replace("\t", "<U+0009>")
    return for_terminal(flattened, max_chars=max_chars)


def _is_invisible(code: int) -> bool:
    return any(code in block for block in _INVISIBLE_RANGES)


_MASK = "[secret masked]"
_MIN_SECRET_CHARS = 4


def mask_secrets(text: str, secrets: tuple[str, ...]) -> str:
    """Replace every exact occurrence of a known secret value (SECURITY.md T-26). A model that
    paraphrases or splits a secret defeats exact matching: that residual risk is documented."""
    for secret in sorted(secrets, key=len, reverse=True):
        if len(secret) >= _MIN_SECRET_CHARS:
            text = text.replace(secret, _MASK)
    return text


def shows_secret(text: str, secrets: tuple[str, ...]) -> bool:
    """Whether masking would change `text`: a known secret value occurs in it, possibly spanning
    several lines (gitleaks values come from the reviewed branch and can be multi-line)."""
    return mask_secrets(text, secrets) != text

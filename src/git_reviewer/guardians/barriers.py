"""Deterministic anti-injection barrier (docs/ARCHITECTURE.md §10.1; SECURITY.md T-01, T-07).

Scans every line shown to the model (added, unchanged and removed) and every file name:
- bidirectional controls (Trojan Source) and Unicode tag characters (hidden ASCII) -> block;
- other invisible or format characters (zero-width, joiners, variation selectors) -> suspect, as
  they also occur legitimately (emoji sequences);
- base64 or hex runs that decode to readable text -> suspect, and the decoded text is scanned too.
  Runs that decode to random bytes (hashes, keys in lockfiles) carry no message and are ignored;
- phrases addressed to an AI, after NFKC normalization, casefolding and removal of invisible
  characters, also across three consecutive lines (split instructions) -> suspect;
- text imitating our own data delimiters -> suspect;
- a carriage return inside a line (Python sees a line break git does not) -> block.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

from git_reviewer.git.diff import PatchLine, patch_lines
from git_reviewer.models import VERDICT_RANK, Diff, LineRef, Verdict

_BIDI = frozenset({0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)})
_TAGS = range(0xE0000, 0xE0080)
_OTHER_INVISIBLE = (
    range(0x200B, 0x200E),
    range(0x2060, 0x2065),
    range(0xFE00, 0xFE10),
    range(0xE0100, 0xE01F0),
    range(0x034F, 0x0350),
    range(0x115F, 0x1161),
    range(0x3164, 0x3165),
    range(0xFFA0, 0xFFA1),
)
_BOM = 0xFEFF
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RUN = re.compile(r"\b[0-9a-fA-F]{64,}\b")
_MIN_DECODED_CHARS = 16

_PHRASES = [
    re.compile(pattern)
    for pattern in (
        # English
        r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|your|the)\b"
        r".{0,20}\b(instructions?|prompts?|rules|guidelines|directives)\b",
        r"\byou are now\b",
        r"\byou're now\b",
        r"\bact as (an?|the)\b",
        r"\bnew (system )?instructions?\s*:",
        r"\bsystem prompt\b",
        r"\b(as|you are) an? (ai|llm|language model|assistant|code reviewer)\b",
        r"\b(ai|llm|assistant|model|reviewer|bot)\b.{0,40}\b(ignore|skip|approve|whitelist)\b",
        r"\b(do not|don't|never)\b.{0,15}\b(report|flag|mention|review|analy[sz]e)\b",
        r"\b(mark|report|rate|classify|treat)\b.{0,30}\bas\b.{0,10}\b(safe|ok|clean|benign|low|info)\b",
        r"\bthis (code|change|file|commit) (is|has been) "
        r"(safe|secure|approved|reviewed|verified)\b",
        r"\b(reveal|print|repeat|output)\b.{0,30}\b(instructions|system prompt|token|canary)\b",
        # Role or chat-template markers
        r"<\|?(im_start|im_end|system|endoftext)\|?>",
        r"\[/?inst\]",
        r"<<\s*sys\s*>>",
        r"^\s*(#+|//|/?\*+)?\s*(system|assistant)\s*:",
        # French
        r"\b(ignore|oublie|oubliez|ignorez)\b.{0,30}\b(instructions|consignes|regles|règles)\b",
        r"\b(tu es|vous etes|vous êtes) (maintenant|desormais|désormais)\b",
        r"\bne (signale|signalez|rapporte|rapportez|mentionne|mentionnez)\b.{0,10}\b(pas|rien)\b",
        r"\b(considere|considère|considérez|marque|marquez)\b.{0,30}\bcomme\b.{0,10}\b(sur|sûr|sain|valide)\b",
        # Spanish
        r"\b(ignora|ignore|olvida)\b.{0,30}\binstrucciones\b",
        r"\bahora eres\b",
        # German
        r"\b(ignoriere|vergiss)\b.{0,30}\b(anweisungen|regeln)\b",
        r"\bdu bist (jetzt|nun)\b",
    )
]
_DELIMITER = re.compile(r"untrusted_[a-z]+|nonce=", re.IGNORECASE)
_SPACES = re.compile(r"\s+")


@dataclass
class BarrierResult:
    verdict: Verdict = "ok"
    reasons: list[str] = field(default_factory=lambda: [])
    flagged: list[PatchLine] = field(default_factory=lambda: [])

    def flag(self, line: PatchLine, verdict: Verdict, reason: str) -> None:
        if VERDICT_RANK[verdict] > VERDICT_RANK[self.verdict]:
            self.verdict = verdict
        if reason not in self.reasons:
            self.reasons.append(reason)
        if line not in self.flagged:
            self.flagged.append(line)

    @property
    def lines(self) -> list[LineRef]:
        return [LineRef(file=line.path, line=max(line.line, 1)) for line in self.flagged]


def scan(diff: Diff) -> BarrierResult:
    result = BarrierResult()
    lines = patch_lines(diff)
    for change in diff.files:
        name_line = PatchLine(change.path, "+", 1, change.path)
        _scan_text(result, name_line, change.path, where="file name")
    for line in lines:
        _scan_text(result, line, line.text, where="line")
        # git splits lines on LF only; Python also ends a line at a lone CR. A CR anywhere but at
        # the end (CRLF files) lets code hide inside what git and the model see as a comment.
        if "\r" in line.text.removesuffix("\r"):
            result.flag(line, "block", "carriage return inside a line (hidden line for Python)")
    _scan_split_phrases(result, lines)
    return result


def normalize(text: str) -> str:
    """NFKC, casefold, invisible characters removed, whitespace collapsed."""
    folded = unicodedata.normalize("NFKC", text).casefold()
    visible = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")
    return _SPACES.sub(" ", visible).strip()


def addresses_an_ai(text: str) -> bool:
    normalized = normalize(text)
    return any(pattern.search(normalized) for pattern in _PHRASES)


def _scan_text(result: BarrierResult, line: PatchLine, text: str, *, where: str) -> None:
    for index, char in enumerate(text):
        code = ord(char)
        if code in _BIDI:
            result.flag(line, "block", f"bidirectional control character U+{code:04X} in a {where}")
        elif code in _TAGS:
            result.flag(line, "block", f"invisible Unicode tag character in a {where}")
        elif code == _BOM and index == 0 and line.line == 1:
            continue
        elif unicodedata.category(char) == "Cf" or any(code in r for r in _OTHER_INVISIBLE):
            result.flag(line, "suspect", f"invisible character U+{code:04X} in a {where}")
    if addresses_an_ai(text):
        result.flag(line, "suspect", f"text addressed to an AI in a {where}")
    if _DELIMITER.search(text):
        result.flag(line, "suspect", f"text imitating the review's data delimiters in a {where}")
    for decoded in _decoded_runs(text):
        reason = "encoded text that addresses an AI" if addresses_an_ai(decoded) else "encoded text"
        result.flag(line, "suspect", f"{reason} in a {where}")


def _scan_split_phrases(result: BarrierResult, lines: list[PatchLine]) -> None:
    """Instructions split across up to three consecutive lines of the same file."""
    for index in range(2, len(lines)):
        window = lines[index - 2 : index + 1]
        if len({line.path for line in window}) != 1:
            continue
        if any(addresses_an_ai(line.text) for line in window):
            continue
        if addresses_an_ai(" ".join(line.text for line in window)):
            for line in window:
                result.flag(line, "suspect", "text addressed to an AI, split across lines")


def _decoded_runs(text: str) -> list[str]:
    decoded: list[str] = []
    for match in _BASE64_RUN.finditer(text):
        candidate = match.group(0)
        try:
            raw = base64.b64decode(candidate + "=" * (-len(candidate) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        readable = _readable(raw)
        if readable is not None:
            decoded.append(readable)
    for match in _HEX_RUN.finditer(text):
        try:
            raw = bytes.fromhex(match.group(0)[: len(match.group(0)) // 2 * 2])
        except ValueError:
            continue
        readable = _readable(raw)
        if readable is not None:
            decoded.append(readable)
    return decoded


def _readable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < _MIN_DECODED_CHARS:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    return text if printable / len(text) >= 0.95 else None

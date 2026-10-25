"""Input validation: size limits, unicode normalisation, invisible-character stripping."""
from __future__ import annotations

import unicodedata

from .errors import ValidationError

# zero-width / bidi-override characters are used to hide instructions ("Trojan Source").
# ZWJ/ZWNJ (U+200D / U+200C) are kept because Hindi/Persian text legitimately needs them.
_INVISIBLE = {0x200B, 0x2060, 0xFEFF, 0x180E,
              *range(0x202A, 0x202F), *range(0x2066, 0x206A)}


def _is_invisible(ch: str) -> bool:
    cp = ord(ch)
    return cp in _INVISIBLE or 0xE0000 <= cp <= 0xE007F   # unicode "tag" characters


def strip_invisible(text: str) -> str:
    return "".join(ch for ch in text if not _is_invisible(ch))


def sanitize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text)
    return "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch) != "Cc")


def validate_input(text: object, max_chars: int) -> str:
    if not isinstance(text, str):
        raise ValidationError("input must be text")
    if len(text) > max_chars:                       # check BEFORE any heavy processing
        raise ValidationError("input too long", limit=max_chars)
    clean = sanitize(text).strip()
    if not clean:
        raise ValidationError("input is empty")
    if len(clean) >= 200 and len(set(clean)) / len(clean) < 0.02:
        raise ValidationError("input looks like a repetition/flood attack")
    return clean

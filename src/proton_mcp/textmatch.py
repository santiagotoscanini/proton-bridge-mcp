"""Client-side text matching: what search criteria mean after decoding.

Bridge's SEARCH matches raw bytes (no RFC 2047, no QP/base64), so every
text criterion is verified here instead, on decoded text, case-, accent-
and invisible-character-insensitively."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Zero-width and other invisible characters used to pad or split words.
INVISIBLE = re.compile(
    r"[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]"
)
_SPACE = re.compile(r"\s+")
_EXTRA = str.maketrans({"æ": "ae", "œ": "oe", "ø": "o", "ł": "l", "đ": "d", "ð": "d", "þ": "th", "ı": "i"})


def fold(text: str) -> str:
    """Lower-case, strip accents and invisibles, collapse whitespace."""
    text = INVISIBLE.sub("", text)
    if text.isascii():
        return _SPACE.sub(" ", text.lower()).strip()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.casefold().translate(_EXTRA)
    return _SPACE.sub(" ", text).strip()


@dataclass(frozen=True)
class TextQuery:
    """Words (all must appear) and quoted phrases (each must appear)."""

    terms: tuple[str, ...]

    @classmethod
    def parse(cls, raw: str) -> TextQuery:
        terms: list[str] = []
        for match in re.finditer(r'"([^"]*)"|(\S+)', raw):
            phrase, word = match.group(1), match.group(2)
            folded = fold(phrase if phrase is not None else word)
            if folded:
                terms.append(folded)
        return cls(tuple(terms))

    def __bool__(self) -> bool:
        return bool(self.terms)

    def matches(self, folded_haystack: str) -> bool:
        return all(term in folded_haystack for term in self.terms)

    def remaining(self, folded_haystack: str) -> TextQuery:
        """The terms this haystack does not satisfy."""
        return TextQuery(tuple(t for t in self.terms if t not in folded_haystack))

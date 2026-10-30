"""UIDPLUS response codes (RFC 4315), which imapclient leaves unparsed.

Bridge silently skips UIDs it cannot act on, so COPY/MOVE results are
read from COPYUID, and a new draft's UID from APPENDUID."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

_BRACKETED = re.compile(rb"\[(COPYUID|APPENDUID)\s+([^\]]*)\]", re.I)


@dataclass(frozen=True)
class UidCode:
    """COPYUID maps source to destination UIDs pairwise; APPENDUID has no source."""

    uidvalidity: int
    source: tuple[int, ...]
    dest: tuple[int, ...]

    def mapping(self) -> dict[int, int]:
        return dict(zip(self.source, self.dest, strict=True))


def expand(uid_set: str, limit: int = 1000) -> list[int]:
    """An explicit UID set (no '*'), refusing anything larger than limit."""
    out: list[int] = []
    for item in uid_set.split(","):
        lo, _, hi = item.partition(":")
        a, b = int(lo), int(hi or lo)
        if abs(b - a) + 1 + len(out) > limit:
            raise ValueError("UID set too large")
        out.extend(range(min(a, b), max(a, b) + 1))
    return out


def _code(name: str, fields: list[bytes]) -> UidCode | None:
    try:
        if name == "COPYUID" and len(fields) == 3:
            src, dst = expand(fields[1].decode()), expand(fields[2].decode())
            return UidCode(int(fields[0]), tuple(src), tuple(dst)) if len(src) == len(dst) else None
        if name == "APPENDUID" and len(fields) == 2:
            return UidCode(int(fields[0]), (), tuple(expand(fields[1].decode())))
    except ValueError:
        return None
    return None


def _bytes(chunk: Any) -> bytes:
    return chunk if isinstance(chunk, bytes) else str(chunk).encode("latin-1", "replace")


def find_code(name: str, untagged: Iterable[Any], tagged: Iterable[Any]) -> UidCode | None:
    """The code from either place it can be: imaplib keeps untagged codes
    under untagged_responses[name] without brackets; a tagged one stays in
    the tagged OK text."""
    name = name.upper()
    for chunk in untagged:
        if chunk:
            code = _code(name, _bytes(chunk).split())
            if code:
                return code
    for chunk in tagged:
        if not chunk:
            continue
        for m in _BRACKETED.finditer(_bytes(chunk)):
            if m.group(1).decode().upper() == name:
                code = _code(name, m.group(2).split())
                if code:
                    return code
    return None

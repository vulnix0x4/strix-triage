"""Printable-string extraction (ASCII + UTF-16LE), with light classification.

Returns a list of :class:`ExtractedString` sorted by offset. The analyzer caps
how many are kept in the report, but IOC/signature scanning runs over the full
set first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_ASCII_FMT = rb"[\x20-\x7e]{%d,}"
_UTF16_FMT = rb"(?:[\x20-\x7e]\x00){%d,}"


@dataclass
class ExtractedString:
    offset: int
    encoding: str  # "ascii" | "utf-16le"
    value: str

    def to_dict(self):
        return {"offset": self.offset, "encoding": self.encoding, "value": self.value}


def extract(data: bytes, min_len: int = 5, limit: int = 100_000) -> list[ExtractedString]:
    out: list[ExtractedString] = []
    ascii_re = re.compile(_ASCII_FMT % min_len)
    utf16_re = re.compile(_UTF16_FMT % min_len)
    for m in re.finditer(ascii_re, data):
        out.append(ExtractedString(m.start(), "ascii", m.group().decode("latin-1")))
        if len(out) >= limit:
            break
    for m in re.finditer(utf16_re, data):
        try:
            val = m.group().decode("utf-16le")
        except UnicodeDecodeError:
            continue
        out.append(ExtractedString(m.start(), "utf-16le", val))
        if len(out) >= limit:
            break
    out.sort(key=lambda s: s.offset)
    return out

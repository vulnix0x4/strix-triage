"""Shannon entropy helpers used for packing / encryption detection."""

from __future__ import annotations

import math
from typing import Iterable


def shannon(data: bytes) -> float:
    """Shannon entropy in bits/byte (0.0 .. 8.0)."""

    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def classify(entropy: float) -> str:
    """Human label for an entropy value."""

    if entropy >= 7.2:
        return "packed/encrypted"
    if entropy >= 6.5:
        return "compressed/high"
    if entropy >= 4.5:
        return "code/mixed"
    return "low/plaintext"


def windows(data: bytes, size: int = 4096) -> Iterable[tuple[int, float]]:
    """Yield ``(offset, entropy)`` for fixed windows — flags localized blobs
    (e.g. an encrypted config) inside an otherwise normal file."""

    for off in range(0, len(data), size):
        chunk = data[off : off + size]
        if chunk:
            yield off, shannon(chunk)

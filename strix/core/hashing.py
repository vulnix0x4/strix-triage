"""Cryptographic and fuzzy hashing.

The standard digests are always available. ``imphash`` (import-table hash,
pefile-compatible) is computed from parsed PE imports. A self-contained fuzzy
hash is implemented so similarity clustering works without the optional
``ssdeep`` C library; if ``ssdeep`` is installed we expose it too.
"""

from __future__ import annotations

import hashlib
from typing import Optional

_CHUNK = 1 << 20  # 1 MiB


def file_digests(path: str) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def imphash(import_names: list[str]) -> Optional[str]:
    """pefile-compatible import hash.

    Each imported symbol is normalised to ``dll.function`` lowercase, ordinals
    rendered as ``dll.ordNNN``, joined by commas and MD5'd. ``import_names`` is
    expected pre-formatted as ``dll.func`` entries in import-table order.
    """

    if not import_names:
        return None
    normalized = []
    for name in import_names:
        n = name.lower()
        for ext in (".dll", ".sys", ".ocx", ".exe"):
            if "." in n:
                dll, _, func = n.partition(".")
                if dll.endswith(ext):
                    dll = dll[: -len(ext)]
                n = f"{dll}.{func}"
                break
        normalized.append(n)
    return hashlib.md5(",".join(normalized).encode()).hexdigest()


# --- self-contained fuzzy hash (CTPH-style, ssdeep spirit) -----------------
# This is a rolling-window piecewise hash. It is NOT ssdeep-compatible, but it
# clusters similar files consistently within a Strix corpus. For cross-tool
# comparison, install the optional ``ssdeep`` extra.

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_WINDOW = 7


def _roll(data: bytes) -> list[int]:
    h1 = h2 = h3 = 0
    out = []
    win = bytearray(_WINDOW)
    for i, b in enumerate(data):
        h2 -= h1
        h2 += _WINDOW * b
        h1 += b
        h1 -= win[i % _WINDOW]
        win[i % _WINDOW] = b
        h3 = ((h3 << 5) & 0xFFFFFFFF) ^ b
        out.append((h1 + h2 + h3) & 0xFFFFFFFF)
    return out


def fuzzy_hash(data: bytes) -> str:
    """Context-triggered piecewise hash. Returns ``block:hash:hash``."""

    if not data:
        return "3:::"
    # block size scales with input so the digest stays bounded
    block = 3
    while block * 64 < len(data):
        block *= 2
    rolls = _roll(data)
    trigger = block - 1

    def _digest(bsize: int) -> str:
        acc = 0
        sig = []
        for i, b in enumerate(data):
            acc = (acc * 131 + b) & 0xFFFFFFFF
            if rolls[i] % bsize == trigger % bsize or i == len(data) - 1:
                sig.append(_B64[acc % 64])
                acc = 0
        return "".join(sig)

    return f"{block}:{_digest(block)}:{_digest(block * 2)}"


def fuzzy_compare(a: str, b: str) -> int:
    """Rough 0-100 similarity between two :func:`fuzzy_hash` digests."""

    try:
        _, a1, a2 = a.split(":", 2)
        _, b1, b2 = b.split(":", 2)
    except ValueError:
        return 0
    best = 0
    for x, y in ((a1, b1), (a1, b2), (a2, b1), (a2, b2)):
        best = max(best, _lcs_ratio(x, y))
    return best


def _lcs_ratio(a: str, b: str) -> int:
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    for ca in a:
        cur = [0]
        for j, cb in enumerate(b, 1):
            cur.append(prev[j - 1] + 1 if ca == cb else max(prev[j], cur[j - 1]))
        prev = cur
    return int(100 * prev[-1] / max(len(a), len(b)))

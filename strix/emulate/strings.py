"""Emulation-based string recovery (FLOSS-style, fully sandboxed).

Finds candidate decode routines (the entry point and the targets of ``call``
instructions), emulates each one in an *isolated* memory image with a hard step
budget, and harvests the bytes those routines write. Printable runs that are
written at "run time" but are *not* already visible as static strings are the
decoded/obfuscated strings an analyst actually wants — stack strings and
self-contained XOR/ROL decryptors both fall out of this with no knowledge of
the algorithm.

No OS, no syscalls, no I/O: see ``strix.emulate.engine`` for the sandbox
invariants.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..disasm import disassemble
from ..disasm.model import OpKind
from .engine import AddressSpace, Emulator

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
_PRINTABLE_W = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


@dataclass
class Recovered:
    value: str
    address: int
    via: str          # entry point VA the routine was reached from
    encoding: str = "ascii"

    def to_dict(self):
        return {"value": self.value, "address": hex(self.address),
                "via": hex(self.via), "encoding": self.encoding}


def find_function_starts(segments, entry_points, cap: int = 96) -> list[int]:
    """Entry point(s) plus intra-image ``call`` targets, de-duplicated."""
    starts: list[int] = []
    seen = set()

    def add(a):
        if a not in seen:
            seen.add(a)
            starts.append(a)

    for ep in entry_points:
        add(ep)
    ranges = [(va, va + len(b)) for va, b in segments]
    for va, body in segments:
        for ins in disassemble(body, addr=va, max_insns=20000):
            if ins.mnemonic == "call" and ins.target is not None:
                t = ins.target
                if any(lo <= t < hi for lo, hi in ranges):
                    add(t)
            if len(starts) >= cap:
                return starts
    return starts[:cap]


def _build_space(segments) -> AddressSpace:
    sp = AddressSpace()
    for va, body in segments:
        sp.map_bytes(va, bytes(body))
    return sp


def _harvest(writes: dict, min_len: int) -> list[tuple[int, str, str]]:
    if not writes:
        return []
    addrs = sorted(writes)
    out: list[tuple[int, str, str]] = []
    # group writes into contiguous runs
    run_start = addrs[0]
    buf = bytearray([writes[run_start]])
    def flush(start, data):
        for m in re.finditer(_PRINTABLE, data):
            out.append((start + m.start(), m.group().decode("latin-1"), "ascii"))
        for m in re.finditer(_PRINTABLE_W, data):
            try:
                out.append((start + m.start(), m.group().decode("utf-16le"), "utf-16le"))
            except UnicodeDecodeError:
                pass
    for a in addrs[1:]:
        if a == run_start + len(buf):
            buf.append(writes[a])
        else:
            flush(run_start, bytes(buf))
            run_start = a
            buf = bytearray([writes[a]])
    flush(run_start, bytes(buf))
    return [(addr, s, enc) for addr, s, enc in out if len(s) >= min_len]


def recover_strings(segments, entry_points, static_strings,
                    max_funcs: int = 96, max_steps: int = 60_000,
                    min_len: int = 4, total_step_budget: int = 3_000_000) -> list[Recovered]:
    """Return decoded strings not already visible statically.

    ``segments`` = list of ``(vaddr, bytes)``. ``static_strings`` = iterable of
    strings already recovered without emulation (used to suppress duplicates).
    """

    static_blob = "\n".join(static_strings)
    starts = find_function_starts(segments, entry_points, cap=max_funcs)
    found: dict[str, Recovered] = {}
    spent = 0
    for ep in starts:
        if spent >= total_step_budget:
            break
        space = _build_space(segments)
        emu = Emulator(space, max_steps=max_steps)
        try:
            emu.run(ep)
        except Exception:
            pass
        spent += emu.steps
        for addr, s, enc in _harvest(space.writes, min_len):
            s = s.strip()
            if len(s) < min_len:
                continue
            if s in static_blob:          # already visible statically
                continue
            if s not in found:
                found[s] = Recovered(value=s, address=addr, via=ep, encoding=enc)
    # drop strings that are just fragments of a longer recovered one
    values = sorted(found, key=len, reverse=True)
    kept: list[str] = []
    for v in values:
        if not any(v != k and v in k for k in kept):
            kept.append(v)
    return [found[v] for v in kept]

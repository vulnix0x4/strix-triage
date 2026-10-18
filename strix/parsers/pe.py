"""Pure-Python PE (Portable Executable) parser.

Parses enough of the PE for triage: COFF + optional header, sections, the
import and export directories, data-directory presence (resources, TLS,
relocations, debug, security/Authenticode), and structural anomalies
(entry point outside a section, raw/virtual size mismatch, overlay data,
abnormal section names/permissions). Deliberately tolerant — malformed PEs
are the norm in malware, so every field read is bounds-checked and failures
degrade to recorded anomalies rather than exceptions.
"""

from __future__ import annotations

import struct
from typing import Optional

from ..core.entropy import shannon
from .base import ParsedBinary, ParsedSection

MACHINE = {
    0x014C: "x86",
    0x0200: "ia64",
    0x8664: "x86-64",
    0x01C0: "arm",
    0xAA64: "arm64",
    0x01C4: "armnt",
    0x0EBC: "efi-byte-code",
}

SUBSYSTEM = {
    0: "unknown", 1: "native", 2: "gui", 3: "console", 5: "os2",
    7: "posix", 9: "windows-ce", 10: "efi-application", 12: "efi-rom",
    14: "xbox", 16: "boot-application",
}

# File header Characteristics
FILE_CHARS = [
    (0x0002, "executable"), (0x0020, "large-address-aware"),
    (0x2000, "dll"), (0x0100, "32bit-machine"), (0x1000, "system"),
    (0x0001, "relocs-stripped"), (0x0004, "line-nums-stripped"),
]

# DllCharacteristics (mitigations / flags)
DLL_CHARS = [
    (0x0020, "high-entropy-va"), (0x0040, "dynamic-base-aslr"),
    (0x0080, "force-integrity"), (0x0100, "nx-compat-dep"),
    (0x0200, "no-isolation"), (0x0400, "no-seh"), (0x0800, "no-bind"),
    (0x1000, "appcontainer"), (0x2000, "wdm-driver"),
    (0x4000, "control-flow-guard"), (0x8000, "terminal-server-aware"),
]

# Section Characteristics
SEC_CHARS = [
    (0x00000020, "code"), (0x00000040, "initialized-data"),
    (0x00000080, "uninitialized-data"), (0x02000000, "discardable"),
    (0x10000000, "shared"), (0x20000000, "execute"),
    (0x40000000, "read"), (0x80000000, "write"),
]

DATA_DIR_NAMES = [
    "export", "import", "resource", "exception", "security", "basereloc",
    "debug", "architecture", "globalptr", "tls", "load-config",
    "bound-import", "iat", "delay-import", "clr-runtime", "reserved",
]


class _Reader:
    __slots__ = ("d", "n")

    def __init__(self, data: bytes):
        self.d = data
        self.n = len(data)

    def u(self, fmt: str, off: int):
        size = struct.calcsize(fmt)
        if off < 0 or off + size > self.n:
            raise ValueError(f"read {fmt} at {off:#x} out of bounds")
        return struct.unpack_from(fmt, self.d, off)

    def cstr(self, off: int, limit: int = 256) -> str:
        end = self.d.find(b"\x00", off, off + limit)
        if end < 0:
            end = min(off + limit, self.n)
        return self.d[off:end].decode("latin-1", "replace")


def is_pe(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    try:
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    except struct.error:
        return False
    return 0 < e_lfanew < len(data) - 4 and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"


def parse(data: bytes) -> ParsedBinary:
    r = _Reader(data)
    pb = ParsedBinary(format="pe")
    try:
        (e_lfanew,) = r.u("<I", 0x3C)
    except ValueError:
        pb.anomalies.append("truncated DOS header")
        return pb

    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        pb.anomalies.append("missing PE signature (DOS stub only)")
        return pb

    coff = e_lfanew + 4
    machine, nsec, timestamp, _psym, _nsym, opt_size, chars = r.u("<HHIIIHH", coff)
    pb.arch = MACHINE.get(machine, f"machine:{machine:#06x}")
    pb.timestamp = timestamp
    pb.characteristics = [name for bit, name in FILE_CHARS if chars & bit]
    pb.is_dll = bool(chars & 0x2000)
    pb.is_executable = bool(chars & 0x0002)

    opt = coff + 20
    data_dirs: list[tuple[int, int]] = []
    if opt_size and opt + 2 <= r.n:
        (magic,) = r.u("<H", opt)
        is_plus = magic == 0x20B
        pb.bits = 64 if is_plus else 32
        pb.extra["pe_magic"] = {0x10B: "PE32", 0x20B: "PE32+", 0x107: "ROM"}.get(magic, hex(magic))
        try:
            if is_plus:
                (entry,) = r.u("<I", opt + 16)
                (image_base,) = r.u("<Q", opt + 24)
                (subsystem,) = r.u("<H", opt + 68)
                (dllchars,) = r.u("<H", opt + 70)
                (nrva,) = r.u("<I", opt + 108)
                dd_off = opt + 112
            else:
                (entry,) = r.u("<I", opt + 16)
                (image_base,) = r.u("<I", opt + 28)
                (subsystem,) = r.u("<H", opt + 68)
                (dllchars,) = r.u("<H", opt + 70)
                (nrva,) = r.u("<I", opt + 92)
                dd_off = opt + 96
            pb.entry_point = entry
            pb.subsystem = SUBSYSTEM.get(subsystem, f"subsystem:{subsystem}")
            pb.extra["image_base"] = image_base
            pb.extra["dll_characteristics"] = [n for b, n in DLL_CHARS if dllchars & b]
            nrva = min(nrva, 16)
            for i in range(nrva):
                rva, sz = r.u("<II", dd_off + i * 8)
                data_dirs.append((rva, sz))
        except ValueError:
            pb.anomalies.append("truncated optional header")
    else:
        pb.anomalies.append("missing optional header")

    # --- sections ---------------------------------------------------------
    sec_off = opt + opt_size
    sections: list[tuple[str, int, int, int, int, int]] = []
    if nsec > 96:
        pb.anomalies.append(f"absurd section count ({nsec})")
        nsec = min(nsec, 96)
    for i in range(nsec):
        base = sec_off + i * 40
        try:
            raw_name = r.d[base : base + 8]
            vsize, vaddr, rsize, rptr = r.u("<IIII", base + 8)
            (sc,) = r.u("<I", base + 36)
        except ValueError:
            pb.anomalies.append("truncated section table")
            break
        name = raw_name.rstrip(b"\x00").decode("latin-1", "replace") or f"sect{i}"
        body = r.d[rptr : rptr + rsize] if 0 < rsize and rptr < r.n else b""
        ps = ParsedSection(
            name=name, vaddr=vaddr, vsize=vsize, raw_size=rsize, offset=rptr,
            entropy=round(shannon(body), 3),
            characteristics=[n for b, n in SEC_CHARS if sc & b],
        )
        pb.sections.append(ps)
        sections.append((name, vaddr, vsize, rptr, rsize, sc))
        # per-section anomalies
        if vsize and rsize and rsize > vsize * 4 and rsize > 0x1000:
            pb.anomalies.append(f"section {name!r} raw size >> virtual size (possible padding/overlay)")
        if ("write" in ps.characteristics and "execute" in ps.characteristics):
            pb.anomalies.append(f"section {name!r} is writable AND executable (W^X violation)")
        if ps.entropy >= 7.2 and rsize > 0x400:
            pb.anomalies.append(f"section {name!r} high entropy {ps.entropy} (packed/encrypted)")

    def rva_to_off(rva: int) -> Optional[int]:
        for _name, va, vs, rp, rs, _sc in sections:
            if va <= rva < va + max(vs, rs):
                delta = rva - va
                if delta < rs:
                    return rp + delta
        return None

    # entry point sanity
    if pb.entry_point and sections:
        if rva_to_off(pb.entry_point) is None:
            pb.anomalies.append(f"entry point RVA {pb.entry_point:#x} not inside any section")
        else:
            for name, va, vs, _rp, _rs, sc in sections:
                if va <= pb.entry_point < va + max(vs, 1) and not (sc & 0x20000000):
                    pb.anomalies.append(f"entry point in non-executable section {name!r}")

    # --- imports ----------------------------------------------------------
    if len(data_dirs) > 1 and data_dirs[1][0]:
        _parse_imports(r, pb, data_dirs[1][0], rva_to_off, pb.bits == 64)
    if len(data_dirs) > 13 and data_dirs[13][0]:
        _parse_imports(r, pb, data_dirs[13][0], rva_to_off, pb.bits == 64, delay=True)

    # --- exports ----------------------------------------------------------
    if len(data_dirs) > 0 and data_dirs[0][0]:
        _parse_exports(r, pb, data_dirs[0][0], rva_to_off)

    # --- data directory presence -----------------------------------------
    present = {}
    for i, (rva, sz) in enumerate(data_dirs):
        if rva and i < len(DATA_DIR_NAMES):
            present[DATA_DIR_NAMES[i]] = {"rva": rva, "size": sz}
    pb.extra["data_directories"] = present
    pb.extra["has_tls_callbacks"] = "tls" in present
    pb.extra["signed"] = "security" in present
    pb.extra["aslr"] = "dynamic-base-aslr" in pb.extra.get("dll_characteristics", [])
    pb.extra["dep"] = "nx-compat-dep" in pb.extra.get("dll_characteristics", [])

    # --- overlay ----------------------------------------------------------
    end_of_last = max((rp + rs for _n, _va, _vs, rp, rs, _sc in sections), default=0)
    if end_of_last and r.n > end_of_last:
        overlay = r.n - end_of_last
        pb.extra["overlay_size"] = overlay
        if overlay > 1024:
            pb.anomalies.append(f"{overlay} bytes of overlay data appended after last section")

    if timestamp == 0:
        pb.anomalies.append("zero compile timestamp (stripped/anti-forensic)")
    elif timestamp > 2000000000:  # ~2033; often a forged/future timestamp
        pb.anomalies.append(f"implausible compile timestamp ({timestamp})")

    return pb


def _parse_imports(r: _Reader, pb: ParsedBinary, dir_rva: int, rva_to_off, is64: bool, delay=False):
    off = r.n and _safe(rva_to_off, dir_rva)
    if off is None:
        return
    ordinal_flag = 0x8000000000000000 if is64 else 0x80000000
    ptr = struct.calcsize("<Q") if is64 else struct.calcsize("<I")
    entry_size = 20
    name_field = 12 if not delay else 4  # delay descriptor: name at +4
    count = 0
    seen_dlls = set()
    while count < 4096:
        base = off + count * entry_size
        try:
            if delay:
                _attrs, name_rva, _mod, _iat, int_rva = r.u("<IIIII", base)
                orig_thunk = int_rva
            else:
                orig_thunk, _ts, _fw, name_rva, iat = r.u("<IIIII", base)
        except ValueError:
            break
        if name_rva == 0 and orig_thunk == 0:
            break
        count += 1
        dll_off = _safe(rva_to_off, name_rva)
        dll = r.cstr(dll_off).lower() if dll_off is not None else f"rva_{name_rva:#x}"
        if dll in seen_dlls and dll.startswith("rva_"):
            break
        seen_dlls.add(dll)
        thunk_rva = orig_thunk or (iat if not delay else 0)
        funcs = _read_thunks(r, thunk_rva, rva_to_off, ordinal_flag, ptr, is64)
        bucket = pb.imported_libs.setdefault(dll, [])
        for fn in funcs:
            bucket.append(fn)
            pb.imports.append(f"{dll}.{fn}" if not fn.startswith("ord#") else f"{dll}.{fn}")
    if delay and seen_dlls:
        pb.extra["delay_imports"] = sorted(seen_dlls)


def _read_thunks(r, thunk_rva, rva_to_off, ordinal_flag, ptr, is64) -> list[str]:
    funcs: list[str] = []
    toff = _safe(rva_to_off, thunk_rva)
    if toff is None:
        return funcs
    fmt = "<Q" if is64 else "<I"
    i = 0
    while i < 8192:
        try:
            (val,) = r.u(fmt, toff + i * ptr)
        except ValueError:
            break
        if val == 0:
            break
        if val & ordinal_flag:
            funcs.append(f"ord#{val & 0xFFFF}")
        else:
            noff = _safe(rva_to_off, val & 0x7FFFFFFF)
            if noff is not None:
                funcs.append(r.cstr(noff + 2))  # skip Hint word
        i += 1
    return funcs


def _parse_exports(r: _Reader, pb: ParsedBinary, dir_rva: int, rva_to_off):
    off = _safe(rva_to_off, dir_rva)
    if off is None:
        return
    try:
        (_flags, _ts, _maj, _min, name_rva, _ord_base,
         _naddr, nnames, _addr_rva, names_rva, _ord_rva) = r.u("<IIHHIIIIIII", off)
    except ValueError:
        return
    dll_off = _safe(rva_to_off, name_rva)
    if dll_off is not None:
        pb.extra["export_dll_name"] = r.cstr(dll_off)
    names_off = _safe(rva_to_off, names_rva)
    if names_off is None:
        return
    for i in range(min(nnames, 8192)):
        try:
            (nrva,) = r.u("<I", names_off + i * 4)
        except ValueError:
            break
        noff = _safe(rva_to_off, nrva)
        if noff is not None:
            pb.exports.append(r.cstr(noff))


def _safe(fn, rva):
    try:
        return fn(rva)
    except Exception:
        return None

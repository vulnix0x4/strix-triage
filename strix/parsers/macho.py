"""Pure-Python Mach-O parser (thin + fat/universal, 32/64-bit).

Extracts arch, load commands, segments/sections with entropy, linked dylibs,
and imported symbols from the symbol table. Flags RWX segments, missing code
signature, and encrypted segments (LC_ENCRYPTION_INFO).
"""

from __future__ import annotations

import struct

from ..core.entropy import shannon
from .base import ParsedBinary, ParsedSection

CPU = {7: "x86", 0x01000007: "x86-64", 12: "arm", 0x0100000C: "arm64", 18: "ppc"}
FILETYPE = {1: "object", 2: "executable", 3: "fvmlib", 4: "core",
            5: "preload", 6: "dylib", 7: "dylinker", 8: "bundle"}

LC_SEGMENT, LC_SEGMENT_64 = 0x01, 0x19
LC_LOAD_DYLIB, LC_SYMTAB = 0x0C, 0x02
LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64 = 0x21, 0x2C
LC_CODE_SIGNATURE = 0x1D

# The magic is always read big-endian (">I"). A result of 0xFEEDFAC* means the
# file's byte order matches that read (big-endian file); the swapped CIGAM
# values (0x*EDFE) mean a little-endian file.
_MAGICS = {
    0xFEEDFACE: (">", False), 0xFEEDFACF: (">", True),
    0xCEFAEDFE: ("<", False), 0xCFFAEDFE: ("<", True),
}


def is_macho(data: bytes) -> bool:
    if len(data) < 4:
        return False
    m = struct.unpack_from(">I", data, 0)[0]
    return m in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA)


def parse(data: bytes) -> ParsedBinary:
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (0xCAFEBABE, 0xBEBAFECA):
        return _parse_fat(data)
    return _parse_thin(data, 0)


def _parse_fat(data: bytes) -> ParsedBinary:
    pb = ParsedBinary(format="macho")
    try:
        nfat = struct.unpack_from(">I", data, 4)[0]
    except struct.error:
        pb.anomalies.append("truncated fat header")
        return pb
    pb.extra["universal"] = True
    arches = []
    first = None
    for i in range(min(nfat, 32)):
        base = 8 + i * 20
        try:
            cputype, _sub, offset, _size, _align = struct.unpack_from(">IIIII", data, base)
        except struct.error:
            break
        arches.append(CPU.get(cputype, hex(cputype)))
        if first is None and offset < len(data):
            first = offset
    pb.extra["fat_arches"] = arches
    if first is not None:
        inner = _parse_thin(data, first)
        inner.extra["universal"] = True
        inner.extra["fat_arches"] = arches
        return inner
    pb.arch = "+".join(arches)
    return pb


def _parse_thin(data: bytes, base: int) -> ParsedBinary:
    pb = ParsedBinary(format="macho")
    try:
        magic = struct.unpack_from(">I", data, base)[0]
    except struct.error:
        pb.anomalies.append("truncated Mach-O header")
        return pb
    en, is64 = _MAGICS.get(magic, ("<", True))
    pb.bits = 64 if is64 else 32
    pb.endian = "little" if en == "<" else "big"
    hdr = en + ("IIIIIII" if not is64 else "IIIIIIII")
    try:
        vals = struct.unpack_from(hdr, data, base)
    except struct.error:
        pb.anomalies.append("malformed Mach-O header")
        return pb
    _m, cputype, _sub, filetype, ncmds, _sizeofcmds, _flags = vals[:7]
    pb.arch = CPU.get(cputype, hex(cputype))
    pb.extra["filetype"] = FILETYPE.get(filetype, str(filetype))
    pb.is_dll = filetype == 6
    pb.is_executable = filetype in (2, 6, 8)

    off = base + (32 if is64 else 28)
    dylibs: list[str] = []
    symtab = None
    has_sig = False
    for _ in range(min(ncmds, 4096)):
        try:
            cmd, cmdsize = struct.unpack_from(en + "II", data, off)
        except struct.error:
            break
        if cmdsize == 0:
            break
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            _read_segment(data, off, en, cmd == LC_SEGMENT_64, pb, base)
        elif cmd == LC_LOAD_DYLIB:
            (nameoff,) = struct.unpack_from(en + "I", data, off + 8)
            p = off + nameoff
            end = data.find(b"\x00", p, off + cmdsize)
            if 0 <= p < len(data) and end > 0:
                dylibs.append(data[p:end].decode("latin-1", "replace"))
        elif cmd == LC_SYMTAB:
            symtab = struct.unpack_from(en + "IIII", data, off + 8)  # symoff,nsyms,stroff,strsize
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            try:
                _co, _cs, cryptid = struct.unpack_from(en + "III", data, off + 8)
                if cryptid != 0:
                    pb.anomalies.append("encrypted segment (LC_ENCRYPTION_INFO, cryptid!=0)")
            except struct.error:
                pass
        elif cmd == LC_CODE_SIGNATURE:
            has_sig = True
        off += cmdsize

    pb.extra["linked_dylibs"] = dylibs
    pb.extra["code_signed"] = has_sig
    if not has_sig and pb.is_executable:
        pb.anomalies.append("no LC_CODE_SIGNATURE (unsigned Mach-O)")

    if symtab:
        _read_symbols(data, symtab, en, is64, dylibs, pb, base)
    return pb


def _read_segment(data, off, en, is64, pb: ParsedBinary, base: int = 0):
    try:
        if is64:
            name = data[off + 8 : off + 24].rstrip(b"\x00").decode("latin-1", "replace")
            _vmaddr, _vmsize, fileoff, filesize, maxprot, initprot, nsects = struct.unpack_from(
                en + "QQQQIII", data, off + 24)
            sect_base = off + 72
            sect_size = 80
        else:
            name = data[off + 8 : off + 24].rstrip(b"\x00").decode("latin-1", "replace")
            _vmaddr, _vmsize, fileoff, filesize, maxprot, initprot, nsects = struct.unpack_from(
                en + "IIIIIII", data, off + 24)
            sect_base = off + 56
            sect_size = 68
    except struct.error:
        return
    prot = [p for p, bit in (("read", 1), ("write", 2), ("execute", 4)) if initprot & bit]
    fileoff += base  # fat-slice file offsets are relative to the slice start
    body = data[fileoff : fileoff + filesize] if filesize else b""
    pb.sections.append(ParsedSection(
        name=name or "<seg>", offset=fileoff, raw_size=filesize, vaddr=_vmaddr,
        entropy=round(shannon(body), 3), characteristics=prot))
    if "write" in prot and "execute" in prot:
        pb.anomalies.append(f"segment {name!r} is writable AND executable (RWX)")
    # named sections inside the segment
    for i in range(min(nsects, 256)):
        b = sect_base + i * sect_size
        try:
            sn = data[b : b + 16].rstrip(b"\x00").decode("latin-1", "replace")
        except Exception:
            break
        if sn and name:
            pb.sections.append(ParsedSection(name=f"{name},{sn}", characteristics=prot))


def _read_symbols(data, symtab, en, is64, dylibs, pb: ParsedBinary, base: int = 0):
    symoff, nsyms, stroff, strsize = symtab
    symoff += base  # relative to slice start
    stroff += base
    nlist = 16 if is64 else 12
    lib_hint = dylibs[0].split("/")[-1] if dylibs else "dylib"
    for i in range(min(nsyms, 16384)):
        b = symoff + i * nlist
        try:
            n_strx, n_type = struct.unpack_from(en + "IB", data, b)
        except struct.error:
            break
        # undefined (imported) symbols: (n_type & 0x0e)==0 (N_UNDF)
        if n_type & 0x0E:
            continue
        p = stroff + n_strx
        end = data.find(b"\x00", p, stroff + strsize)
        if p < len(data) and end > 0:
            name = data[p:end].decode("latin-1", "replace").lstrip("_")
            if name:
                pb.imports.append(f"{lib_hint}.{name}")
                pb.imported_libs.setdefault(lib_hint, []).append(name)

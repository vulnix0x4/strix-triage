"""Pure-Python ELF parser (32/64-bit, LE/BE).

Extracts machine/type, section headers with entropy, and dynamic-symbol
imports from ``.dynsym``/``.dynstr`` so Linux capability mapping works. Also
flags common anomalies: no section headers (stripped/packed), RWX segments,
and packer section names.
"""

from __future__ import annotations

import struct

from ..core.entropy import shannon
from .base import ParsedBinary, ParsedSection

ET = {0: "none", 1: "relocatable", 2: "executable", 3: "shared-object(.so/pie)", 4: "core"}
EM = {
    0x03: "x86", 0x3E: "x86-64", 0x28: "arm", 0xB7: "arm64",
    0x08: "mips", 0x14: "ppc", 0x15: "ppc64", 0xF3: "riscv", 0x02: "sparc",
}
SHT_DYNSYM, SHT_STRTAB, SHT_DYNAMIC = 11, 3, 6


def is_elf(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def parse(data: bytes) -> ParsedBinary:
    pb = ParsedBinary(format="elf")
    if len(data) < 0x40:
        pb.anomalies.append("truncated ELF header")
        return pb
    ei_class, ei_data = data[4], data[5]
    is64 = ei_class == 2
    pb.bits = 64 if is64 else 32
    en = "<" if ei_data == 1 else ">"
    pb.endian = "little" if ei_data == 1 else "big"

    try:
        if is64:
            e_type, e_machine, _ver, e_entry, _phoff, e_shoff = struct.unpack_from(
                en + "HHIQQQ", data, 16)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(en + "HHH", data, 58)
        else:
            e_type, e_machine, _ver, e_entry, _phoff, e_shoff = struct.unpack_from(
                en + "HHIIII", data, 16)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(en + "HHH", data, 46)
    except struct.error:
        pb.anomalies.append("malformed ELF header")
        return pb

    pb.arch = EM.get(e_machine, f"machine:{e_machine:#x}")
    pb.entry_point = e_entry
    pb.is_dll = e_type == 3
    pb.is_executable = e_type in (2, 3)
    pb.extra["elf_type"] = ET.get(e_type, str(e_type))

    if e_shnum == 0 or e_shoff == 0:
        pb.anomalies.append("no section headers (stripped or packed — common in UPX/malware droppers)")
        return pb
    if e_shnum > 4096:
        pb.anomalies.append(f"absurd section count ({e_shnum})")
        return pb

    # read section headers
    secs = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        try:
            if is64:
                nameoff, stype, flags, _addr, offset, size = struct.unpack_from(en + "IIQQQQ", data, base)
                link = struct.unpack_from(en + "I", data, base + 40)[0]
            else:
                nameoff, stype, flags, _addr, offset, size = struct.unpack_from(en + "IIIIII", data, base)
                link = struct.unpack_from(en + "I", data, base + 24)[0]
        except struct.error:
            pb.anomalies.append("truncated section table")
            break
        secs.append((nameoff, stype, flags, offset, size, link))

    # section-header string table
    shstr_off = secs[e_shstrndx][3] if e_shstrndx < len(secs) else 0

    def sname(nameoff):
        p = shstr_off + nameoff
        end = data.find(b"\x00", p)
        return data[p:end].decode("latin-1", "replace") if 0 <= p < len(data) and end > 0 else ""

    dynsym = dynstr = None
    for nameoff, stype, flags, offset, size, link in secs:
        nm = sname(nameoff)
        body = data[offset : offset + size] if stype != 8 and size else b""  # skip NOBITS
        pb.sections.append(ParsedSection(
            name=nm or "<unnamed>", offset=offset, raw_size=size,
            entropy=round(shannon(body), 3),
            characteristics=[c for c, bit in (("write", 1), ("alloc", 2), ("execute", 4)) if flags & bit],
        ))
        if (flags & 1) and (flags & 4):
            pb.anomalies.append(f"section {nm!r} is writable AND executable (RWX)")
        if nm in (".dynsym",):
            dynsym = (offset, size, link)
        if nm == ".dynstr":
            dynstr = (offset, size)
        if nm.startswith("UPX") or nm in (".packed",):
            pb.anomalies.append(f"packer artifact section {nm!r}")

    # dynamic symbol imports
    if dynsym and dynstr:
        off, size, _link = dynsym
        str_off, str_size = dynstr
        sym_sz = 24 if is64 else 16
        for i in range(size // sym_sz):
            b = off + i * sym_sz
            try:
                if is64:
                    st_name, st_info, _o, st_shndx = struct.unpack_from(en + "IBBH", data, b)
                else:
                    st_name, _val, _sz, st_info, _o, st_shndx = struct.unpack_from(en + "IIIBBH", data, b)
            except struct.error:
                break
            if st_name == 0 or st_shndx != 0:  # SHN_UNDEF (0) == imported
                continue
            p = str_off + st_name
            end = data.find(b"\x00", p, str_off + str_size)
            if p < len(data) and end > 0:
                fn = data[p:end].decode("latin-1", "replace")
                if fn:
                    pb.imports.append(f"libc.{fn}")
                    pb.imported_libs.setdefault("libc", []).append(fn)
    return pb

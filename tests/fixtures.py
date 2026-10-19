"""Synthetic, INERT binary fixtures for testing Strix.

These builders emit files that *statically look like* malware — a valid PE
header, an import table naming injection APIs, a high-entropy section, and
ransom-note / C2 strings — but contain **no executable logic whatsoever**.
The ``.text`` section is filler bytes; nothing here can run. They exist purely
so the analyzer and detection rules can be exercised deterministically on a
machine that (correctly) has no real malware lying around.
"""

from __future__ import annotations

import os
import struct

IMAGE_FILE_MACHINE_AMD64 = 0x8664
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def stackstring_code(secret: bytes, base_disp: int = -0x80) -> bytes:
    """Emit inert x86-64 that builds ``secret`` byte-by-byte on the stack.

    This is the 'stack string' obfuscation that defeats static string
    extraction — the bytes never exist contiguously in the file. It touches
    only the stack (rbp-relative), so it decodes identically regardless of
    image base. It performs no I/O and simply returns.
    """
    assert base_disp + len(secret) < 0x7F, "secret too long for disp8 stub"
    code = bytearray()
    code += bytes([0x55])                               # push rbp
    code += bytes([0x48, 0x89, 0xE5])                   # mov rbp, rsp
    code += bytes([0x48, 0x81, 0xEC, 0x00, 0x01, 0, 0])  # sub rsp, 0x100
    for i, ch in enumerate(secret):
        code += bytes([0xC6, 0x45, (base_disp + i) & 0xFF, ch])   # mov byte [rbp+d8], ch
    code += bytes([0xC6, 0x45, (base_disp + len(secret)) & 0xFF, 0x00])  # null term
    code += bytes([0x48, 0x89, 0xEC])                   # mov rsp, rbp
    code += bytes([0x5D])                               # pop rbp
    code += bytes([0xC3])                               # ret
    return bytes(code)


def make_suspicious_pe(
    imports=(
        ("kernel32.dll", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                           "GetProcAddress", "LoadLibraryA"]),
        ("wininet.dll", ["InternetOpenA", "InternetReadFile", "URLDownloadToFileA"]),
    ),
    strings=(
        b"vssadmin delete shadows /all /quiet",
        b"Your files have been encrypted! To decrypt your files send bitcoin.",
        b"bitcoin wallet: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
        b"http://malicious-c2-sample.top/gate.php",
        b"http://abcdefghij234567qrstuv.onion/panel",
        b"powershell -nop -w hidden -enc SQBFAFgAKA==",
        b"SELECT * FROM AntiVirusProduct",
        b"VMwareService.exe  VBoxService.exe  sandboxie",
        b"ReflectiveLoader",
    ),
    high_entropy_bytes: int = 4096,
    text_code: bytes = b"\xcc" * 64,
) -> bytes:
    """Build an inert PE32+ specimen with suspicious static features."""

    # ---- build .rdata (imports + strings) in RVA space -------------------
    rdata_rva = 0x2000
    rd = bytearray()

    # reserve space for Import Descriptors (one per dll + null terminator)
    n = len(imports)
    idt_size = (n + 1) * 20
    idt_off = 0
    rd += b"\x00" * idt_size
    cursor = idt_size

    def put(data: bytes) -> int:
        nonlocal cursor
        off = cursor
        rd.extend(data)
        cursor += len(data)
        return off

    descriptors = []
    for dll, funcs in imports:
        # IMAGE_IMPORT_BY_NAME entries: hint(2) + name + NUL
        name_offs = []
        for fn in funcs:
            off = put(struct.pack("<H", 0) + fn.encode() + b"\x00")
            if len(rd) % 2:  # keep word alignment
                put(b"\x00")
            name_offs.append(off)
        dll_name_off = put(dll.encode() + b"\x00")
        if len(rd) % 2:
            put(b"\x00")
        # ILT (and IAT) thunks: 8-byte RVAs to the by-name structs, null-term
        ilt_off = cursor
        for off in name_offs:
            put(struct.pack("<Q", rdata_rva + off))
        put(struct.pack("<Q", 0))
        descriptors.append((ilt_off, dll_name_off))

    # strings blob
    for s in strings:
        put(s + b"\x00")

    # now fill in the import descriptors
    for i, (ilt_off, dll_name_off) in enumerate(descriptors):
        struct.pack_into("<IIIII", rd, i * 20,
                         rdata_rva + ilt_off,  # OriginalFirstThunk (ILT)
                         0, 0,
                         rdata_rva + dll_name_off,  # Name
                         rdata_rva + ilt_off)  # FirstThunk (reuse ILT as IAT)

    rdata = bytes(rd)

    # ---- sections --------------------------------------------------------
    text = text_code  # filler by default; a decoder stub for emulation fixtures
    packed = os.urandom(high_entropy_bytes)

    secs = [
        (b".text", 0x1000, text, 0x60000020),            # code|exec|read
        (b".rdata", rdata_rva, rdata, 0x40000040),       # init-data|read
        (b".packed", 0x3000, packed, 0xE0000040),        # read|write|exec (RWX!) + init
    ]

    # ---- headers ---------------------------------------------------------
    e_lfanew = 0x80
    coff_off = e_lfanew + 4
    opt_off = coff_off + 20
    opt_size = 240
    sect_hdr_off = opt_off + opt_size
    headers_end = sect_hdr_off + 40 * len(secs)
    size_of_headers = _align(headers_end, FILE_ALIGN)

    # assign raw file offsets
    raw_cursor = size_of_headers
    placed = []
    for name, rva, body, chars in secs:
        raw_size = _align(len(body), FILE_ALIGN)
        placed.append((name, rva, body, chars, raw_cursor, raw_size))
        raw_cursor += raw_size
    total_size = raw_cursor

    buf = bytearray(total_size)

    # DOS header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"

    # COFF
    struct.pack_into("<HHIIIHH", buf, coff_off,
                     IMAGE_FILE_MACHINE_AMD64, len(secs), 0x5F000000, 0, 0,
                     opt_size, 0x0022)  # EXECUTABLE | LARGE_ADDRESS_AWARE

    # Optional header (PE32+)
    o = bytearray(opt_size)
    struct.pack_into("<H", o, 0, 0x20B)                 # Magic PE32+
    struct.pack_into("<I", o, 16, 0x1000)               # AddressOfEntryPoint
    struct.pack_into("<I", o, 20, 0x1000)               # BaseOfCode
    struct.pack_into("<Q", o, 24, 0x140000000)          # ImageBase
    struct.pack_into("<I", o, 32, SECT_ALIGN)           # SectionAlignment
    struct.pack_into("<I", o, 36, FILE_ALIGN)           # FileAlignment
    struct.pack_into("<I", o, 56, 0x4000)               # SizeOfImage
    struct.pack_into("<I", o, 60, size_of_headers)      # SizeOfHeaders
    struct.pack_into("<H", o, 68, 3)                    # Subsystem = console
    struct.pack_into("<H", o, 70, 0x0000)              # DllCharacteristics: NO aslr/dep
    struct.pack_into("<I", o, 108, 16)                  # NumberOfRvaAndSizes
    # DataDirectory[1] = Import
    struct.pack_into("<II", o, 112 + 1 * 8, rdata_rva, idt_size)
    buf[opt_off:opt_off + opt_size] = o

    # Section headers + bodies
    for i, (name, rva, body, chars, raw_off, raw_size) in enumerate(placed):
        base = sect_hdr_off + i * 40
        buf[base:base + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<IIII", buf, base + 8, len(body), rva, raw_size, raw_off)
        struct.pack_into("<I", buf, base + 36, chars)
        buf[raw_off:raw_off + len(body)] = body

    return bytes(buf)


def make_benign_pe() -> bytes:
    """A minimal, well-formed PE with mitigations and mundane imports."""

    data = make_suspicious_pe(
        imports=(("kernel32.dll", ["GetStdHandle", "WriteFile", "ExitProcess"]),
                 ("msvcrt.dll", ["printf", "malloc", "free"])),
        strings=(b"Hello, world!", b"usage: demo [options]", b"(c) 2026 Example Corp"),
        high_entropy_bytes=0,
    )
    buf = bytearray(data)
    # turn on ASLR + DEP + NX in DllCharacteristics so it looks like real builds
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    opt_off = e_lfanew + 4 + 20
    struct.pack_into("<H", buf, opt_off + 70, 0x0140)  # dynamic-base + nx-compat
    # drop the RWX .packed section characteristics to read-only init-data
    idx = buf.find(b".packed\x00")
    if idx != -1:
        struct.pack_into("<I", buf, idx + 36, 0x40000040)  # read | initialized-data
    return bytes(buf)


def make_decoder_pe(secret: bytes = b"http://hidden-c2.top/beacon") -> bytes:
    """A PE whose entry point reconstructs a hidden C2 URL on the stack.

    The URL is *not* present as a contiguous string in the file — only
    sandboxed emulation of the entry stub reveals it. Static imports/strings
    are mundane, so the recovered string is the whole story.
    """
    return make_suspicious_pe(
        imports=(("kernel32.dll", ["GetProcAddress", "LoadLibraryA", "VirtualAlloc"]),),
        strings=(b"loading...", b"config.dat", b"%TEMP%\\svc.log"),
        high_entropy_bytes=0,
        text_code=stackstring_code(secret),
    )


def write_fixtures(dest_dir: str) -> dict:
    os.makedirs(dest_dir, exist_ok=True)
    out = {}
    specimens = {
        "specimen_suspicious.exe.bin": make_suspicious_pe(),
        "specimen_benign.exe.bin": make_benign_pe(),
        "specimen_decoder.exe.bin": make_decoder_pe(),
        "specimen_notes.txt": b"just some harmless text\nnothing to see here\n",
    }
    for name, body in specimens.items():
        p = os.path.join(dest_dir, name)
        with open(p, "wb") as fh:
            fh.write(body)
        out[name] = p
    return out


if __name__ == "__main__":
    import sys
    dest = sys.argv[1] if len(sys.argv) > 1 else "samples"
    for name, path in write_fixtures(dest).items():
        print(f"wrote {path} ({os.path.getsize(path)} bytes)")

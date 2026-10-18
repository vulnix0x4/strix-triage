"""Magic-byte based file typing — no libmagic dependency.

Returns ``(file_type, mime, format_family)``. ``format_family`` is what the
analyzer switches on to pick a parser: ``pe``, ``elf``, ``macho``, ``script``,
``archive``, ``document``, ``data``.
"""

from __future__ import annotations

from typing import Tuple

Typing = Tuple[str, str, str]


def _is_mostly_text(head: bytes) -> bool:
    if not head:
        return False
    text = sum(1 for b in head if b in (9, 10, 13) or 32 <= b <= 126)
    return text / len(head) > 0.90


def detect(data: bytes) -> Typing:
    head = data[:64]

    # --- containers / executables -----------------------------------------
    if data[:2] == b"MZ":
        # Could be DOS stub only; PE confirmed later by the parser.
        return ("PE / MZ executable", "application/vnd.microsoft.portable-executable", "pe")
    if data[:4] == b"\x7fELF":
        return ("ELF executable", "application/x-elf", "elf")
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return ("Mach-O executable", "application/x-mach-binary", "macho")
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        # Mach-O fat/universal (0xcafebabe). Java class also uses cafebabe but
        # with a version word; treat as macho-fat, parser disambiguates.
        return ("Mach-O universal (fat) binary", "application/x-mach-binary", "macho")

    # --- archives ----------------------------------------------------------
    if data[:2] == b"PK" and data[2:4] in (b"\x03\x04", b"\x05\x06", b"\x07\x08"):
        return ("ZIP archive (or OOXML/JAR/APK)", "application/zip", "archive")
    if data[:6] == b"Rar!\x1a\x07":
        return ("RAR archive", "application/x-rar", "archive")
    if data[:2] == b"\x1f\x8b":
        return ("gzip stream", "application/gzip", "archive")
    if data[:3] == b"BZh":
        return ("bzip2 archive", "application/x-bzip2", "archive")
    if data[:6] == b"\xfd7zXZ\x00":
        return ("xz archive", "application/x-xz", "archive")
    if data[:4] == b"7z\xbc\xaf":
        return ("7-Zip archive", "application/x-7z-compressed", "archive")

    # --- documents ---------------------------------------------------------
    if data[:4] == b"%PDF":
        return ("PDF document", "application/pdf", "document")
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return ("OLE2 / legacy Office document", "application/x-ole-storage", "document")
    if data[:4] == b"\xed\xab\xee\xdb":
        return ("RPM package", "application/x-rpm", "archive")

    # --- scripts (shebang / known interpreters) ----------------------------
    if data[:2] == b"#!":
        line = data[:120].split(b"\n", 1)[0].decode("latin-1", "replace")
        return (f"script ({line.strip()})", "text/x-script", "script")
    low = data[:512].lstrip().lower()
    if low[:5] == b"<?php":
        return ("PHP script", "application/x-php", "script")
    if low[:14] == b"<!doctype html" or low[:5] == b"<html":
        return ("HTML document", "text/html", "document")
    if low[:5] in (b"<?xml",):
        return ("XML document", "application/xml", "document")

    # --- generic text vs data ---------------------------------------------
    if _is_mostly_text(data[:1024]):
        return ("text", "text/plain", "script")
    return ("binary data", "application/octet-stream", "data")

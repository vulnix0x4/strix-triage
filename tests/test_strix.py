"""Test suite for Strix. Run with: pytest -q"""

from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from strix.core import entropy, filetype, hashing
from strix.core.analyzer import Analyzer
from strix.core.model import Severity, Verdict
from strix.detect import engine
from strix.extractors import iocs, strings
from strix.parsers import macho, pe
from tests.fixtures import make_benign_pe, make_suspicious_pe


# --------------------------------------------------------------------------
# core primitives
# --------------------------------------------------------------------------
def test_entropy_bounds():
    assert entropy.shannon(b"") == 0.0
    assert entropy.shannon(b"\x00" * 1000) == 0.0
    assert 7.9 <= entropy.shannon(os.urandom(8192)) <= 8.0
    assert entropy.classify(7.5) == "packed/encrypted"
    assert entropy.classify(1.0) == "low/plaintext"


def test_filetype_detection():
    assert filetype.detect(make_suspicious_pe())[2] == "pe"
    assert filetype.detect(b"\x7fELF\x02\x01\x01")[2] == "elf"
    assert filetype.detect(b"%PDF-1.7\n")[2] == "document"
    assert filetype.detect(b"#!/bin/sh\necho hi")[2] == "script"
    assert filetype.detect(b"PK\x03\x04zip")[2] == "archive"
    assert filetype.detect(b"plain readable text here, nothing binary")[2] == "script"


def test_hashing_and_fuzzy():
    data = b"A" * 5000
    f1 = hashing.fuzzy_hash(data)
    f2 = hashing.fuzzy_hash(data + b"A" * 50)
    f3 = hashing.fuzzy_hash(os.urandom(5000))
    assert hashing.fuzzy_compare(f1, f2) > hashing.fuzzy_compare(f1, f3)
    assert hashing.imphash(["kernel32.dll.CreateFileW"]) == hashing.imphash(["KERNEL32.dll.CreateFileW"])


# --------------------------------------------------------------------------
# PE parser
# --------------------------------------------------------------------------
def test_pe_parse_imports_and_sections():
    data = make_suspicious_pe()
    assert pe.is_pe(data)
    pb = pe.parse(data)
    assert pb.format == "pe"
    assert pb.arch == "x86-64"
    assert pb.bits == 64
    names = [i.lower() for i in pb.imports]
    assert any("virtualallocex" in n for n in names)
    assert any("urldownloadtofilea" in n for n in names)
    assert any(n.startswith("kernel32.dll.") for n in names)
    assert any(s.name == ".packed" for s in pb.sections)
    assert any("writable AND executable" in a for a in pb.anomalies)


def test_pe_not_confused_by_dos_stub():
    assert not pe.is_pe(b"MZ" + b"\x00" * 100)  # no PE sig


# --------------------------------------------------------------------------
# signature engine
# --------------------------------------------------------------------------
def test_engine_literal_and_count_conditions():
    rules = engine.compile_rules('''
        rule t1 {
            strings:
                $a = "evil" nocase
                $b = "payload"
            condition:
                $a and $b
        }
        rule t2 {
            strings:
                $a = "evil"
            condition:
                #a > 2
        }
        rule t3 {
            strings:
                $a = "x"
                $b = "y"
                $c = "z"
            condition:
                2 of them
        }
    ''')
    data = b"EVIL things with payload inside"
    names = {m.rule for m in engine.scan(data, rules)}
    assert "t1" in names and "t2" not in names

    data2 = b"evil evil evil"
    names2 = {m.rule for m in engine.scan(data2, rules)}
    assert "t2" in names2

    data3 = b"only x and y here"
    names3 = {m.rule for m in engine.scan(data3, rules)}
    assert "t3" in names3


def test_engine_hex_wildcards():
    rules = engine.compile_rules(
        "rule h { strings: $a = { DE AD ?? EF } condition: $a }")
    assert engine.scan(b"\xde\xad\xbe\xef", rules)
    assert engine.scan(b"\xde\xad\x00\xef", rules)
    assert not engine.scan(b"\xde\xad\xbe\xff", rules)


def test_engine_entropy_and_filesize_terms():
    rules = engine.compile_rules(
        'rule e { strings: $mz = { 4D 5A } condition: $mz and entropy > 7.0 and filesize > 1KB }')
    hi = b"MZ" + os.urandom(4096)
    lo = b"MZ" + b"\x00" * 4096
    assert engine.scan(hi, rules, entropy=entropy.shannon(hi))
    assert not engine.scan(lo, rules, entropy=entropy.shannon(lo))


def test_bundled_rules_load():
    rules = engine.load_bundled()
    assert len(rules) >= 10
    assert any(r.name == "Ransom_ShadowCopy_Destruction" for r in rules)


# --------------------------------------------------------------------------
# IOC extraction
# --------------------------------------------------------------------------
def test_ioc_extraction_filters_noise():
    s = iocs.extract([
        "connect to http://malware-c2.top/x and https://safe.example.com",
        "contact evil@bad.ru",
        "127.0.0.1 is local but 8.8.8.8 is public",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "wallet 1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
        "vssadmin delete shadows",
    ])
    assert any("malware-c2.top" in u for u in s.urls)
    assert "8.8.8.8" in s.ipv4 and "127.0.0.1" not in s.ipv4
    assert any("microsoft" not in d for d in s.domains)  # benign filtered
    assert s.registry
    assert any("btc:" in c for c in s.crypto)
    assert any("shadow-copy" in x for x in s.suspicious)


def test_strings_ascii_and_utf16():
    blob = b"hello\x00\x00w\x00o\x00r\x00l\x00d\x00"
    found = strings.extract(blob, min_len=4)
    vals = [s.value for s in found]
    assert "hello" in vals
    assert "world" in vals


# --------------------------------------------------------------------------
# full pipeline verdicts
# --------------------------------------------------------------------------
def test_suspicious_specimen_scores_malicious():
    report = Analyzer().analyze_bytes(make_suspicious_pe(), path="specimen.exe")
    assert report.verdict in (Verdict.MALICIOUS, Verdict.LIKELY_MALICIOUS)
    assert report.score >= 70
    assert "T1055" in report.attack_techniques      # injection
    assert "T1486" in report.attack_techniques       # ransomware/impact
    assert report.max_severity == Severity.CRITICAL


def test_benign_specimen_scores_clean():
    report = Analyzer().analyze_bytes(make_benign_pe(), path="clean.exe")
    assert report.verdict in (Verdict.CLEAN, Verdict.LOW_RISK)
    assert report.score < 25


def test_report_json_roundtrip_is_serializable():
    import json
    report = Analyzer().analyze_bytes(make_suspicious_pe(), path="x.exe")
    blob = json.dumps(report.to_dict())
    back = json.loads(blob)
    assert back["verdict"] == report.verdict.value
    assert back["file"]["hashes"]["sha256"]


def test_scoring_saturates():
    report = Analyzer().analyze_bytes(make_suspicious_pe(), path="x.exe")
    assert report.score <= 100


# --------------------------------------------------------------------------
# ELF + Mach-O smoke tests
# --------------------------------------------------------------------------
def _minimal_elf64() -> bytes:
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2  # 64-bit
    hdr[5] = 1  # little-endian
    struct.pack_into("<HH", hdr, 16, 2, 0x3E)  # ET_EXEC, x86-64
    return bytes(hdr)


def test_elf_header_parse():
    from strix.parsers import elf
    pb = elf.parse(_minimal_elf64())
    assert pb.arch == "x86-64"
    assert pb.bits == 64
    assert any("no section headers" in a for a in pb.anomalies)


def test_macho_real_binary_if_present():
    for cand in ("/bin/ls", "/bin/cat", "/usr/bin/true"):
        if os.path.exists(cand):
            data = open(cand, "rb").read()
            assert macho.is_macho(data)
            pb = macho.parse(data)
            assert pb.format == "macho"
            assert pb.arch != "unknown"
            return

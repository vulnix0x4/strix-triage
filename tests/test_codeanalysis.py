"""Tests for the disassembler, emulator, string recovery, corpus, and rulegen."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from strix.core.analyzer import Analyzer
from strix.core.model import Verdict
from strix.detect.genrule import generate
from strix.disasm import decode, disassemble
from strix.disasm.analyze import analyze_code
from strix.disasm.model import OpKind
from strix.emulate import AddressSpace, Emulator
from strix.emulate.strings import recover_strings
from tests.fixtures import make_decoder_pe, make_suspicious_pe, stackstring_code


# --------------------------------------------------------------------------
# disassembler
# --------------------------------------------------------------------------
def test_decode_known_encodings():
    cases = {
        "55": ("push", 1),
        "4889e5": ("mov", 3),
        "b82a000000": ("mov", 5),
        "48c7c005000000": ("mov", 7),
        "31c0": ("xor", 2),
        "c3": ("ret", 1),
        "0f05": ("syscall", 2),
        "65488b042560000000": ("mov", 9),
        "488d041a": ("lea", 4),
        "e800000000": ("call", 5),
        "0fb6c0": ("movzx", 3),
        "c1e004": ("shl", 3),
    }
    for hexs, (mnem, length) in cases.items():
        ins = decode(bytes.fromhex(hexs))
        assert ins is not None, hexs
        assert ins.mnemonic == mnem, f"{hexs}: {ins.mnemonic} != {mnem}"
        assert ins.length == length, f"{hexs}: len {ins.length} != {length}"


def test_decode_resolves_branch_target():
    # jmp rel8 0xEB 0x10 at address 0x1000 -> target 0x1012
    ins = decode(bytes.fromhex("eb10"), addr=0x1000)
    assert ins.mnemonic == "jmp"
    assert ins.target == 0x1012


def test_call_register_is_64bit():
    ins = decode(bytes.fromhex("ffd0"))  # call rax
    assert ins.mnemonic == "call"
    assert ins.operands[0].reg == "rax"


def test_disassemble_recovers_after_bad_bytes():
    # garbage then a ret; linear sweep must not hang and must find the ret
    blob = b"\x06\x07\xc3"  # 0x06/0x07 invalid in 64-bit -> db, then ret
    insns = list(disassemble(blob))
    assert insns[-1].mnemonic == "ret"


def test_gs_peb_access_flagged():
    ins = decode(bytes.fromhex("65488b042560000000"))
    assert ins.operands[1].seg == "gs" and ins.operands[1].disp == 0x60
    _stats, findings = analyze_code([ins])
    assert any(f.id == "code.peb_walk" for f in findings)


# --------------------------------------------------------------------------
# emulator
# --------------------------------------------------------------------------
def _xor_stub():
    return bytes.fromhex(
        "48be0020000000000000" "48bf0030000000000000" "48c7c105000000"
        "8a06" "3455" "8807" "48ffc6" "48ffc7" "48ffc9" "75ef" "c3")


def test_emulator_decodes_xor_buffer():
    code = _xor_stub()
    enc = bytes(b ^ 0x55 for b in b"HELLO")
    sp = AddressSpace()
    sp.map_bytes(0x1000, code)
    sp.map_bytes(0x2000, enc)
    emu = Emulator(sp)
    reason = emu.run(0x1000)
    assert reason == "returned from top function"
    assert sp.read_bytes(0x3000, 5) == b"HELLO"


def test_emulator_sandbox_stops_on_syscall():
    sp = AddressSpace()
    sp.map_bytes(0x1000, bytes.fromhex("0f05"))  # syscall
    emu = Emulator(sp)
    assert "syscall" in emu.run(0x1000)


def test_emulator_step_cap():
    # eb fe = jmp $ (infinite loop) must terminate at the step cap
    sp = AddressSpace()
    sp.map_bytes(0x1000, bytes.fromhex("ebfe"))
    emu = Emulator(sp, max_steps=500)
    assert emu.run(0x1000) == "step cap reached"
    assert emu.steps == 500


def test_register_subwidth_semantics():
    sp = AddressSpace()
    emu = Emulator(sp)
    emu.regs.set("rax", 0x1122334455667788)
    emu.regs.set("eax", 0xDEADBEEF)           # 32-bit write zero-extends
    assert emu.regs.get("rax") == 0xDEADBEEF
    emu.regs.set("al", 0x00)
    assert emu.regs.get("rax") == 0xDEADBE00


# --------------------------------------------------------------------------
# string recovery
# --------------------------------------------------------------------------
def test_recover_stack_string():
    secret = b"http://recovered-c2.example.top/x"
    code = stackstring_code(secret)
    segs = [(0x401000, code)]
    rec = recover_strings(segs, [0x401000], static_strings=[])
    vals = [r.value for r in rec]
    assert any("recovered-c2.example.top" in v for v in vals)


def test_recovery_suppresses_static_strings():
    secret = b"this_is_already_static_12345"
    code = stackstring_code(secret)
    segs = [(0x401000, code)]
    rec = recover_strings(segs, [0x401000], static_strings=[secret.decode()])
    assert all(secret.decode() not in r.value for r in rec)


def test_end_to_end_emulation_finding():
    report = Analyzer().analyze_bytes(make_decoder_pe(b"http://hidden-xyz.top/b"),
                                      path="decoder.exe")
    assert any(f.id == "emulation.decoded_strings" for f in report.findings)
    decoded = report.sections.get("decoded_strings", [])
    assert any("hidden-xyz.top" in d["value"] for d in decoded)
    assert report.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS)


def test_deep_code_can_be_disabled():
    report = Analyzer(deep_code=False).analyze_bytes(
        make_decoder_pe(b"http://hidden-xyz.top/b"), path="d.exe")
    assert "decoded_strings" not in report.sections


# --------------------------------------------------------------------------
# corpus + rule generation + navigator
# --------------------------------------------------------------------------
def test_corpus_roundtrip_and_cluster(tmp_path):
    from strix.corpus import Corpus
    db = str(tmp_path / "c.db")
    a = Analyzer()
    r1 = a.analyze_bytes(make_suspicious_pe(), path="a.exe")
    r2 = a.analyze_bytes(make_suspicious_pe(), path="b.exe")  # identical content
    with Corpus(db) as c:
        assert c.add(r1) and c.add(r2)
        assert c.stats()["total"] == 2
        clusters = c.cluster(threshold=40)
        assert clusters and len(clusters[0]) == 2  # identical samples cluster


def test_genrule_includes_decoded_string():
    report = Analyzer().analyze_bytes(make_decoder_pe(b"http://genrule-c2.top/z"),
                                      path="x.exe")
    rule = generate(report)
    assert "genrule-c2.top" in rule
    assert "rule Strix_auto_" in rule
    assert "condition:" in rule


def test_navigator_layer_shape():
    from strix.report import navigator
    report = Analyzer().analyze_bytes(make_suspicious_pe(), path="x.exe")
    layer = navigator.build_layer(report)
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"]
    assert all("techniqueID" in t and "score" in t for t in layer["techniques"])

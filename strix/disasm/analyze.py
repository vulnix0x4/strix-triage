"""Code-level heuristics over a disassembled instruction stream.

Operates purely on statically decoded instructions (no execution) to spot the
shapes that distinguish malware code from benign compiler output: PEB walks,
API-name hashing loops, tight XOR/ADD/ROL decode loops, dynamic/indirect
control flow, direct ``syscall`` usage, stack-string construction, and
anti-analysis instructions (``rdtsc``, ``cpuid``, ``int 2d``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..core.model import Finding, Severity
from .model import Instruction, OpKind


@dataclass
class CodeStats:
    count: int = 0
    mnemonics: dict = field(default_factory=dict)
    peb_access: list = field(default_factory=list)
    indirect_calls: int = 0
    indirect_jmps: int = 0
    syscalls: int = 0
    rdtsc: int = 0
    cpuid: int = 0
    int2d: int = 0
    xor_self: int = 0           # xor reg,reg (zeroing — benign, counted for context)
    xor_decrypt: int = 0        # xor reg/mem, reg/imm (non-zeroing)
    rol_ror: int = 0
    loops: int = 0
    stack_string_bytes: int = 0
    pushes_imm: int = 0
    invalid: int = 0


def _tally(insns: Iterable[Instruction]) -> CodeStats:
    s = CodeStats()
    for ins in insns:
        s.count += 1
        s.mnemonics[ins.mnemonic] = s.mnemonics.get(ins.mnemonic, 0) + 1
        m = ins.mnemonic
        ops = ins.operands

        if m == "db":
            s.invalid += 1
        elif m == "syscall":
            s.syscalls += 1
        elif m == "rdtsc":
            s.rdtsc += 1
        elif m == "cpuid":
            s.cpuid += 1
        elif m == "int" and ops and ops[0].kind is OpKind.IMM and ops[0].value == 0x2D:
            s.int2d += 1
        elif m in ("loop", "loope", "loopne"):
            s.loops += 1
        elif m in ("rol", "ror", "rcl", "rcr"):
            s.rol_ror += 1
        elif m == "call" and ops and ops[0].kind in (OpKind.REG, OpKind.MEM):
            s.indirect_calls += 1
        elif m == "jmp" and ops and ops[0].kind in (OpKind.REG, OpKind.MEM):
            s.indirect_jmps += 1
        elif m == "push" and ops and ops[0].kind is OpKind.IMM:
            s.pushes_imm += 1
        elif m == "xor" and len(ops) == 2:
            a, b = ops
            if a.kind is OpKind.REG and b.kind is OpKind.REG and a.reg == b.reg:
                s.xor_self += 1
            else:
                s.xor_decrypt += 1
        elif m in ("mov",) and len(ops) == 2 and ops[0].kind is OpKind.MEM and ops[1].kind is OpKind.IMM:
            # mov [rbp-X], imm  → stack string construction (printable immediates)
            if ops[0].base in ("rbp", "rsp") and _printable_imm(ops[1].value, ops[1].size):
                s.stack_string_bytes += ops[1].size

        # PEB access: fs:[0x30] (x86) or gs:[0x60] (x64)
        for o in ops:
            if o.kind is OpKind.MEM and o.seg in ("fs", "gs"):
                if (o.seg == "gs" and o.disp == 0x60) or (o.seg == "fs" and o.disp == 0x30):
                    s.peb_access.append(ins.address)
    return s


def analyze_code(insns: Iterable[Instruction]) -> tuple[CodeStats, list[Finding]]:
    stats = _tally(insns)
    findings: list[Finding] = []

    if stats.peb_access:
        findings.append(Finding(
            id="code.peb_walk", title="PEB access (fs:[0x30]/gs:[0x60]) in code",
            severity=Severity.HIGH, category="code",
            description="Reads the Process Environment Block to locate loaded modules without imports — classic shellcode / API-resolution technique.",
            evidence=[hex(a) for a in stats.peb_access[:6]], attack=["T1106", "T1027"]))

    if stats.syscalls:
        findings.append(Finding(
            id="code.direct_syscall", title=f"Direct syscall instruction(s) ×{stats.syscalls}",
            severity=Severity.HIGH, category="code",
            description="Invokes kernel services directly, bypassing user-mode API hooks (EDR evasion).",
            attack=["T1106", "T1562.001"]))

    # API-hashing / decrypt loop heuristic: a loop body dominated by rotates +
    # xor/add over a counter is the signature of name-hashing and string crypto.
    if (stats.rol_ror >= 1 and stats.xor_decrypt >= 1) or stats.rol_ror >= 3:
        findings.append(Finding(
            id="code.hash_or_crypt_loop",
            title="Rotate+XOR arithmetic cluster (API hashing / string crypto)",
            severity=Severity.MEDIUM, category="code",
            description="Rotate instructions combined with XOR/ADD are the arithmetic core of API-name hashing and lightweight string encryption.",
            evidence=[f"rol/ror×{stats.rol_ror}", f"xor(non-zeroing)×{stats.xor_decrypt}"],
            attack=["T1027", "T1140"]))

    if stats.xor_decrypt >= 4 and stats.loops:
        findings.append(Finding(
            id="code.xor_decrypt_loop", title="XOR decryption loop",
            severity=Severity.HIGH, category="code",
            description="A loop applying repeated non-zeroing XORs over data is a self-decrypting stub.",
            evidence=[f"xor×{stats.xor_decrypt}", f"loop×{stats.loops}"],
            attack=["T1140", "T1027.002"]))

    if stats.indirect_calls + stats.indirect_jmps >= 6:
        findings.append(Finding(
            id="code.dynamic_flow",
            title=f"Heavy indirect control flow (call/jmp reg/mem ×{stats.indirect_calls + stats.indirect_jmps})",
            severity=Severity.MEDIUM, category="code",
            description="Dense indirect calls/jumps indicate dynamically-resolved APIs or an obfuscated dispatcher.",
            attack=["T1027"]))

    if stats.rdtsc >= 2 or stats.cpuid >= 2 or stats.int2d:
        ev = []
        if stats.rdtsc:
            ev.append(f"rdtsc×{stats.rdtsc}")
        if stats.cpuid:
            ev.append(f"cpuid×{stats.cpuid}")
        if stats.int2d:
            ev.append(f"int 2d×{stats.int2d}")
        findings.append(Finding(
            id="code.timing_antidebug", title="Timing / anti-debug instructions",
            severity=Severity.MEDIUM, category="anti-analysis",
            description="rdtsc/cpuid timing checks or int 2d are used to detect debuggers and sandboxes.",
            evidence=ev, attack=["T1497.003", "T1622"]))

    if stats.stack_string_bytes >= 8:
        findings.append(Finding(
            id="code.stack_strings",
            title=f"Stack-string construction (~{stats.stack_string_bytes} bytes)",
            severity=Severity.MEDIUM, category="code",
            description="Strings built byte-by-byte on the stack evade static string extraction.",
            attack=["T1027"]))

    # a .text that mostly fails to decode is either data, encrypted, or packed
    if stats.count and stats.invalid / stats.count > 0.35 and stats.count > 40:
        findings.append(Finding(
            id="code.undecodable",
            title=f"Code region {100*stats.invalid//stats.count}% undecodable",
            severity=Severity.MEDIUM, category="packing",
            description="A high proportion of invalid instructions suggests the executable section is encrypted or packed, not real code.",
            attack=["T1027.002"]))

    return stats, findings


def _printable_imm(value: int, size: int) -> bool:
    if size > 8 or value <= 0:
        return False
    data = value.to_bytes(8, "little")[:size]
    nz = [b for b in data if b]
    return bool(nz) and all(0x20 <= b <= 0x7E for b in nz)

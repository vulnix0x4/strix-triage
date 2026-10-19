"""x86 / x86-64 instruction decoder (triage subset).

Covers the instruction families common in malware stubs and decryptors. Unknown
bytes decode to a single-byte ``db`` so the stream self-resynchronises.
"""

from __future__ import annotations

import struct
from typing import Optional

from .model import Instruction, Operand, OpKind

# --- register name tables --------------------------------------------------
R64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
       "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
R32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
       "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
R16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
       "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]
R8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
      "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
R8L = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]
XMM = [f"xmm{i}" for i in range(16)]

ALU = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
SHIFT = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"]
CC = ["o", "no", "b", "ae", "e", "ne", "be", "a",
      "s", "ns", "p", "np", "l", "ge", "le", "g"]


def reg_name(idx: int, size: int, rex_present: bool) -> str:
    idx &= 0xF
    if size == 8:
        return R64[idx]
    if size == 4:
        return R32[idx]
    if size == 2:
        return R16[idx]
    if rex_present:
        return R8[idx]
    return R8L[idx] if idx < 8 else R8[idx]


class _Rex:
    __slots__ = ("present", "w", "r", "x", "b")

    def __init__(self, byte: Optional[int] = None):
        if byte is None:
            self.present = self.w = self.r = self.x = self.b = 0
        else:
            self.present = 1
            self.w = (byte >> 3) & 1
            self.r = (byte >> 2) & 1
            self.x = (byte >> 1) & 1
            self.b = byte & 1


class _Cur:
    __slots__ = ("d", "p", "n")

    def __init__(self, data: bytes, pos: int):
        self.d = data
        self.p = pos
        self.n = len(data)

    def eof(self) -> bool:
        return self.p >= self.n

    def u8(self) -> int:
        b = self.d[self.p]
        self.p += 1
        return b

    def s8(self) -> int:
        v = self.u8()
        return v - 256 if v >= 128 else v

    def u16(self) -> int:
        v = struct.unpack_from("<H", self.d, self.p)[0]
        self.p += 2
        return v

    def s16(self) -> int:
        v = struct.unpack_from("<h", self.d, self.p)[0]
        self.p += 2
        return v

    def u32(self) -> int:
        v = struct.unpack_from("<I", self.d, self.p)[0]
        self.p += 4
        return v

    def s32(self) -> int:
        v = struct.unpack_from("<i", self.d, self.p)[0]
        self.p += 4
        return v

    def u64(self) -> int:
        v = struct.unpack_from("<Q", self.d, self.p)[0]
        self.p += 8
        return v


class Decoder:
    def __init__(self, mode64: bool = True):
        self.mode64 = mode64

    # -- public -------------------------------------------------------------
    def decode(self, data: bytes, addr: int = 0, offset: int = 0) -> Optional[Instruction]:
        if offset >= len(data):
            return None
        cur = _Cur(data, offset)
        try:
            return self._decode(cur, addr)
        except (IndexError, struct.error):
            # ran off the end mid-instruction
            raw = data[offset:offset + 1]
            return Instruction(addr, 1, "db", [Operand(OpKind.IMM, value=data[offset])],
                               raw=raw, opsize=1)

    # -- internals ----------------------------------------------------------
    def _decode(self, cur: _Cur, addr: int) -> Instruction:
        start = cur.p
        prefixes: list[str] = []
        seg = None
        opsize_override = False
        rep = None
        lock = False
        # legacy prefixes
        while not cur.eof():
            b = cur.d[cur.p]
            if b == 0x66:
                opsize_override = True; prefixes.append("opsize"); cur.p += 1
            elif b == 0x67:
                prefixes.append("addrsize"); cur.p += 1
            elif b == 0xF0:
                lock = True; prefixes.append("lock"); cur.p += 1
            elif b == 0xF2:
                rep = "repne"; prefixes.append("repne"); cur.p += 1
            elif b == 0xF3:
                rep = "rep"; prefixes.append("rep"); cur.p += 1
            elif b in (0x2E, 0x36, 0x3E, 0x26):
                cur.p += 1
            elif b == 0x64:
                seg = "fs"; cur.p += 1
            elif b == 0x65:
                seg = "gs"; cur.p += 1
            else:
                break

        rex = _Rex()
        if self.mode64 and not cur.eof() and 0x40 <= cur.d[cur.p] <= 0x4F:
            rex = _Rex(cur.u8())

        # default operation size
        if rex.w:
            opsize = 8
        elif opsize_override:
            opsize = 2
        else:
            opsize = 4

        ctx = _Ctx(cur, addr, rex, seg, opsize, rep, lock, self.mode64, prefixes)
        op = cur.u8()
        if op == 0x0F:
            insn = self._two_byte(ctx, cur.u8())
        else:
            insn = self._one_byte(ctx, op)

        length = cur.p - start
        insn.length = length
        insn.address = addr
        insn.raw = bytes(cur.d[start:cur.p])
        insn.prefixes = prefixes
        return insn

    # ---- one-byte opcode map ---------------------------------------------
    def _one_byte(self, c: "_Ctx", op: int) -> Instruction:
        cur = c.cur
        # ALU group 0x00..0x3D
        if op < 0x40 and (op & 0x07) < 6 and (op & 0x38) >> 3 < 8 and op not in (0x0F,):
            mnem = ALU[(op >> 3) & 7]
            form = op & 7
            return self._alu_form(c, mnem, form)

        if 0x50 <= op <= 0x57:  # push r64
            r = reg_name((op - 0x50) | (c.rex.b << 3), 8, c.rex.present)
            return _mk("push", [Operand(OpKind.REG, reg=r, size=8)], opsize=8)
        if 0x58 <= op <= 0x5F:  # pop r64
            r = reg_name((op - 0x58) | (c.rex.b << 3), 8, c.rex.present)
            return _mk("pop", [Operand(OpKind.REG, reg=r, size=8)], opsize=8)

        if op == 0x68:  # push imm32
            return _mk("push", [_imm(c.cur.s32(), c.opsize)], opsize=c.opsize)
        if op == 0x6A:  # push imm8
            return _mk("push", [_imm(c.cur.s8(), 1)], opsize=c.opsize)
        if op in (0x69, 0x6B):  # imul Gv, Ev, imm
            reg, rm = self._modrm(c, c.opsize, c.opsize)
            imm = _imm(c.cur.s8(), 1) if op == 0x6B else _imm(c.cur.s32(), c.opsize)
            return _mk("imul", [reg, rm, imm], opsize=c.opsize)

        if 0x70 <= op <= 0x7F:  # Jcc rel8
            return self._branch(c, "j" + CC[op - 0x70], c.cur.s8(), rel8=True)

        if op in (0x80, 0x81, 0x83):  # ALU imm group
            reg_field, rm = self._modrm_rm_only(c, 1 if op == 0x80 else c.opsize)
            mnem = ALU[reg_field]
            if op == 0x80:
                imm = _imm(c.cur.u8(), 1)
            elif op == 0x81:
                imm = _imm(c.cur.s32() if c.opsize != 2 else c.cur.s16(), c.opsize)
            else:
                imm = _imm(c.cur.s8(), 1)
            return _mk(mnem, [rm, imm], opsize=rm.size)

        if op in (0x84, 0x85):  # test Eb/Ev, Gb/Gv
            size = 1 if op == 0x84 else c.opsize
            reg, rm = self._modrm(c, size, size)
            return _mk("test", [rm, reg], opsize=size)
        if op in (0x86, 0x87):  # xchg
            size = 1 if op == 0x86 else c.opsize
            reg, rm = self._modrm(c, size, size)
            return _mk("xchg", [rm, reg], opsize=size)

        if op in (0x88, 0x89, 0x8A, 0x8B):  # mov
            size = 1 if op in (0x88, 0x8A) else c.opsize
            reg, rm = self._modrm(c, size, size)
            if op in (0x88, 0x89):
                return _mk("mov", [rm, reg], opsize=size)
            return _mk("mov", [reg, rm], opsize=size)
        if op == 0x8D:  # lea Gv, M
            reg, rm = self._modrm(c, c.opsize, c.opsize, force_mem=True)
            return _mk("lea", [reg, rm], opsize=c.opsize)
        if op == 0x8F:  # pop Ev
            _f, rm = self._modrm_rm_only(c, 8)
            return _mk("pop", [rm], opsize=8)

        if op == 0x90:
            return _mk("nop" if not c.rep else "pause", [])
        if 0x91 <= op <= 0x97:  # xchg eAX, r
            r = reg_name((op - 0x90) | (c.rex.b << 3), c.opsize, c.rex.present)
            a = reg_name(0, c.opsize, c.rex.present)
            return _mk("xchg", [Operand(OpKind.REG, reg=a, size=c.opsize),
                                Operand(OpKind.REG, reg=r, size=c.opsize)], opsize=c.opsize)
        if op == 0x98:
            return _mk("cdqe" if c.rex.w else "cwde", [])
        if op == 0x99:
            return _mk("cqo" if c.rex.w else "cdq", [])

        if op in (0xA4, 0xA5):
            return _mk(("rep " if c.rep else "") + ("movsb" if op == 0xA4 else "movsd"), [])
        if op in (0xA6, 0xA7):
            return _mk("cmpsb" if op == 0xA6 else "cmpsd", [])
        if op in (0xAA, 0xAB):
            return _mk(("rep " if c.rep else "") + ("stosb" if op == 0xAA else "stosd"), [])
        if op in (0xAC, 0xAD):
            return _mk("lodsb" if op == 0xAC else "lodsd", [])
        if op in (0xAE, 0xAF):
            return _mk("scasb" if op == 0xAE else "scasd", [])
        if op == 0xA8:
            return _mk("test", [Operand(OpKind.REG, reg="al", size=1), _imm(c.cur.u8(), 1)], opsize=1)
        if op == 0xA9:
            return _mk("test", [Operand(OpKind.REG, reg=reg_name(0, c.opsize, c.rex.present), size=c.opsize),
                                _imm(c.cur.s32() if c.opsize != 2 else c.cur.s16(), c.opsize)], opsize=c.opsize)

        if 0xB0 <= op <= 0xB7:  # mov r8, imm8
            r = reg_name((op - 0xB0) | (c.rex.b << 3), 1, c.rex.present)
            return _mk("mov", [Operand(OpKind.REG, reg=r, size=1), _imm(c.cur.u8(), 1)], opsize=1)
        if 0xB8 <= op <= 0xBF:  # mov r, imm (imm64 if REX.W)
            r = reg_name((op - 0xB8) | (c.rex.b << 3), c.opsize, c.rex.present)
            imm = c.cur.u64() if c.rex.w else (c.cur.u16() if c.opsize == 2 else c.cur.u32())
            return _mk("mov", [Operand(OpKind.REG, reg=r, size=c.opsize), _imm(imm, c.opsize)], opsize=c.opsize)

        if op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):  # shift group
            size = 1 if op in (0xC0, 0xD0, 0xD2) else c.opsize
            field, rm = self._modrm_rm_only(c, size)
            mnem = SHIFT[field]
            if op in (0xC0, 0xC1):
                amt = _imm(c.cur.u8(), 1)
            elif op in (0xD0, 0xD1):
                amt = _imm(1, 1)
            else:
                amt = Operand(OpKind.REG, reg="cl", size=1)
            return _mk(mnem, [rm, amt], opsize=size)

        if op == 0xC2:
            return _mk("ret", [_imm(c.cur.u16(), 2)])
        if op == 0xC3:
            return _mk("ret", [])
        if op in (0xC6, 0xC7):  # mov Eb/Ev, imm
            size = 1 if op == 0xC6 else c.opsize
            _f, rm = self._modrm_rm_only(c, size)
            imm = _imm(c.cur.u8(), 1) if size == 1 else _imm(
                c.cur.s32() if size != 2 else c.cur.s16(), size)
            return _mk("mov", [rm, imm], opsize=size)
        if op == 0xC9:
            return _mk("leave", [])
        if op == 0xCC:
            return _mk("int3", [])
        if op == 0xCD:
            return _mk("int", [_imm(c.cur.u8(), 1)])

        if op in (0xE0, 0xE1, 0xE2):  # loopne/loope/loop
            return self._branch(c, {0xE0: "loopne", 0xE1: "loope", 0xE2: "loop"}[op], c.cur.s8(), rel8=True)
        if op == 0xE3:
            return self._branch(c, "jrcxz" if c.mode64 else "jecxz", c.cur.s8(), rel8=True)
        if op == 0xE8:  # call rel32
            return self._branch(c, "call", c.cur.s32(), rel8=False)
        if op == 0xE9:  # jmp rel32
            return self._branch(c, "jmp", c.cur.s32(), rel8=False)
        if op == 0xEB:  # jmp rel8
            return self._branch(c, "jmp", c.cur.s8(), rel8=True)

        if op == 0xF4:
            return _mk("hlt", [])
        if op in (0xF6, 0xF7):  # unary/test group
            size = 1 if op == 0xF6 else c.opsize
            field, rm = self._modrm_rm_only(c, size)
            names = ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"]
            if field in (0, 1):
                imm = _imm(c.cur.u8(), 1) if size == 1 else _imm(
                    c.cur.s32() if size != 2 else c.cur.s16(), size)
                return _mk("test", [rm, imm], opsize=size)
            return _mk(names[field], [rm], opsize=size)
        if op in (0xFE, 0xFF):  # inc/dec/call/jmp/push group
            if op == 0xFE:
                field, rm = self._modrm_rm_only(c, 1)
                return _mk(["inc", "dec"][field & 1], [rm], opsize=1)
            field, rm = self._modrm_rm_only(c, c.opsize)
            return self._ff_group(c, field, rm)

        if op in (0xF5,):
            return _mk("cmc", [])
        if op == 0xF8:
            return _mk("clc", [])
        if op == 0xF9:
            return _mk("stc", [])
        if op == 0xFC:
            return _mk("cld", [])
        if op == 0xFD:
            return _mk("std", [])

        # unknown — emit db
        return _mk("db", [_imm(op, 1)], opsize=1)

    def _ff_group(self, c: "_Ctx", field: int, rm: Operand) -> Instruction:
        if field == 0:
            return _mk("inc", [rm], opsize=rm.size)
        if field == 1:
            return _mk("dec", [rm], opsize=rm.size)
        if field in (2, 4, 6):  # call/jmp/push are 64-bit operands in long mode
            _promote64(rm)
            return _mk({2: "call", 4: "jmp", 6: "push"}[field], [rm], opsize=8)
        return _mk("(ff)", [rm], opsize=rm.size)

    # ---- two-byte opcode map (0x0F ..) -----------------------------------
    def _two_byte(self, c: "_Ctx", op: int) -> Instruction:
        if op == 0x05:
            return _mk("syscall", [])
        if op == 0x0B:
            return _mk("ud2", [])
        if op == 0x1F:  # multi-byte nop Ev
            _f, rm = self._modrm_rm_only(c, c.opsize)
            return _mk("nop", [rm], opsize=c.opsize)
        if op == 0x1E:  # endbr64/endbr32 (F3 0F 1E FA/FB) and reserved-nop forms
            modrm = c.cur.u8()
            if c.rep == "rep" and modrm in (0xFA, 0xFB):
                return _mk("endbr64" if modrm == 0xFA else "endbr32", [])
            return _mk("nop", [])
        if op == 0x31:
            return _mk("rdtsc", [])
        if op == 0xA2:
            return _mk("cpuid", [])
        if op == 0x0D:
            _f, rm = self._modrm_rm_only(c, c.opsize)
            return _mk("prefetch", [rm])
        if 0x80 <= op <= 0x8F:  # Jcc rel32
            return self._branch(c, "j" + CC[op - 0x80], c.cur.s32(), rel8=False)
        if 0x90 <= op <= 0x9F:  # setcc Eb
            _f, rm = self._modrm_rm_only(c, 1)
            return _mk("set" + CC[op - 0x90], [rm], opsize=1)
        if 0x40 <= op <= 0x4F:  # cmovcc Gv, Ev
            reg, rm = self._modrm(c, c.opsize, c.opsize)
            return _mk("cmov" + CC[op - 0x40], [reg, rm], opsize=c.opsize)
        if op in (0xB6, 0xB7):  # movzx
            src = 1 if op == 0xB6 else 2
            reg, rm = self._modrm(c, c.opsize, src)
            return _mk("movzx", [reg, rm], opsize=c.opsize)
        if op in (0xBE, 0xBF):  # movsx
            src = 1 if op == 0xBE else 2
            reg, rm = self._modrm(c, c.opsize, src)
            return _mk("movsx", [reg, rm], opsize=c.opsize)
        if op == 0xAF:  # imul Gv, Ev
            reg, rm = self._modrm(c, c.opsize, c.opsize)
            return _mk("imul", [reg, rm], opsize=c.opsize)
        if op in (0xA3, 0xAB, 0xB3, 0xBB):  # bt/bts/btr/btc
            reg, rm = self._modrm(c, c.opsize, c.opsize)
            return _mk({0xA3: "bt", 0xAB: "bts", 0xB3: "btr", 0xBB: "btc"}[op], [rm, reg], opsize=c.opsize)
        if op in (0xB0, 0xB1):  # cmpxchg
            size = 1 if op == 0xB0 else c.opsize
            reg, rm = self._modrm(c, size, size)
            return _mk("cmpxchg", [rm, reg], opsize=size)
        if op in (0xC0, 0xC1):  # xadd
            size = 1 if op == 0xC0 else c.opsize
            reg, rm = self._modrm(c, size, size)
            return _mk("xadd", [rm, reg], opsize=size)
        # --- a handful of SSE/crypto-relevant ops (operands best-effort) ---
        if op in (0x10, 0x11, 0x28, 0x29, 0x6E, 0x6F, 0x7E, 0x7F, 0x57, 0xEF, 0xD6, 0x12, 0x13):
            reg, rm = self._modrm(c, 16, 16, xmm=True)
            name = {0x10: "movups", 0x11: "movups", 0x28: "movaps", 0x29: "movaps",
                    0x6E: "movd", 0x6F: "movdqa", 0x7E: "movd", 0x7F: "movdqa",
                    0x57: "xorps", 0xEF: "pxor", 0xD6: "movq", 0x12: "movlps",
                    0x13: "movlps"}[op]
            if op in (0x11, 0x29, 0x7F, 0xD6, 0x13):
                return _mk(name, [rm, reg], opsize=16)
            return _mk(name, [reg, rm], opsize=16)
        if op in (0x38, 0x3A):  # three-byte AES/SSE4 — consume modrm, mark generic
            _third = c.cur.u8()
            reg, rm = self._modrm(c, 16, 16, xmm=True)
            return _mk("sse3b", [reg, rm], opsize=16)

        return _mk("db", [_imm(0x0F, 1)], opsize=1)

    # ---- ModRM / SIB ------------------------------------------------------
    def _peek_reg(self, c: "_Ctx") -> int:
        b = c.cur.d[c.cur.p]
        return (b >> 3) & 7

    def _modrm(self, c: "_Ctx", reg_size: int, rm_size: int,
               force_mem: bool = False, xmm: bool = False):
        modrm = c.cur.u8()
        mod = modrm >> 6
        reg_f = ((modrm >> 3) & 7) | (c.rex.r << 3)
        rm_f = (modrm & 7)
        if xmm:
            reg_op = Operand(OpKind.REG, reg=XMM[reg_f & 0xF], size=16)
        else:
            reg_op = Operand(OpKind.REG, reg=reg_name(reg_f, reg_size, c.rex.present), size=reg_size)

        if mod == 3 and not force_mem:
            full = rm_f | (c.rex.b << 3)
            rm_op = (Operand(OpKind.REG, reg=XMM[full & 0xF], size=16) if xmm
                     else Operand(OpKind.REG, reg=reg_name(full, rm_size, c.rex.present), size=rm_size))
            return reg_op, rm_op

        rm_op = self._mem(c, mod, rm_f, rm_size)
        return reg_op, rm_op

    def _modrm_rm_only(self, c: "_Ctx", rm_size: int):
        """Return ``(reg_field_value, rm_operand)`` for group opcodes."""
        modrm = c.cur.u8()
        mod = modrm >> 6
        reg_f = (modrm >> 3) & 7
        rm_f = modrm & 7
        if mod == 3:
            full = rm_f | (c.rex.b << 3)
            return reg_f, Operand(OpKind.REG, reg=reg_name(full, rm_size, c.rex.present), size=rm_size)
        return reg_f, self._mem(c, mod, rm_f, rm_size)

    def _mem(self, c: "_Ctx", mod: int, rm_f: int, size: int) -> Operand:
        cur = c.cur
        base = index = None
        scale = 1
        disp = 0
        rip = False
        if rm_f == 4:  # SIB
            sib = cur.u8()
            scale = 1 << (sib >> 6)
            idx = ((sib >> 3) & 7) | (c.rex.x << 3)
            bse = (sib & 7) | (c.rex.b << 3)
            if ((sib >> 3) & 7) != 4 or c.rex.x:  # index present (esp index = none unless REX.X)
                if idx != 4:
                    index = reg_name(idx, 8, True)
            if (sib & 7) == 5 and mod == 0:
                disp = cur.s32()
                base = None
            else:
                base = reg_name(bse, 8, True)
        elif rm_f == 5 and mod == 0:  # RIP-relative
            disp = cur.s32()
            rip = True
        else:
            base = reg_name(rm_f | (c.rex.b << 3), 8, True)

        if mod == 1:
            disp = cur.s8()
        elif mod == 2:
            disp = cur.s32()

        op = Operand(OpKind.MEM, base=base, index=index, scale=scale, disp=disp,
                     seg=c.seg, rip_relative=rip, size=size)
        return op

    # ---- branches ---------------------------------------------------------
    def _branch(self, c: "_Ctx", mnem: str, rel: int, rel8: bool) -> Instruction:
        # target resolved after length known; we stash rel and fix up in _decode
        insn = _mk(mnem, [Operand(OpKind.REL, value=rel, size=1 if rel8 else 4)])
        insn._pending_rel = rel  # type: ignore[attr-defined]
        return insn

    def _alu_form(self, c: "_Ctx", mnem: str, form: int) -> Instruction:
        if form == 0:   # Eb, Gb
            reg, rm = self._modrm(c, 1, 1)
            return _mk(mnem, [rm, reg], opsize=1)
        if form == 1:   # Ev, Gv
            reg, rm = self._modrm(c, c.opsize, c.opsize)
            return _mk(mnem, [rm, reg], opsize=c.opsize)
        if form == 2:   # Gb, Eb
            reg, rm = self._modrm(c, 1, 1)
            return _mk(mnem, [reg, rm], opsize=1)
        if form == 3:   # Gv, Ev
            reg, rm = self._modrm(c, c.opsize, c.opsize)
            return _mk(mnem, [reg, rm], opsize=c.opsize)
        if form == 4:   # AL, Ib
            return _mk(mnem, [Operand(OpKind.REG, reg="al", size=1), _imm(c.cur.u8(), 1)], opsize=1)
        # form == 5: eAX, Iz
        return _mk(mnem, [Operand(OpKind.REG, reg=reg_name(0, c.opsize, c.rex.present), size=c.opsize),
                          _imm(c.cur.s32() if c.opsize != 2 else c.cur.s16(), c.opsize)], opsize=c.opsize)


class _Ctx:
    __slots__ = ("cur", "addr", "rex", "seg", "opsize", "rep", "lock", "mode64", "prefixes")

    def __init__(self, cur, addr, rex, seg, opsize, rep, lock, mode64, prefixes):
        self.cur = cur
        self.addr = addr
        self.rex = rex
        self.seg = seg
        self.opsize = opsize
        self.rep = rep
        self.lock = lock
        self.mode64 = mode64
        self.prefixes = prefixes

    def addr_start(self, cur):  # unused helper kept for clarity
        return self.addr


def _mk(mnem: str, operands, opsize: int = 0) -> Instruction:
    return Instruction(address=0, length=0, mnemonic=mnem, operands=list(operands), opsize=opsize)


def _imm(value: int, size: int) -> Operand:
    return Operand(OpKind.IMM, value=value, size=size)


_SUB2IDX = {name: i for tbl in (R32, R16, R8, R8L) for i, name in enumerate(tbl)}


def _promote64(op: Operand) -> None:
    """Bump a register operand to its 64-bit form (e.g. eax -> rax)."""
    op.size = 8
    if op.kind is OpKind.REG and op.reg in _SUB2IDX and op.reg not in R64:
        op.reg = R64[_SUB2IDX[op.reg]]


# --- module-level convenience ---------------------------------------------
_DEFAULT = Decoder(mode64=True)


def decode(data: bytes, addr: int = 0, offset: int = 0, mode64: bool = True) -> Optional[Instruction]:
    dec = _DEFAULT if mode64 else Decoder(mode64=False)
    insn = dec.decode(data, addr=addr, offset=offset)
    if insn is not None:
        _resolve_rel(insn)
    return insn


def disassemble(data: bytes, addr: int = 0, mode64: bool = True,
                max_insns: int = 100000):
    """Linear-sweep disassembly. Yields :class:`Instruction` objects."""
    dec = Decoder(mode64=mode64)
    off = 0
    produced = 0
    while off < len(data) and produced < max_insns:
        insn = dec.decode(data, addr=addr + off, offset=off)
        if insn is None or insn.length == 0:
            break
        _resolve_rel(insn)
        yield insn
        off += insn.length
        produced += 1


def _resolve_rel(insn: Instruction) -> None:
    rel = getattr(insn, "_pending_rel", None)
    if rel is None:
        return
    target = insn.address + insn.length + rel
    insn.target = target & 0xFFFFFFFFFFFFFFFF
    for o in insn.operands:
        if o.kind is OpKind.REL:
            o.value = insn.target

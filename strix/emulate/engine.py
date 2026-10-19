"""The sandboxed emulator core: address space, registers, flags, step loop.

Safety invariants (enforced here, not by convention):
  * no syscalls / interrupts — they immediately stop emulation;
  * no control transfer outside mapped memory — stops emulation;
  * a hard instruction-count cap and a bounded memory arena;
  * writes are recorded so a caller can diff out decoded data.
There is deliberately no way for emulated code to perform I/O of any kind.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..disasm.model import Instruction, Operand, OpKind
from ..disasm.x86 import R8, R8L, R16, R32, R64, Decoder

MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}

# name -> (parent64, size, is_high8)
_REGMAP: dict[str, tuple[str, int, bool]] = {}
for _i, _n in enumerate(R64):
    _REGMAP[_n] = (_n, 8, False)
    _REGMAP[R32[_i]] = (_n, 4, False)
    _REGMAP[R16[_i]] = (_n, 2, False)
    _REGMAP[R8[_i]] = (_n, 1, False)
for _i, _n in enumerate(R8L):
    if _n not in _REGMAP:  # ah/ch/dh/bh
        _REGMAP[_n] = (R64[_i & 3], 1, _n.endswith("h") and _i >= 4)
_REGMAP["ah"] = ("rax", 1, True)
_REGMAP["ch"] = ("rcx", 1, True)
_REGMAP["dh"] = ("rdx", 1, True)
_REGMAP["bh"] = ("rbx", 1, True)


class EmulationLimit(Exception):
    """Raised internally when a sandbox boundary is hit."""


_PAGE = 0x1000


class AddressSpace:
    """Sparse, page-backed flat memory with write tracking and a size cap."""

    def __init__(self, cap_bytes: int = 64 * 1024 * 1024):
        self.pages: dict[int, bytearray] = {}
        self.mapped: set[int] = set()        # pages that were explicitly mapped
        self.writes: dict[int, int] = {}      # addr -> byte (decoded output)
        self.cap = cap_bytes

    def map_bytes(self, addr: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self._page(addr + i, create=True)[ (addr + i) & (_PAGE - 1) ] = b
            self.mapped.add((addr + i) >> 12)

    def _page(self, addr: int, create: bool) -> Optional[bytearray]:
        pn = addr >> 12
        pg = self.pages.get(pn)
        if pg is None:
            if not create:
                return None
            if len(self.pages) * _PAGE >= self.cap:
                raise EmulationLimit("memory cap exceeded")
            pg = bytearray(_PAGE)
            self.pages[pn] = pg
        return pg

    def is_mapped(self, addr: int) -> bool:
        return (addr >> 12) in self.mapped

    def read(self, addr: int, size: int) -> int:
        val = 0
        for i in range(size):
            pg = self._page(addr + i, create=False)
            b = pg[(addr + i) & (_PAGE - 1)] if pg is not None else 0
            val |= b << (8 * i)
        return val

    def write(self, addr: int, value: int, size: int) -> None:
        for i in range(size):
            b = (value >> (8 * i)) & 0xFF
            self._page(addr + i, create=True)[(addr + i) & (_PAGE - 1)] = b
            self.writes[addr + i] = b

    def read_bytes(self, addr: int, size: int) -> bytes:
        return bytes(self.read(addr + i, 1) for i in range(size))


@dataclass
class Registers:
    vals: dict[str, int] = field(default_factory=lambda: {r: 0 for r in R64})
    rip: int = 0
    flags: int = 0  # bit0 CF, 2 PF, 4 AF, 6 ZF, 7 SF, 11 OF

    def get(self, name: str) -> int:
        parent, size, high = _REGMAP[name]
        v = self.vals[parent]
        if high:
            return (v >> 8) & 0xFF
        return v & MASK[size]

    def set(self, name: str, value: int) -> None:
        parent, size, high = _REGMAP[name]
        value &= MASK[size]
        if high:
            self.vals[parent] = (self.vals[parent] & ~0xFF00) | (value << 8)
        elif size == 4:
            self.vals[parent] = value            # 32-bit write zero-extends
        else:
            self.vals[parent] = (self.vals[parent] & ~MASK[size]) | value


# flag bit positions
CF, PF, AF, ZF, SF, OF = 0, 2, 4, 6, 7, 11


class Emulator:
    def __init__(self, space: AddressSpace, max_steps: int = 200_000,
                 stack_base: int = 0x7FFF0000, stack_size: int = 0x40000):
        self.space = space
        self.regs = Registers()
        self.max_steps = max_steps
        self.steps = 0
        self.decoder = Decoder(mode64=True)
        self.call_depth = 0
        self.stopped_reason = ""
        # set up a stack
        self.space.map_bytes(stack_base, b"\x00" * stack_size)
        self.regs.set("rsp", stack_base + stack_size - 0x100)
        self.regs.set("rbp", self.regs.get("rsp"))
        self._ret_sentinel = 0xDEADBEEF00000000

    # -- flag helpers -------------------------------------------------------
    def _gf(self, bit: int) -> int:
        return (self.regs.flags >> bit) & 1

    def _sf(self, bit: int, on: bool) -> None:
        if on:
            self.regs.flags |= (1 << bit)
        else:
            self.regs.flags &= ~(1 << bit)

    def _set_zsp(self, result: int, size: int) -> None:
        result &= MASK[size]
        self._sf(ZF, result == 0)
        self._sf(SF, (result >> (size * 8 - 1)) & 1 == 1)
        self._sf(PF, bin(result & 0xFF).count("1") % 2 == 0)

    # -- operand access -----------------------------------------------------
    def _ea(self, op: Operand) -> int:
        addr = op.disp
        if op.rip_relative:
            addr += self.regs.rip
        elif op.base:
            addr += self.regs.get(op.base)
        if op.index:
            addr += self.regs.get(op.index) * op.scale
        return addr & MASK[8]

    def read_op(self, op: Operand) -> int:
        if op.kind is OpKind.REG:
            return self.regs.get(op.reg)
        if op.kind is OpKind.IMM or op.kind is OpKind.REL:
            return op.value & MASK[op.size or 8]
        return self.space.read(self._ea(op), op.size or 8)

    def write_op(self, op: Operand, value: int) -> None:
        if op.kind is OpKind.REG:
            self.regs.set(op.reg, value)
        elif op.kind is OpKind.MEM:
            self.space.write(self._ea(op), value & MASK[op.size or 8], op.size or 8)

    # -- main loop ----------------------------------------------------------
    def run(self, start: int) -> str:
        self.regs.rip = start
        # push a return sentinel so the top-level function's ret ends the run
        self._push(self._ret_sentinel)
        try:
            while self.steps < self.max_steps:
                self.steps += 1
                if not self.space.is_mapped(self.regs.rip):
                    return self._stop("rip left mapped memory")
                code = self.space.read_bytes(self.regs.rip, 16)
                insn = self.decoder.decode(code, addr=self.regs.rip, offset=0)
                if insn is None or insn.length == 0 or insn.mnemonic == "db":
                    return self._stop("undecodable instruction")
                from ..disasm.x86 import _resolve_rel
                _resolve_rel(insn)
                nxt = self.regs.rip + insn.length
                cont = self._exec(insn, nxt)
                if cont is None:
                    return self.stopped_reason or "halted"
                self.regs.rip = cont
            return self._stop("step cap reached")
        except EmulationLimit as e:
            return self._stop(str(e))
        except Exception as e:
            return self._stop(f"fault: {e!r}")

    def _stop(self, reason: str) -> str:
        self.stopped_reason = reason
        return reason

    # -- stack --------------------------------------------------------------
    def _push(self, value: int) -> None:
        sp = (self.regs.get("rsp") - 8) & MASK[8]
        self.regs.set("rsp", sp)
        self.space.write(sp, value & MASK[8], 8)

    def _pop(self) -> int:
        sp = self.regs.get("rsp")
        val = self.space.read(sp, 8)
        self.regs.set("rsp", (sp + 8) & MASK[8])
        return val

    # -- execution ----------------------------------------------------------
    def _exec(self, ins: Instruction, nxt: int) -> Optional[int]:
        m = ins.mnemonic
        ops = ins.operands

        if m in ("nop", "pause", "cld", "std", "clc", "stc", "cmc", "prefetch",
                 "cdqe", "cwde", "cdq", "cqo", "endbr64", "sse3b"):
            return nxt
        if m in ("hlt", "ud2"):
            self._stop("hlt/ud2"); return None
        if m == "syscall" or m == "int":
            self._stop("syscall/int (sandbox: no OS)"); return None
        if m in ("rdtsc",):
            self.regs.set("rax", 0); self.regs.set("rdx", 0); return nxt
        if m == "cpuid":
            for r in ("rax", "rbx", "rcx", "rdx"):
                self.regs.set(r, 0)
            return nxt

        if m == "mov":
            self.write_op(ops[0], self.read_op(ops[1])); return nxt
        if m in ("movzx",):
            self.write_op(ops[0], self.read_op(ops[1]) & MASK[ops[1].size]); return nxt
        if m == "movsx":
            self.write_op(ops[0], _sext(self.read_op(ops[1]), ops[1].size)); return nxt
        if m == "lea":
            self.write_op(ops[0], self._ea(ops[1])); return nxt
        if m == "push":
            self._push(_sext(self.read_op(ops[0]), ops[0].size) if ops[0].kind is OpKind.IMM
                       else self.read_op(ops[0])); return nxt
        if m == "pop":
            self.write_op(ops[0], self._pop()); return nxt
        if m == "xchg":
            a, b = self.read_op(ops[0]), self.read_op(ops[1])
            self.write_op(ops[0], b); self.write_op(ops[1], a); return nxt

        if m in ("add", "sub", "adc", "sbb", "cmp", "xor", "or", "and", "test"):
            return self._alu(m, ops, nxt)
        if m in ("inc", "dec"):
            sz = ops[0].size or 8
            v = self.read_op(ops[0])
            r = (v + 1 if m == "inc" else v - 1) & MASK[sz]
            self.write_op(ops[0], r); self._set_zsp(r, sz); return nxt
        if m in ("neg",):
            sz = ops[0].size or 8
            v = self.read_op(ops[0]); r = (-v) & MASK[sz]
            self.write_op(ops[0], r); self._set_zsp(r, sz); self._sf(CF, v != 0); return nxt
        if m in ("not",):
            sz = ops[0].size or 8
            self.write_op(ops[0], (~self.read_op(ops[0])) & MASK[sz]); return nxt
        if m in ("mul", "imul") and len(ops) == 1:
            sz = ops[0].size or 8
            a = self.regs.get({1: "al", 2: "ax", 4: "eax", 8: "rax"}[sz])
            res = (a * self.read_op(ops[0]))
            self.regs.set({1: "ax", 2: "ax", 4: "eax", 8: "rax"}[sz], res & MASK[sz])
            if sz >= 4:
                self.regs.set({4: "edx", 8: "rdx"}[sz], (res >> (sz * 8)) & MASK[sz])
            return nxt
        if m == "imul":
            if len(ops) == 2:
                r = self.read_op(ops[0]) * self.read_op(ops[1])
            else:  # 3-operand
                r = self.read_op(ops[1]) * _sext(self.read_op(ops[2]), ops[2].size)
            self.write_op(ops[0], r & MASK[ops[0].size or 8]); return nxt
        if m in ("div", "idiv"):
            sz = ops[0].size or 8
            d = self.read_op(ops[0]) or 1
            a = self.regs.get({1: "ax", 2: "ax", 4: "eax", 8: "rax"}[sz])
            self.regs.set({1: "al", 2: "ax", 4: "eax", 8: "rax"}[sz], (a // d) & MASK[sz])
            return nxt

        if m in ("shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr"):
            return self._shift(m, ops, nxt)

        if m in ("jmp",):
            if ops[0].kind is OpKind.REL:
                return ins.target
            tgt = self.read_op(ops[0])
            return tgt
        if m.startswith("j") and m != "jmp":  # Jcc / jrcxz / jecxz
            return self._jcc(m, ins, nxt)
        if m in ("loop", "loope", "loopne"):
            rcx = (self.regs.get("rcx") - 1) & MASK[8]
            self.regs.set("rcx", rcx)
            take = rcx != 0
            if m == "loope":
                take = take and self._gf(ZF)
            elif m == "loopne":
                take = take and not self._gf(ZF)
            return ins.target if take else nxt

        if m == "call":
            self._push(nxt)
            self.call_depth += 1
            if self.call_depth > 256:
                self._stop("call depth exceeded"); return None
            if ops[0].kind is OpKind.REL:
                return ins.target
            tgt = self.read_op(ops[0])
            if not self.space.is_mapped(tgt):
                # calling an unmapped import — skip it, return 0 in rax
                self._pop()
                self.call_depth -= 1
                self.regs.set("rax", 0)
                return nxt
            return tgt
        if m == "ret":
            ret = self._pop()
            self.call_depth = max(0, self.call_depth - 1)
            if ops and ops[0].kind is OpKind.IMM:
                self.regs.set("rsp", (self.regs.get("rsp") + ops[0].value) & MASK[8])
            if ret == self._ret_sentinel:
                self._stop("returned from top function"); return None
            return ret
        if m == "leave":
            self.regs.set("rsp", self.regs.get("rbp"))
            self.regs.set("rbp", self._pop())
            return nxt
        if m.startswith("set"):  # setcc
            self.write_op(ops[0], 1 if self._cond(m[3:]) else 0); return nxt
        if m.startswith("cmov"):
            if self._cond(m[4:]):
                self.write_op(ops[0], self.read_op(ops[1]))
            return nxt
        if m in ("movsb", "movsd", "stosb", "stosd", "lodsb", "lodsd",
                 "scasb", "scasd", "cmpsb", "cmpsd", "rep movsb", "rep movsd",
                 "rep stosb", "rep stosd"):
            return self._string_op(m, nxt)

        # unknown but decoded — treat as nop to keep going
        return nxt

    # -- instruction families ----------------------------------------------
    def _alu(self, m: str, ops, nxt):
        sz = ops[0].size or 8
        a = self.read_op(ops[0])
        b = self.read_op(ops[1])
        if ops[1].kind is OpKind.IMM and ops[1].size < sz:
            b = _sext(b, ops[1].size) & MASK[sz]
        if m in ("add", "adc"):
            c = self._gf(CF) if m == "adc" else 0
            r = (a + b + c) & MASK[sz]
            self._sf(CF, a + b + c > MASK[sz])
            self._sf(OF, (~(a ^ b) & (a ^ r) >> (sz * 8 - 1)) & 1 == 1)
        elif m in ("sub", "sbb", "cmp"):
            c = self._gf(CF) if m == "sbb" else 0
            r = (a - b - c) & MASK[sz]
            self._sf(CF, a < b + c)
            self._sf(OF, ((a ^ b) & (a ^ r) >> (sz * 8 - 1)) & 1 == 1)
        elif m == "xor":
            r = (a ^ b) & MASK[sz]; self._sf(CF, False); self._sf(OF, False)
        elif m == "or":
            r = (a | b) & MASK[sz]; self._sf(CF, False); self._sf(OF, False)
        elif m in ("and", "test"):
            r = (a & b) & MASK[sz]; self._sf(CF, False); self._sf(OF, False)
        else:
            r = a
        self._set_zsp(r, sz)
        if m not in ("cmp", "test"):
            self.write_op(ops[0], r)
        return nxt

    def _shift(self, m: str, ops, nxt):
        sz = ops[0].size or 8
        bits = sz * 8
        v = self.read_op(ops[0])
        amt = self.read_op(ops[1]) & (0x3F if sz == 8 else 0x1F)
        if amt == 0:
            return nxt
        if m in ("shl", "sal"):
            r = (v << amt) & MASK[sz]
        elif m == "shr":
            r = (v & MASK[sz]) >> amt
        elif m == "sar":
            r = _sext(v, sz) >> amt
        elif m == "rol":
            a = amt % bits
            r = ((v << a) | (v >> (bits - a))) & MASK[sz]
        elif m == "ror":
            a = amt % bits
            r = ((v >> a) | (v << (bits - a))) & MASK[sz]
        else:  # rcl/rcr — approximate without CF-through for triage
            a = amt % bits
            r = ((v << a) | (v >> (bits - a))) & MASK[sz]
        r &= MASK[sz]
        self.write_op(ops[0], r)
        self._set_zsp(r, sz)
        return nxt

    def _string_op(self, m: str, nxt):
        # single-iteration (or short rep) byte/dword copy/store — bounded
        size = 1 if m.endswith("b") else 4
        rep = m.startswith("rep ")
        base = m.split()[-1]
        n = (self.regs.get("rcx") if rep else 1)
        n = min(n, 0x10000)
        for _ in range(n):
            si, di = self.regs.get("rsi"), self.regs.get("rdi")
            if base == "movsd" or base == "movsb":
                self.space.write(di, self.space.read(si, size), size)
                self.regs.set("rsi", si + size); self.regs.set("rdi", di + size)
            elif base.startswith("stos"):
                self.space.write(di, self.regs.get({1: "al", 4: "eax"}[size]), size)
                self.regs.set("rdi", di + size)
            elif base.startswith("lods"):
                self.regs.set({1: "al", 4: "eax"}[size], self.space.read(si, size))
                self.regs.set("rsi", si + size)
            else:
                break
        if rep:
            self.regs.set("rcx", 0)
        return nxt

    # -- conditions ---------------------------------------------------------
    def _cond(self, cc: str) -> bool:
        f = self._gf
        table = {
            "o": f(OF), "no": not f(OF), "b": f(CF), "ae": not f(CF),
            "e": f(ZF), "ne": not f(ZF), "be": f(CF) or f(ZF), "a": not f(CF) and not f(ZF),
            "s": f(SF), "ns": not f(SF), "p": f(PF), "np": not f(PF),
            "l": f(SF) != f(OF), "ge": f(SF) == f(OF),
            "le": f(ZF) or (f(SF) != f(OF)), "g": not f(ZF) and (f(SF) == f(OF)),
        }
        return table.get(cc, False)

    def _jcc(self, m: str, ins: Instruction, nxt):
        if m in ("jrcxz", "jecxz"):
            take = self.regs.get("rcx" if m == "jrcxz" else "ecx") == 0
        else:
            take = self._cond(m[1:])
        return ins.target if take else nxt


def _sext(value: int, size: int) -> int:
    value &= MASK[size]
    if value >> (size * 8 - 1):
        return value - (1 << (size * 8))
    return value

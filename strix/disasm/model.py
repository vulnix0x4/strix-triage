"""Instruction / operand model shared by the disassembler and emulator."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class OpKind(enum.Enum):
    REG = "reg"
    MEM = "mem"
    IMM = "imm"
    REL = "rel"   # branch displacement, already resolved to an absolute target


@dataclass
class Operand:
    kind: OpKind
    # REG: ``reg`` = canonical name ("rax", "eax", "al", "r8d", ...)
    reg: Optional[str] = None
    # MEM: effective address = seg:[base + index*scale + disp]
    base: Optional[str] = None
    index: Optional[str] = None
    scale: int = 1
    disp: int = 0
    seg: Optional[str] = None       # "fs"/"gs" when a segment prefix is present
    rip_relative: bool = False
    # IMM / REL
    value: int = 0
    # width of this operand access in bytes (1/2/4/8)
    size: int = 0

    # -- rendering ----------------------------------------------------------
    def render(self) -> str:
        if self.kind is OpKind.REG:
            return self.reg or "?"
        if self.kind is OpKind.IMM:
            return _hex(self.value)
        if self.kind is OpKind.REL:
            return _hex(self.value)
        # memory
        parts = []
        if self.rip_relative:
            parts.append("rip")
        elif self.base:
            parts.append(self.base)
        if self.index:
            parts.append(f"{self.index}*{self.scale}" if self.scale != 1 else self.index)
        inner = "+".join(parts) if parts else ""
        if self.disp or not inner:
            sign = "+" if (self.disp >= 0 and inner) else ("-" if self.disp < 0 else "")
            inner += f"{sign}{_hex(abs(self.disp))}" if inner else _hex(self.disp)
        sz = {1: "byte", 2: "word", 4: "dword", 8: "qword"}.get(self.size, "")
        seg = f"{self.seg}:" if self.seg else ""
        return f"{sz} ptr {seg}[{inner}]".strip()


@dataclass
class Instruction:
    address: int
    length: int
    mnemonic: str
    operands: list[Operand] = field(default_factory=list)
    raw: bytes = b""
    opsize: int = 0                 # operation width in bytes
    prefixes: list[str] = field(default_factory=list)
    # branch target absolute address, when statically known
    target: Optional[int] = None

    @property
    def end(self) -> int:
        return self.address + self.length

    def render(self) -> str:
        ops = ", ".join(o.render() for o in self.operands)
        pre = (" ".join(p for p in self.prefixes if p in ("rep", "repne", "lock")) + " ").lstrip()
        return f"{pre}{self.mnemonic}{(' ' + ops) if ops else ''}".strip()

    def __str__(self) -> str:
        return f"{self.address:#010x}  {self.raw.hex():<20}  {self.render()}"


def _hex(v: int) -> str:
    return f"-0x{-v:x}" if v < 0 else f"0x{v:x}"

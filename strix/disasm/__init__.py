"""Pure-Python x86/x86-64 disassembler (triage subset).

This is not a full-ISA decoder — it covers the instruction families that
actually show up in malware entry stubs, decryptors, and shellcode: data
movement, the ALU groups, shifts/rotates, branches, calls, stack ops, PEB
access, and the syscall/cpuid/rdtsc family. Anything it can't decode becomes a
``db`` byte so the stream never desynchronises fatally.

The same ``Instruction`` objects feed both the textual disassembly and the
sandboxed emulator (``strix.emulate``), so decode semantics live in exactly one
place.
"""

from .model import Instruction, Operand, OpKind
from .x86 import Decoder, decode, disassemble

__all__ = ["Instruction", "Operand", "OpKind", "Decoder", "decode", "disassemble"]

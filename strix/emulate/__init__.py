"""A tiny, sandboxed x86-64 emulator for defensive string recovery.

The emulator is an abstract interpreter, not a runtime. It has **no operating
system**: there are no syscalls, no file/registry/network/process access, and
no way to call out of the mapped image. Execution is bounded by a hard
instruction cap and a flat, size-limited memory arena. Its only purpose is to
replay self-contained decode routines (stack-string builders, XOR/ROL
decryptors whose key and data are both embedded) so an analyst can read the
strings the author tried to hide — exactly the technique Mandiant's FLOSS uses.
"""

from .engine import Emulator, AddressSpace, EmulationLimit

__all__ = ["Emulator", "AddressSpace", "EmulationLimit"]

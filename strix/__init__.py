"""Strix — static malware triage & analysis framework.

Strix safely dissects suspicious binaries *without running them as programs*. It
parses PE/ELF/Mach-O, hashes, measures entropy, extracts strings/IOCs, maps
imported APIs to ATT&CK, matches heuristic signatures, disassembles code to spot
malware patterns, and replays self-contained decode routines in a fully
sandboxed emulator (no OS, no syscalls, no I/O) to recover obfuscated strings.
The sample is never executed as a program; the emulator only abstract-interprets
isolated decode stubs, exactly as defensive tools like FLOSS do.
"""

__version__ = "0.2.0"
__all__ = ["__version__"]

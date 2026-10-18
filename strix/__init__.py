"""Strix — static malware triage & analysis framework.

Strix safely dissects suspicious binaries *without executing them*. Everything
it does is read-only static analysis: parsing headers, hashing, measuring
entropy, extracting strings/IOCs, mapping imported APIs to ATT&CK techniques,
and matching heuristic signatures. It never runs the sample.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]

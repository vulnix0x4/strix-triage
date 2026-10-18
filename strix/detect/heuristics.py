"""Structural heuristics that turn parser observations into findings.

These are deliberately conservative and explainable — each returns a
:class:`Finding` with concrete evidence so an analyst can audit *why* the score
moved, rather than trusting a black box.
"""

from __future__ import annotations

from ..core.model import Finding, Severity
from ..parsers.base import ParsedBinary

# Keywords in a parser anomaly string → (severity, attack-ids)
_ANOMALY_SEVERITY = [
    ("writable AND executable", Severity.MEDIUM, ("T1055",)),
    ("W^X", Severity.MEDIUM, ("T1055",)),
    ("RWX", Severity.MEDIUM, ("T1055",)),
    ("high entropy", Severity.MEDIUM, ("T1027.002",)),
    ("packed", Severity.MEDIUM, ("T1027.002",)),
    ("overlay data", Severity.LOW, ()),
    ("entry point", Severity.HIGH, ("T1027",)),
    ("no section headers", Severity.MEDIUM, ("T1027.002",)),
    ("encrypted segment", Severity.HIGH, ("T1027",)),
    ("packer artifact", Severity.MEDIUM, ("T1027.002",)),
    ("timestamp", Severity.LOW, ("T1070.006",)),
    ("unsigned", Severity.INFO, ()),
]


def _severity_for(anomaly: str):
    low = anomaly.lower()
    for kw, sev, attack in _ANOMALY_SEVERITY:
        if kw.lower() in low:
            return sev, list(attack)
    return Severity.LOW, []


def from_parsed(pb: ParsedBinary) -> list[Finding]:
    findings: list[Finding] = []

    # 1) structural anomalies recorded by the parser
    for i, anomaly in enumerate(pb.anomalies):
        sev, attack = _severity_for(anomaly)
        findings.append(Finding(
            id=f"struct.anomaly.{i}",
            title=anomaly,
            severity=sev,
            category="structure",
            description="Structural anomaly detected during parsing.",
            attack=attack,
        ))

    # 2) PE mitigation posture (legit software usually ships these)
    if pb.format == "pe" and pb.bits:
        dchars = pb.extra.get("dll_characteristics", [])
        missing = []
        if "dynamic-base-aslr" not in dchars:
            missing.append("ASLR")
        if "nx-compat-dep" not in dchars:
            missing.append("DEP/NX")
        if missing and pb.is_executable:
            findings.append(Finding(
                id="struct.mitigations",
                title=f"Missing exploit mitigations: {', '.join(missing)}",
                severity=Severity.LOW,
                category="structure",
                description="Modern compilers enable these by default; their absence is common in hand-crafted or old malware.",
                evidence=missing,
            ))
        if not pb.extra.get("signed"):
            findings.append(Finding(
                id="struct.unsigned",
                title="No Authenticode security directory (unsigned)",
                severity=Severity.INFO,
                category="structure",
                description="Binary carries no embedded code signature.",
            ))

    # 3) import-table sparsity + packing: strong packer tell
    n_imports = len(pb.imports)
    overall_hi = any(s.entropy >= 7.2 for s in pb.sections if s.raw_size > 0x400)
    if pb.is_executable and n_imports <= 5 and overall_hi:
        findings.append(Finding(
            id="struct.packed_sparse_imports",
            title=f"Very few imports ({n_imports}) alongside high-entropy section(s)",
            severity=Severity.HIGH,
            category="packing",
            description="A runnable binary with almost no imports and packed sections typically resolves its real APIs only after unpacking.",
            attack=["T1027.002"],
        ))

    # 4) TLS callbacks (pre-main execution, favored by anti-analysis)
    if pb.extra.get("has_tls_callbacks"):
        findings.append(Finding(
            id="struct.tls_callbacks",
            title="TLS callbacks present (code runs before entry point)",
            severity=Severity.MEDIUM,
            category="anti-analysis",
            description="TLS callbacks execute before main(), a known anti-debug / early-exec technique.",
            attack=["T1055"],
        ))

    # 5) exported function count on an EXE (not a DLL) is unusual
    if pb.format == "pe" and not pb.is_dll and len(pb.exports) > 0:
        findings.append(Finding(
            id="struct.exe_exports",
            title=f"Non-DLL image exports {len(pb.exports)} function(s)",
            severity=Severity.LOW,
            category="structure",
            evidence=pb.exports[:10],
        ))

    return findings

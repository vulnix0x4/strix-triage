"""ANSI console renderer for an AnalysisReport."""

from __future__ import annotations

import os
import sys

from ..core.model import AnalysisReport, Severity, Verdict

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if _COLOR else text


_SEV_COLOR = {
    Severity.CRITICAL: "1;37;41", Severity.HIGH: "1;31", Severity.MEDIUM: "1;33",
    Severity.LOW: "36", Severity.INFO: "2;37",
}
_VERDICT_COLOR = {
    Verdict.MALICIOUS: "1;37;41", Verdict.LIKELY_MALICIOUS: "1;31",
    Verdict.SUSPICIOUS: "1;33", Verdict.LOW_RISK: "36", Verdict.CLEAN: "1;32",
}


def _bar(score: int, width: int = 30) -> str:
    filled = round(score / 100 * width)
    color = "1;32" if score < 25 else "1;33" if score < 55 else "1;31"
    return _c(color, "█" * filled) + _c("2;37", "░" * (width - filled))


def render(report: AnalysisReport, show_strings: bool = False) -> str:
    f = report.file
    L: list[str] = []
    L.append(_c("1;36", "╔" + "═" * 62 + "╗"))
    L.append(_c("1;36", "║") + _c("1;37", "  STRIX — static malware triage report".ljust(62)) + _c("1;36", "║"))
    L.append(_c("1;36", "╚" + "═" * 62 + "╝"))
    L.append("")
    L.append(f"  {_c('1;37','File')}      : {f.path}")
    L.append(f"  {_c('1;37','Type')}      : {f.file_type}  ({f.format_family}, {f.arch or 'n/a'})")
    L.append(f"  {_c('1;37','Size')}      : {f.size:,} bytes    entropy {f.entropy:.3f}/8.0")
    L.append(f"  {_c('1;37','SHA256')}    : {f.hashes.get('sha256','')}")
    L.append(f"  {_c('1;37','MD5')}       : {f.hashes.get('md5','')}")
    if f.hashes.get("imphash"):
        L.append(f"  {_c('1;37','imphash')}   : {f.hashes['imphash']}")
    L.append(f"  {_c('1;37','fuzzy')}     : {f.hashes.get('fuzzy','')}")
    L.append("")

    verdict = report.verdict
    L.append("  " + _c("1;37", "VERDICT   : ") +
             _c(_VERDICT_COLOR[verdict], f" {verdict.value.upper()} "))
    L.append(f"  {_c('1;37','THREAT    :')} {_bar(report.score)} {report.score}/100")
    L.append("")

    # findings by category
    grouped = report.findings_by_category()
    if not grouped:
        L.append("  " + _c("1;32", "No findings — nothing notable surfaced."))
    for cat, items in grouped.items():
        L.append("  " + _c("1;4;37", cat.upper()))
        for fnd in items:
            tag = _c(_SEV_COLOR[fnd.severity], f"[{fnd.severity.label.upper():^8}]")
            L.append(f"    {tag} {fnd.title}")
            if fnd.attack:
                L.append(f"              {_c('2;37','ATT&CK: ' + ', '.join(fnd.attack))}")
            for e in fnd.evidence[:6]:
                L.append(f"              {_c('2;37','↳ ' + _trunc(str(e)))}")
        L.append("")

    if report.attack_techniques:
        L.append("  " + _c("1;4;37", "ATT&CK TECHNIQUES OBSERVED"))
        L.append("    " + _c("36", ", ".join(report.attack_techniques)))
        L.append("")

    if show_strings:
        sample = report.sections.get("strings_sample", [])
        L.append("  " + _c("1;4;37", f"STRINGS (showing {len(sample)} of {report.sections.get('strings_total',0)})"))
        for s in sample[:120]:
            L.append(f"    {_c('2;37', s['offset']and hex(s['offset']) or '0x0')}  {_trunc(s['value'], 90)}")
        L.append("")

    if report.errors:
        L.append("  " + _c("1;33", "WARNINGS"))
        for e in report.errors:
            L.append(f"    - {e}")
        L.append("")

    L.append(_c("2;37", "  (static analysis only — the sample was never executed)"))
    return "\n".join(L)


def _trunc(s: str, n: int = 100) -> str:
    s = s.replace("\n", "\\n").replace("\r", "\\r")
    return s if len(s) <= n else s[: n - 1] + "…"

"""Analysis orchestrator — runs the full static pipeline over one file.

Pipeline (all read-only, the sample is never executed):

    file bytes → type/hash/entropy → format parser → capability mapping
    → structural heuristics → string & IOC extraction → signature engine
    → assembled AnalysisReport
"""

from __future__ import annotations

import datetime as _dt
import os
from typing import Optional

from .. import __version__
from ..detect import capabilities, engine, heuristics
from ..disasm import disassemble
from ..disasm.analyze import analyze_code
from ..emulate.strings import recover_strings
from ..extractors import iocs as ioc_mod
from ..extractors import strings as str_mod
from ..parsers import elf as elf_p
from ..parsers import macho as macho_p
from ..parsers import pe as pe_p
from . import entropy as ent_mod
from . import filetype, hashing
from .model import AnalysisReport, FileFacts, Finding, Severity

# A sample of extracted strings kept in the report (full set is still scanned).
_STRINGS_IN_REPORT = 400
# Cap individual-capability weight so one API spammed 50× can't dominate.
_MAX_CAP_MULT = 2.0


class Analyzer:
    def __init__(self, extra_rule_paths: Optional[list[str]] = None,
                 use_bundled_rules: bool = True, min_string_len: int = 5,
                 deep_code: bool = True):
        self.min_string_len = min_string_len
        self.deep_code = deep_code  # disassembly + sandboxed emulation stages
        self.rules = engine.load_bundled() if use_bundled_rules else []
        if extra_rule_paths:
            self.rules += engine.load_paths(extra_rule_paths)

    # -- public API ---------------------------------------------------------
    def analyze_file(self, path: str) -> AnalysisReport:
        with open(path, "rb") as fh:
            data = fh.read()
        return self.analyze_bytes(data, path=path)

    def analyze_bytes(self, data: bytes, path: str = "<memory>") -> AnalysisReport:
        started = _utcnow()
        facts = self._facts(data, path)
        report = AnalysisReport(file=facts, tool_version=__version__, started_at=started)

        pb = self._parse(data, facts, report)
        if pb is not None:
            self._run_capabilities(pb, report)
            for f in heuristics.from_parsed(pb):
                report.add(f)
            report.add_section("binary", pb.to_dict())
            report.add_section("imports", self._import_summary(pb))
            if pb.format == "pe":
                facts.hashes["imphash"] = hashing.imphash(pb.imports) or ""

        # strings are extracted once and shared by IOC + emulation stages
        extracted = str_mod.extract(data, min_len=self.min_string_len)
        values = [s.value for s in extracted]
        report.add_section("strings_total", len(extracted))
        report.add_section("strings_sample", [s.to_dict() for s in extracted[:_STRINGS_IN_REPORT]])

        self._run_iocs(values, report, origin="static")
        if pb is not None and self.deep_code:
            self._run_code_analysis(data, pb, values, report)
        self._run_signatures(data, facts, report)

        report.finished_at = _utcnow()
        return report

    # -- stages -------------------------------------------------------------
    def _facts(self, data: bytes, path: str) -> FileFacts:
        ftype, mime, family = filetype.detect(data)
        facts = FileFacts(
            path=os.path.abspath(path) if path != "<memory>" else path,
            size=len(data), file_type=ftype, mime=mime, format_family=family,
            hashes=hashing.file_digests(path) if os.path.isfile(path) else _mem_digests(data),
            entropy=round(ent_mod.shannon(data), 4),
        )
        facts.hashes["fuzzy"] = hashing.fuzzy_hash(data)
        return facts

    def _parse(self, data, facts: FileFacts, report: AnalysisReport):
        try:
            fam = facts.format_family
            if fam == "pe" and pe_p.is_pe(data):
                pb = pe_p.parse(data)
            elif fam == "elf" and elf_p.is_elf(data):
                pb = elf_p.parse(data)
            elif fam == "macho" and macho_p.is_macho(data):
                pb = macho_p.parse(data)
            else:
                return None
            facts.arch = pb.arch
            return pb
        except Exception as exc:  # parsers are tolerant, but never let one crash a scan
            report.note_error(f"parser error ({facts.format_family}): {exc!r}")
            return None

    def _run_capabilities(self, pb, report: AnalysisReport):
        hits, grouped = capabilities.analyze(pb.imports)
        if grouped:
            report.add_section("capabilities", grouped)
        # one finding per capability, evidence = the symbols that triggered it
        per_cap: dict[str, list] = {}
        for rule, sym in hits:
            per_cap.setdefault(rule.capability, []).append((rule, sym))
        for cap, items in per_cap.items():
            rule = items[0][0]
            syms = sorted({s for _r, s in items})
            mult = min(_MAX_CAP_MULT, 1.0 + 0.1 * (len(syms) - 1))
            report.add(Finding(
                id=f"cap.{cap.replace(' ', '_')}",
                title=f"Capability: {cap}",
                severity=rule.severity,
                category="capability",
                description=rule.note or f"Imports enabling: {cap}.",
                evidence=syms[:12],
                attack=list(rule.attack),
                weight_multiplier=mult,
            ))

    def _run_iocs(self, values, report: AnalysisReport, origin: str = "static"):
        iset = ioc_mod.extract(values)
        tag = "" if origin == "static" else f" [from {origin}]"
        sfx = "" if origin == "static" else f".{origin}"
        if origin == "static":
            report.add_section("iocs", iset.to_dict())
        elif iset.total():
            report.add_section(f"iocs_{origin}", iset.to_dict())

        if iset.urls or iset.ipv4 or iset.domains or iset.ipv6:
            ev = (iset.urls[:8] + iset.ipv4[:8] + iset.domains[:8])[:16]
            onion = any(".onion" in u for u in iset.urls) or any(d.endswith(".onion") for d in iset.domains)
            report.add(Finding(
                id=f"ioc.network{sfx}",
                title=f"Network indicators{tag} ({len(iset.urls)} URL, {len(iset.ipv4)} IPv4, {len(iset.domains)} domain)",
                severity=Severity.HIGH if origin != "static" and (iset.urls or iset.domains)
                else (Severity.MEDIUM if (iset.urls or iset.domains) else Severity.LOW),
                category="ioc",
                description="Hard-coded network endpoints may be C2 or download infrastructure."
                + ("" if origin == "static" else " Recovered only after emulation — deliberately hidden."),
                evidence=ev,
                attack=["T1071"] + (["T1573"] if onion else []),
            ))
        if iset.crypto:
            report.add(Finding(
                id=f"ioc.crypto_address{sfx}",
                title=f"Cryptocurrency address(es){tag} ({len(iset.crypto)})",
                severity=Severity.MEDIUM, category="ioc",
                description="Wallet addresses are common in ransomware and clipboard-hijack coinstealers.",
                evidence=iset.crypto[:8], attack=["T1486"]))
        if iset.suspicious:
            report.add(Finding(
                id=f"ioc.suspicious_strings{sfx}",
                title=f"Suspicious command/technique strings{tag} ({len(iset.suspicious)})",
                severity=Severity.HIGH if len(iset.suspicious) >= 3 or origin != "static" else Severity.MEDIUM,
                category="ioc",
                description="Strings matching known offensive tradecraft (LOLBins, PowerShell, persistence)."
                + ("" if origin == "static" else " Revealed by sandboxed emulation."),
                evidence=iset.suspicious[:12], attack=["T1059"],
                weight_multiplier=min(_MAX_CAP_MULT, 1.0 + 0.08 * len(iset.suspicious))))
        if iset.evasion:
            report.add(Finding(
                id=f"ioc.evasion_strings{sfx}",
                title=f"Sandbox/VM/analysis-tool awareness{tag} ({len(iset.evasion)})",
                severity=Severity.MEDIUM, category="anti-analysis",
                description="References to VM, sandbox or debugger product names suggest evasion checks.",
                evidence=iset.evasion[:12], attack=["T1497"]))
        if iset.pdb and origin == "static":
            report.add(Finding(
                id="ioc.pdb_path", title="Debug PDB path leaked",
                severity=Severity.INFO, category="ioc",
                description="Build path can attribute/cluster the sample.",
                evidence=iset.pdb[:5]))

    def _run_code_analysis(self, data: bytes, pb, static_values, report: AnalysisReport):
        image_base = pb.extra.get("image_base", 0) or 0
        segments: list[tuple[int, bytes]] = []
        exec_sections: list[tuple[int, bytes, str]] = []
        for s in pb.sections:
            if s.raw_size <= 0 or s.offset < 0:
                continue
            body = data[s.offset:s.offset + s.raw_size]
            if not body:
                continue
            va = (image_base + s.vaddr) if pb.format == "pe" else s.vaddr
            if va <= 0:
                continue
            segments.append((va, body))
            if "execute" in s.characteristics:
                exec_sections.append((va, body, s.name))
        if not exec_sections:
            return

        # --- static disassembly heuristics --------------------------------
        insns = []
        for va, body, _name in exec_sections[:4]:
            insns.extend(disassemble(body, addr=va, max_insns=12000))
        if insns:
            stats, code_findings = analyze_code(insns)
            for f in code_findings:
                report.add(f)
            top = sorted(stats.mnemonics.items(), key=lambda kv: kv[1], reverse=True)[:15]
            report.add_section("code", {
                "instructions_decoded": stats.count,
                "undecodable": stats.invalid,
                "top_mnemonics": dict(top),
                "disasm_sample": [str(i) for i in insns[:80]],
            })

        # --- sandboxed emulation: recover hidden strings ------------------
        entry_points = []
        if pb.entry_point:
            ev = (image_base + pb.entry_point) if pb.format == "pe" else pb.entry_point
            entry_points.append(ev)
        try:
            recovered = recover_strings(segments, entry_points, static_values)
        except Exception as exc:  # emulation must never break a scan
            report.note_error(f"emulation error: {exc!r}")
            return
        if recovered:
            report.add_section("decoded_strings", [r.to_dict() for r in recovered[:200]])
            report.add(Finding(
                id="emulation.decoded_strings",
                title=f"Emulation recovered {len(recovered)} hidden string(s)",
                severity=Severity.HIGH,
                category="anti-analysis",
                description="Strings that do not appear statically were reconstructed by sandboxed emulation of the sample's own decode routines (stack strings / self-decrypting data).",
                evidence=[r.value[:100] for r in recovered[:12]],
                attack=["T1027", "T1140"],
                weight_multiplier=min(_MAX_CAP_MULT, 1.0 + 0.05 * len(recovered)),
            ))
            # feed decoded strings back through IOC/suspicious detection
            self._run_iocs([r.value for r in recovered], report, origin="emulation")

    def _run_signatures(self, data: bytes, facts: FileFacts, report: AnalysisReport):
        if not self.rules:
            return
        matches = engine.scan(data, self.rules, filesize=facts.size, entropy=facts.entropy)
        report.add_section("signatures", [
            {"rule": m.rule, "meta": m.meta, "evidence": m.evidence()} for m in matches
        ])
        for m in matches:
            sev = Severity.from_str(m.meta.get("severity", "medium"))
            report.add(Finding(
                id=f"sig.{m.rule}",
                title=f"Signature: {m.rule}",
                severity=sev,
                category=m.meta.get("category", "signature"),
                description=m.meta.get("description", ""),
                evidence=m.evidence(),
                attack=m.meta.get("attack", []) if isinstance(m.meta.get("attack"), list) else [],
            ))

    @staticmethod
    def _import_summary(pb) -> dict:
        return {
            "count": len(pb.imports),
            "libraries": {lib: fns for lib, fns in sorted(pb.imported_libs.items())},
            "exports": pb.exports[:200],
        }


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mem_digests(data: bytes) -> dict:
    import hashlib
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

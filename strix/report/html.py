"""Self-contained HTML renderer — one file, no external assets, dark theme."""

from __future__ import annotations

import html
import json

from ..core.model import AnalysisReport, Severity, Verdict

_SEV_CLASS = {
    Severity.CRITICAL: "crit", Severity.HIGH: "high", Severity.MEDIUM: "med",
    Severity.LOW: "low", Severity.INFO: "info",
}
_VERDICT_CLASS = {
    Verdict.MALICIOUS: "crit", Verdict.LIKELY_MALICIOUS: "high",
    Verdict.SUSPICIOUS: "med", Verdict.LOW_RISK: "low", Verdict.CLEAN: "clean",
}


def _e(x) -> str:
    return html.escape(str(x), quote=True)


def render(report: AnalysisReport) -> str:
    f = report.file
    v = report.verdict
    score = report.score

    rows = []
    for cat, items in report.findings_by_category().items():
        rows.append(f'<h3 class="cat">{_e(cat)}</h3>')
        for fnd in items:
            sev = _SEV_CLASS[fnd.severity]
            ev = "".join(f'<li>{_e(e)}</li>' for e in fnd.evidence[:12])
            attack = ""
            if fnd.attack:
                chips = "".join(
                    f'<a class="att" href="https://attack.mitre.org/techniques/{_e(t.replace(".","/"))}/" '
                    f'target="_blank" rel="noopener">{_e(t)}</a>' for t in fnd.attack)
                attack = f'<div class="attack">{chips}</div>'
            rows.append(
                f'<div class="finding {sev}">'
                f'<div class="fhead"><span class="sev {sev}">{_e(fnd.severity.label.upper())}</span>'
                f'<span class="ftitle">{_e(fnd.title)}</span></div>'
                f'{f"<p class=fdesc>{_e(fnd.description)}</p>" if fnd.description else ""}'
                f'{attack}'
                f'{f"<ul class=ev>{ev}</ul>" if ev else ""}'
                f'</div>')
    findings_html = "\n".join(rows) or '<p class="none">No findings — nothing notable surfaced.</p>'

    # sections: binary layout table
    binary = report.sections.get("binary", {})
    sec_rows = ""
    for s in binary.get("sections", []):
        hot = "hot" if s.get("entropy", 0) >= 7.2 else ""
        sec_rows += (f'<tr class="{hot}"><td>{_e(s["name"])}</td>'
                     f'<td>{s.get("vaddr",0):#x}</td><td>{s.get("raw_size",0):,}</td>'
                     f'<td>{s.get("entropy",0):.3f}</td>'
                     f'<td>{_e(", ".join(s.get("characteristics",[])))}</td></tr>')
    sec_table = (f'<table class="grid"><thead><tr><th>Section</th><th>VAddr</th>'
                 f'<th>Raw size</th><th>Entropy</th><th>Flags</th></tr></thead>'
                 f'<tbody>{sec_rows}</tbody></table>') if sec_rows else ""

    # imports
    imp = report.sections.get("imports", {})
    imp_html = ""
    for lib, fns in (imp.get("libraries") or {}).items():
        items = "".join(f"<code>{_e(fn)}</code>" for fn in fns[:60])
        imp_html += f'<details><summary>{_e(lib)} <span class="muted">({len(fns)})</span></summary><div class="imps">{items}</div></details>'

    # IOCs
    iocs = report.sections.get("iocs", {})
    ioc_html = ""
    for key, vals in iocs.items():
        if not vals:
            continue
        lis = "".join(f"<li>{_e(x)}</li>" for x in vals[:50])
        ioc_html += f'<details><summary>{_e(key)} <span class="muted">({len(vals)})</span></summary><ul class="ioc">{lis}</ul></details>'

    attack_chips = "".join(
        f'<a class="att" href="https://attack.mitre.org/techniques/{_e(t.replace(".","/"))}/" '
        f'target="_blank" rel="noopener">{_e(t)}</a>' for t in report.attack_techniques)

    raw_json = _e(json.dumps(report.to_dict(), indent=2, default=str))

    return _TEMPLATE.format(
        title=_e(f.path.split("/")[-1] or "sample"),
        path=_e(f.path), ftype=_e(f.file_type), family=_e(f.format_family),
        arch=_e(f.arch or "n/a"), size=f"{f.size:,}", entropy=f"{f.entropy:.3f}",
        sha256=_e(f.hashes.get("sha256", "")), md5=_e(f.hashes.get("md5", "")),
        sha1=_e(f.hashes.get("sha1", "")),
        imphash=_e(f.hashes.get("imphash", "—") or "—"), fuzzy=_e(f.hashes.get("fuzzy", "")),
        verdict=_e(v.value.upper()), vclass=_VERDICT_CLASS[v], score=score,
        dash=f"{score*3.39:.1f} 339",
        findings=findings_html, sections=sec_table, imports=imp_html or '<p class="muted">none</p>',
        iocs=ioc_html or '<p class="muted">none</p>', attack=attack_chips or '<span class="muted">none</span>',
        started=_e(report.started_at), version=_e(report.tool_version), rawjson=raw_json,
    )


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Strix · {title}</title>
<style>
:root{{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--line:#30363d;--fg:#e6edf3;
--muted:#8b949e;--crit:#f85149;--high:#ff7b72;--med:#e3b341;--low:#58a6ff;--info:#6e7681;--clean:#3fb950;}}
*{{box-sizing:border-box}}
body{{margin:0;font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
background:var(--bg);color:var(--fg)}}
.wrap{{max-width:1040px;margin:0 auto;padding:28px 20px 80px}}
header{{display:flex;align-items:center;gap:14px;border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:22px}}
.logo{{font-size:30px}}
h1{{font-size:20px;margin:0}}
h1 small{{color:var(--muted);font-weight:400;font-size:13px}}
.top{{display:grid;grid-template-columns:260px 1fr;gap:20px;margin-bottom:26px}}
@media(max-width:720px){{.top{{grid-template-columns:1fr}}}}
.gauge{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;text-align:center}}
.ring{{position:relative;width:150px;height:150px;margin:4px auto 10px}}
.ring svg{{transform:rotate(-90deg)}}
.ring .val{{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}}
.ring .val b{{font-size:34px}}
.ring .val span{{color:var(--muted);font-size:12px}}
.badge{{display:inline-block;padding:5px 14px;border-radius:999px;font-weight:700;letter-spacing:.5px;font-size:13px}}
.facts{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px}}
.facts dl{{display:grid;grid-template-columns:120px 1fr;gap:6px 12px;margin:0}}
.facts dt{{color:var(--muted)}} .facts dd{{margin:0;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}}
section{{margin-bottom:24px}}
h2{{font-size:15px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);border-bottom:1px solid var(--line);padding-bottom:6px}}
.cat{{margin:18px 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--low)}}
.finding{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:8px;padding:12px 14px;margin:8px 0}}
.finding.crit{{border-left-color:var(--crit)}} .finding.high{{border-left-color:var(--high)}}
.finding.med{{border-left-color:var(--med)}} .finding.low{{border-left-color:var(--low)}}
.fhead{{display:flex;align-items:center;gap:10px}}
.ftitle{{font-weight:600}}
.sev{{font-size:10.5px;font-weight:800;padding:2px 7px;border-radius:5px;letter-spacing:.5px}}
.sev.crit{{background:var(--crit);color:#000}} .sev.high{{background:var(--high);color:#000}}
.sev.med{{background:var(--med);color:#000}} .sev.low{{background:var(--low);color:#000}} .sev.info{{background:var(--info);color:#000}}
.fdesc{{margin:7px 0 4px;color:var(--muted)}}
.ev{{margin:6px 0 2px;padding-left:18px;color:#adbac7;font-family:ui-monospace,Menlo,monospace;font-size:12px}}
.ev li{{word-break:break-all}}
.attack{{margin-top:6px;display:flex;flex-wrap:wrap;gap:6px}}
.att{{background:var(--panel2);border:1px solid var(--line);color:var(--low);text-decoration:none;
font-size:11px;padding:2px 8px;border-radius:6px}}
.att:hover{{border-color:var(--low)}}
table.grid{{width:100%;border-collapse:collapse;font-size:12.5px}}
.grid th,.grid td{{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);font-family:ui-monospace,Menlo,monospace}}
.grid th{{color:var(--muted);font-family:inherit}}
.grid tr.hot td{{color:var(--med)}}
details{{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:6px 0;padding:4px 12px}}
summary{{cursor:pointer;font-weight:600}}
.imps code{{display:inline-block;background:var(--panel2);border:1px solid var(--line);border-radius:5px;
padding:1px 6px;margin:3px;font-size:11.5px}}
ul.ioc{{columns:2;font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}}
.muted{{color:var(--muted)}} .none{{color:var(--clean)}}
pre.raw{{background:#010409;border:1px solid var(--line);border-radius:8px;padding:14px;overflow:auto;
font-size:11.5px;max-height:460px}}
footer{{color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px;margin-top:30px}}
.att-row{{display:flex;flex-wrap:wrap;gap:6px}}
</style></head>
<body><div class="wrap">
<header><div class="logo">🦉</div><div><h1>Strix triage report</h1>
<small>{path}</small></div></header>

<div class="top">
  <div class="gauge">
    <div class="ring"><svg width="150" height="150" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="54" fill="none" stroke="#30363d" stroke-width="10"/>
      <circle cx="60" cy="60" r="54" fill="none" stroke="currentColor" stroke-width="10"
        stroke-linecap="round" stroke-dasharray="{dash}" class="arc-{vclass}"/>
    </svg><div class="val"><b>{score}</b><span>/ 100</span></div></div>
    <span class="badge sev {vclass}">{verdict}</span>
  </div>
  <div class="facts"><dl>
    <dt>Type</dt><dd>{ftype} · {family} · {arch}</dd>
    <dt>Size</dt><dd>{size} bytes</dd>
    <dt>Entropy</dt><dd>{entropy} / 8.0</dd>
    <dt>SHA-256</dt><dd>{sha256}</dd>
    <dt>SHA-1</dt><dd>{sha1}</dd>
    <dt>MD5</dt><dd>{md5}</dd>
    <dt>imphash</dt><dd>{imphash}</dd>
    <dt>fuzzy</dt><dd>{fuzzy}</dd>
  </dl></div>
</div>

<section><h2>Findings</h2>{findings}</section>
<section><h2>ATT&amp;CK techniques</h2><div class="att-row">{attack}</div></section>
<section><h2>Section / segment layout</h2>{sections}</section>
<section><h2>Imports</h2>{imports}</section>
<section><h2>Indicators of compromise</h2>{iocs}</section>
<section><h2>Raw JSON</h2><details><summary>show machine-readable report</summary><pre class="raw">{rawjson}</pre></details></section>

<footer>Generated by Strix v{version} · {started} · <strong>Static analysis only — the sample was never executed.</strong></footer>
</div>
<style>
.arc-crit{{color:var(--crit)}}.arc-high{{color:var(--high)}}.arc-med{{color:var(--med)}}
.arc-low{{color:var(--low)}}.arc-clean{{color:var(--clean)}}
</style>
</body></html>"""

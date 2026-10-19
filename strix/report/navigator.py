"""Export findings as a MITRE ATT&CK Navigator layer.

The output JSON loads directly into https://mitre-attack.github.io/attack-navigator/
so an analyst can see a sample's observed techniques highlighted on the matrix,
colored by the severity of the finding that observed them.
"""

from __future__ import annotations

import json

from ..core.model import AnalysisReport, Severity

_SEV_SCORE = {
    Severity.INFO: 20, Severity.LOW: 40, Severity.MEDIUM: 60,
    Severity.HIGH: 80, Severity.CRITICAL: 100,
}


def build_layer(report: AnalysisReport) -> dict:
    # highest-severity finding per technique, plus the titles that observed it
    best: dict[str, Severity] = {}
    comments: dict[str, list[str]] = {}
    for f in report.findings:
        for t in f.attack:
            # Navigator keys sub-techniques as "T1055.001"
            if t not in best or f.severity > best[t]:
                best[t] = f.severity
            comments.setdefault(t, [])
            if f.title not in comments[t]:
                comments[t].append(f.title)

    techniques = [{
        "techniqueID": t,
        "score": _SEV_SCORE[sev],
        "comment": "; ".join(comments[t][:6]),
        "enabled": True,
        "metadata": [{"name": "max-severity", "value": sev.label}],
    } for t, sev in sorted(best.items())]

    name = report.file.path.split("/")[-1] or "sample"
    return {
        "name": f"Strix · {name}",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (f"Strix static-triage techniques for {name} "
                        f"(verdict: {report.verdict.value}, score {report.score}/100). "
                        f"SHA256 {report.file.hashes.get('sha256','')}."),
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe766", "#ffaa00", "#ff6b6b", "#b30000"],
            "minValue": 0, "maxValue": 100,
        },
        "legendItems": [
            {"label": "info/low", "color": "#ffe766"},
            {"label": "medium", "color": "#ffaa00"},
            {"label": "high", "color": "#ff6b6b"},
            {"label": "critical", "color": "#b30000"},
        ],
        "sorting": 3,
        "hideDisabled": True,
    }


def render(report: AnalysisReport) -> str:
    return json.dumps(build_layer(report), indent=2)

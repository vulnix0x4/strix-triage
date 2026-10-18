"""Data model for an analysis run.

The whole pipeline writes into an :class:`AnalysisReport`. Renderers (console,
JSON, HTML) only ever read from it, so adding an output format never touches
analysis logic.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class Severity(enum.IntEnum):
    """Ordered so that ``max()`` over findings gives the worst one."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]


# How many points a single finding of each severity contributes to the 0-100
# threat score. Tuned so that one CRITICAL or a cluster of HIGHs crosses the
# "malicious" line, while a handful of LOW/INFO stays in "suspicious".
SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 4,
    Severity.MEDIUM: 12,
    Severity.HIGH: 28,
    Severity.CRITICAL: 55,
}


class Verdict(enum.Enum):
    CLEAN = "clean"
    LOW_RISK = "low-risk"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely-malicious"
    MALICIOUS = "malicious"

    @classmethod
    def from_score(cls, score: int) -> "Verdict":
        if score >= 80:
            return cls.MALICIOUS
        if score >= 55:
            return cls.LIKELY_MALICIOUS
        if score >= 25:
            return cls.SUSPICIOUS
        if score >= 8:
            return cls.LOW_RISK
        return cls.CLEAN


@dataclass
class Finding:
    """A single observation that may raise the threat score.

    ``category`` groups findings in the report (e.g. ``packing``, ``capability``,
    ``signature``, ``ioc``). ``attack`` holds MITRE ATT&CK technique IDs when
    known, so the report can be pivoted by adversary behavior.
    """

    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    # Multiplier for repeated/clustered evidence; capped later during scoring.
    weight_multiplier: float = 1.0

    def score_contribution(self) -> float:
        return SEVERITY_WEIGHT[self.severity] * self.weight_multiplier

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


@dataclass
class FileFacts:
    """Immutable facts about the input file."""

    path: str
    size: int
    file_type: str = "unknown"
    mime: str = "application/octet-stream"
    format_family: str = "unknown"  # pe / elf / macho / script / archive / data
    arch: Optional[str] = None
    hashes: dict[str, str] = field(default_factory=dict)
    entropy: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisReport:
    file: FileFacts
    findings: list[Finding] = field(default_factory=list)
    # Free-form structured sections produced by parsers/extractors, surfaced
    # in JSON/HTML output (imports, sections, strings sample, IOCs, ...).
    sections: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    tool_version: str = ""
    started_at: str = ""
    finished_at: str = ""

    # ---- mutation helpers -------------------------------------------------
    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_section(self, name: str, data: Any) -> None:
        self.sections[name] = data

    def note_error(self, msg: str) -> None:
        self.errors.append(msg)

    # ---- derived values ---------------------------------------------------
    @property
    def score(self) -> int:
        raw = sum(f.score_contribution() for f in self.findings)
        # Saturating curve: diminishing returns past the first few strong hits
        # so a noisy file with many weak findings can't trivially hit 100.
        score = 100 * (1 - 0.5 ** (raw / 60.0))
        return int(round(min(100.0, score)))

    @property
    def verdict(self) -> Verdict:
        return Verdict.from_score(self.score)

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def attack_techniques(self) -> list[str]:
        seen: list[str] = []
        for f in self.findings:
            for t in f.attack:
                if t not in seen:
                    seen.append(t)
        return sorted(seen)

    def findings_by_category(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in sorted(self.findings, key=lambda x: x.severity, reverse=True):
            out.setdefault(f.category, []).append(f)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "file": self.file.to_dict(),
            "score": self.score,
            "verdict": self.verdict.value,
            "max_severity": self.max_severity.label,
            "attack_techniques": self.attack_techniques,
            "findings": [f.to_dict() for f in sorted(
                self.findings, key=lambda x: x.severity, reverse=True)],
            "sections": self.sections,
            "errors": self.errors,
        }

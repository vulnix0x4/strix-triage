"""JSON renderer — stable schema for pipelines / SIEM ingestion."""

from __future__ import annotations

import json

from ..core.model import AnalysisReport


def render(report: AnalysisReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False, default=str)

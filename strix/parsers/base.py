"""Common parsed-binary representation shared by every format parser."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class ParsedSection:
    name: str
    vaddr: int = 0
    vsize: int = 0
    raw_size: int = 0
    offset: int = 0
    entropy: float = 0.0
    characteristics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ParsedBinary:
    """Format-neutral view a capability engine can reason about."""

    format: str
    arch: str = "unknown"
    bits: int = 0
    endian: str = "little"
    entry_point: int = 0
    timestamp: Optional[int] = None
    is_dll: bool = False
    is_executable: bool = True
    subsystem: Optional[str] = None
    sections: list[ParsedSection] = field(default_factory=list)
    # Fully-qualified imported symbols, ``library.function`` order-preserved.
    imports: list[str] = field(default_factory=list)
    imported_libs: dict[str, list[str]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    # Human-readable structural anomalies worth a finding.
    anomalies: list[str] = field(default_factory=list)
    characteristics: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["sections"] = [s.to_dict() for s in self.sections]
        return d

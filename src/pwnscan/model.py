from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class BinaryInfo:
    format: str
    bits: int
    endian: str
    architecture: str
    entrypoint: Optional[int]
    image_base: Optional[int] = None
    imports: List[str] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    mitigations: Dict[str, Optional[bool]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    evidence: List[str]
    attack_vector: str
    validation: List[str]
    patch: str
    exploit_status: str = "validation-only"
    flag_path: str = "Manual confirmation required before a flag-recovery payload exists."


@dataclass(frozen=True)
class ScanReport:
    schema: str
    target: str
    sha256: str
    size: int
    binary: BinaryInfo
    findings: List[Finding]

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

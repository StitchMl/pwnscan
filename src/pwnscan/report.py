from __future__ import annotations

import json
import os
import sys
from typing import Dict

from .model import ScanReport


COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"


def render_json(report: ScanReport, pretty: bool = False) -> str:
    return json.dumps(report.as_dict(), indent=2 if pretty else None, sort_keys=True, separators=None if pretty else (",", ":"), ensure_ascii=True)


def render_text(report: ScanReport, color: bool = False) -> str:
    binary = report.binary
    lines = [
        "pwnscan %s %s-bit %s" % (binary.format, binary.bits, binary.architecture),
        "target: %s" % report.target,
        "sha256: %s" % report.sha256,
        "entrypoint: %s" % ("unknown" if binary.entrypoint is None else hex(binary.entrypoint)),
        "mitigations: " + ", ".join("%s=%s" % (key, _state(value)) for key, value in sorted(binary.mitigations.items())),
        "imports: " + (", ".join(binary.imports) if binary.imports else "none found"),
        "",
    ]
    for finding in report.findings:
        label = "[%s] %s %s" % (finding.severity.upper(), finding.id, finding.title)
        if color:
            label = COLORS[finding.severity] + label + RESET
        lines.extend([
            label,
            "  confidence: %s" % finding.confidence,
            "  exploit: %s" % finding.exploit_status,
            "  flag path: %s" % finding.flag_path,
        ])
        for evidence in finding.evidence:
            lines.append("  evidence: %s" % evidence)
        lines.append("  vector: %s" % finding.attack_vector)
        for step in finding.validation:
            lines.append("  validate: %s" % step)
        lines.extend(["  patch: %s" % finding.patch, ""])
    return "\n".join(lines).rstrip() + "\n"


def _state(value: object) -> str:
    return "unknown" if value is None else ("on" if value else "off")


def use_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

from __future__ import annotations

import json
import os
import sys

from .model import ScanReport

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"

SEVERITY_SUMMARY_ORDER = ("critical", "high", "medium", "low", "info")
RULE = "-" * 60
FIELD_WIDTH = 12


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
        "findings: " + _summary(report.findings),
        "",
    ]
    for finding in report.findings:
        label = "[%s] %s %s" % (finding.severity.upper(), finding.id, finding.title)
        if color:
            label = COLORS[finding.severity] + label + RESET
        lines.extend([RULE, label])
        lines.append(_field("confidence", finding.confidence))
        lines.append(_field("exploit", finding.exploit_status))
        lines.append(_field("flag path", finding.flag_path))
        for evidence in finding.evidence:
            lines.append(_field("evidence", evidence))
        lines.append(_field("vector", finding.attack_vector))
        for step in finding.validation:
            lines.append(_field("validate", step))
        lines.append(_field("patch", finding.patch))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _field(key: str, value: str) -> str:
    return "  " + (key + ":").ljust(FIELD_WIDTH) + value


def _summary(findings) -> str:
    if not findings:
        return "none"
    counts: dict = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    parts = ["%d %s" % (counts[severity], severity) for severity in SEVERITY_SUMMARY_ORDER if counts.get(severity)]
    return "%d (%s)" % (len(findings), ", ".join(parts))


def _state(value: object) -> str:
    if value is None:
        return "unknown"
    return "on" if value else "off"


def use_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

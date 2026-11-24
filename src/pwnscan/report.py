from __future__ import annotations

import json
import os
import shutil
import sys
import textwrap

from .model import GUARDED_PREFIX, ScanReport

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"
DIM = "\033[2m"
GREEN = "\033[32m"
BOLD_GREEN = "\033[1;32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD_CYAN = "\033[1;36m"

CONFIDENCE_COLORS = {"high": BOLD_CYAN, "medium": YELLOW, "low": DIM}

SEVERITY_SUMMARY_ORDER = ("critical", "high", "medium", "low", "info")
RULE = "-" * 60
FIELD_WIDTH = 12


def render_json(report: ScanReport, pretty: bool = False) -> str:
    return json.dumps(report.as_dict(), indent=2 if pretty else None, sort_keys=True, separators=None if pretty else (",", ":"), ensure_ascii=True)


def _wrap_width(width: int | None = None) -> int:
    if width is not None:
        return max(40, width)
    columns = shutil.get_terminal_size((100, 24)).columns
    return max(72, min(columns, 120))


def _wrap_header(prefix: str, value: str, width: int) -> str:
    if not value:
        return prefix
    body_width = max(20, width - len(prefix))
    wrapped = textwrap.wrap(value, width=body_width, break_long_words=False, break_on_hyphens=False) or [value]
    indent = " " * len(prefix)
    return "\n".join([prefix + wrapped[0]] + [indent + line for line in wrapped[1:]])


def render_text(report: ScanReport, color: bool = False, width: int | None = None) -> str:
    wrap_at = _wrap_width(width)
    binary = report.binary
    mitigations = ", ".join(
        "%s=%s" % (key, _state_colored(value) if color else _state(value))
        for key, value in sorted(binary.mitigations.items())
    )
    imports_text = ", ".join(binary.imports) if binary.imports else "none found"
    lines = [
        "pwnscan %s %s-bit %s" % (binary.format, binary.bits, binary.architecture),
        "target: %s" % report.target,
        "sha256: %s" % report.sha256,
        "entrypoint: %s" % ("unknown" if binary.entrypoint is None else hex(binary.entrypoint)),
        "mitigations: " + mitigations,
        _wrap_header("imports: ", imports_text, wrap_at),
        "findings: " + _summary(report.findings),
        "",
    ]
    for finding in report.findings:
        lines.extend(_render_finding(finding, color, wrap_at))
    return "\n".join(lines).rstrip() + "\n"


def _render_finding(finding, color: bool, wrap_at: int) -> list:
    label = "[%s] %s %s" % (finding.severity.upper(), finding.id, finding.title)
    if color:
        label = COLORS[finding.severity] + label + RESET
    lines = [(DIM + RULE + RESET) if color else RULE, label]
    conf_color = CONFIDENCE_COLORS.get(finding.confidence, "") if color else ""
    exploit_color = BOLD_GREEN if (color and finding.exploit_status == "payload-ready") else ""
    lines.extend([
        _field("confidence", finding.confidence, wrap_at, color=color, value_color=conf_color),
        _field("exploit", finding.exploit_status, wrap_at, color=color, value_color=exploit_color),
        _field("flag path", finding.flag_path, wrap_at, color=color),
    ])
    for evidence in finding.evidence:
        ev_color = DIM if (color and evidence.startswith(GUARDED_PREFIX)) else ""
        lines.append(_field("evidence", evidence, wrap_at, color=color, value_color=ev_color))
    lines.append(_field("vector", finding.attack_vector, wrap_at, color=color))
    lines.extend(_field("validate", step, wrap_at, color=color) for step in finding.validation)
    lines.extend([_field("patch", finding.patch, wrap_at, color=color), ""])
    return lines


def _field(key: str, value: str, width: int = 100, color: bool = False, value_color: str = "") -> str:
    prefix = "  " + (key + ":").ljust(FIELD_WIDTH)
    body_width = max(20, width - len(prefix))
    wrapped = textwrap.wrap(value, width=body_width, break_long_words=False, break_on_hyphens=False) or [value]
    styled_prefix = (DIM + prefix + RESET) if color else prefix
    indent = " " * len(prefix)
    rendered_lines = []
    for idx, part in enumerate(wrapped):
        styled_part = (value_color + part + RESET) if (color and value_color) else part
        rendered_lines.append((styled_prefix if idx == 0 else indent) + styled_part)
    return "\n".join(rendered_lines)


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


def _state_colored(value: object) -> str:
    if value is None:
        return DIM + "unknown" + RESET
    return (GREEN + "on" + RESET) if value else (RED + "off" + RESET)


def use_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

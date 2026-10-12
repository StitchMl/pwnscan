from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable, List, Sequence

from .model import BinaryInfo, Finding, ScanReport
from .parsers import parse_binary


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
UNBOUNDED = {"gets": "reads an unbounded line", "strcpy": "copies without a length", "strcat": "appends without a length", "sprintf": "formats without a destination length", "vsprintf": "formats without a destination length", "scanf": "may use an unbounded %s", "sscanf": "may use an unbounded %s", "fscanf": "may use an unbounded %s"}
FORMAT_SINKS = {"printf", "fprintf", "syslog"}
COMMAND_SINKS = {"system", "popen", "execve", "WinExec", "CreateProcess"}
WIN_NAMES = re.compile(r"(?:^|[^a-z])(win|print[_-]?flag|give[_-]?flag|shell|secret)(?:[^a-z]|$)", re.I)
FLAG_TEXT = re.compile(r"(?:flag|ctf|secret|password|/bin/sh|cat\s+[^\s]*flag)", re.I)


def _finding(identity: str, title: str, severity: str, confidence: str, evidence: Sequence[str], vector: str, validation: Sequence[str], patch: str) -> Finding:
    return Finding(identity, title, severity, confidence, sorted(set(evidence), key=str.lower), vector, list(validation), patch)


def analyze(info: BinaryInfo) -> List[Finding]:
    imports = set(info.imports)
    symbols = set(info.symbols)
    findings: List[Finding] = []

    dangerous = sorted(imports & set(UNBOUNDED), key=str.lower)
    if dangerous:
        reasons = ["%s: %s" % (name, UNBOUNDED[name]) for name in dangerous]
        mitigations = info.mitigations
        nx = mitigations.get("nx")
        canary = mitigations.get("stack_canary")
        if canary is False and nx is False:
            vector = "Find the overwrite offset, control the return address, then jump to injected stack data or a win function."
        elif canary is False:
            vector = "Find the overwrite offset, control the return address, then build a ROP/ret2libc chain or jump to a win function."
        else:
            vector = "Trace attacker-controlled lengths to the destination. If a stack canary blocks return-address control, target adjacent data or leak the canary first."
        findings.append(_finding(
            "PWN-BOF-001", "Probable unbounded memory write", "high", "high", reasons, vector,
            ["Inspect each call site and destination size.", "Generate a cyclic pattern in an isolated challenge runner.", "Confirm control of saved state with a debugger."],
            "Replace unbounded calls with length-aware APIs and reject input larger than the destination.",
        ))

    format_evidence = sorted(imports & FORMAT_SINKS, key=str.lower)
    format_clues = sorted(value for value in info.strings if "%n" in value or re.search(r"%(?:\d+\$)?[pxs]", value))[:8]
    if format_evidence and format_clues:
        findings.append(_finding(
            "PWN-FMT-001", "Format-string attack surface", "high", "medium",
            ["format sink: %s" % item for item in format_evidence] + ["format clue: %s" % item for item in format_clues],
            "Supply positional format specifiers to map the stack. Use reads to disclose pointers or a controlled %n write if the program passes user data as the format string.",
            ["Decompile each sink call and identify the format argument.", "Check whether input reaches that argument unchanged."],
            "Pass a constant format string and provide user data through a value argument.",
        ))

    commands = sorted(imports & COMMAND_SINKS, key=str.lower)
    if commands:
        findings.append(_finding(
            "PWN-CMD-001", "Command execution primitive", "high", "medium",
            ["command sink: %s" % name for name in commands],
            "Trace user-controlled strings into the command argument. Inject a separator or replace an argument to read the flag if the challenge lacks filtering.",
            ["Inspect string construction before the sink.", "Record quoting and the invoked shell or process API."],
            "Avoid shell command construction. Use fixed executable paths and validated argument arrays.",
        ))

    win_symbols = sorted(name for name in symbols if WIN_NAMES.search(name))
    win_strings = sorted((value for value in info.strings if FLAG_TEXT.search(value)), key=str.lower)[:12]
    if win_symbols or win_strings:
        address_note = "PIE requires a code-pointer leak or a relative control transfer." if info.mitigations.get("pie") else "A fixed image may permit a direct ret2win address."
        findings.append(_finding(
            "PWN-WIN-001", "Hidden success path or flag material", "medium", "high" if win_symbols else "medium",
            ["symbol: %s" % name for name in win_symbols] + ["string: %s" % value for value in win_strings],
            "Reach the success routine through a corrupted return address, function pointer, or intended state transition. " + address_note,
            ["Cross-reference each clue.", "List callers and guard conditions for candidate success routines."],
            "Remove dormant privileged paths and keep secrets outside the challenge binary in production software.",
        ))

    missing = [name for name in ("nx", "stack_canary", "pie" if info.format in {"ELF", "Mach-O"} else "aslr") if info.mitigations.get(name) is False]
    if missing:
        findings.append(_finding(
            "PWN-MIT-001", "Exploit mitigations disabled", "medium", "high",
            ["%s disabled" % name for name in sorted(missing)],
            "Use the missing mitigations to simplify an existing memory-corruption vector: fixed code addresses help ROP, no canary helps stack overwrite, and executable memory helps shellcode.",
            ["Confirm loader policy on the challenge host.", "Pair this finding with a controllable corruption primitive."],
            "Enable compiler and linker hardening: stack protector, non-executable memory, PIE/ASLR, RELRO, and platform control-flow protection.",
        ))

    if not findings:
        findings.append(_finding(
            "PWN-TRIAGE-000", "No high-signal static primitive found", "info", "high", [],
            "Review input parsing, integer arithmetic, state transitions, and indirect calls in a decompiler. Static triage cannot prove safety.",
            ["Map all input sources to memory writes.", "Inspect comparisons around flag and success strings."],
            "Apply bounds checks and hardening after manual review identifies the trust boundary.",
        ))
    return sorted(findings, key=lambda finding: (SEVERITY_ORDER[finding.severity], finding.id, tuple(finding.evidence)))


def scan_bytes(data: bytes, target: str = "<memory>") -> ScanReport:
    info = parse_binary(data)
    return ScanReport("pwnscan/v1", target, hashlib.sha256(data).hexdigest(), len(data), info, analyze(info))


def scan_file(path: Path) -> ScanReport:
    data = path.read_bytes()
    return scan_bytes(data, str(path))

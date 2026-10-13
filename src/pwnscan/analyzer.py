from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Iterable, List, Sequence

from .model import BinaryInfo, Finding, ScanReport
from .parsers import parse_binary


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
UNBOUNDED = {"gets": "reads an unbounded line", "strcpy": "copies without a length", "strcat": "appends without a length", "sprintf": "formats without a destination length", "vsprintf": "formats without a destination length", "scanf": "may use an unbounded %s", "sscanf": "may use an unbounded %s", "fscanf": "may use an unbounded %s"}
FORMAT_SINKS = {"printf", "fprintf", "syslog"}
COMMAND_SINKS = {"system", "popen", "execve", "WinExec", "CreateProcess"}
BOUNDED_WRITES = {
    "read": (1, 2), "recv": (1, 2), "recvfrom": (1, 2),
    "memcpy": (0, 2), "memmove": (0, 2), "strncpy": (0, 2),
}
WIN_NAMES = re.compile(r"(?:^|[^a-z])(win|print[_-]?flag|give[_-]?flag|shell|secret)(?:[^a-z]|$)", re.I)
FLAG_TEXT = re.compile(r"(?:flag|ctf|secret|password|/bin/sh|cat\s+[^\s]*flag)", re.I)


def _finding(identity: str, title: str, severity: str, confidence: str, evidence: Sequence[str], vector: str, validation: Sequence[str], patch: str, exploit_status: str = "validation-only", flag_path: str = "Manual confirmation required before a flag-recovery payload exists.") -> Finding:
    return Finding(identity, title, severity, confidence, sorted(set(evidence), key=str.lower), vector, list(validation), patch, exploit_status, flag_path)


def _call_name(call: dict) -> str:
    return str(call.get("to") or "").rsplit("::", 1)[-1].lstrip("_")


def _call_argument(call: dict, index: int) -> dict:
    arguments = call.get("arguments")
    if not isinstance(arguments, list) or index >= len(arguments) or not isinstance(arguments[index], dict):
        return {}
    return arguments[index]


def _dynamic_argument(argument: dict) -> bool:
    return argument.get("kind") in {"dynamic", "stack"}


def _bounded_overflows(calls: Sequence[dict]) -> list[dict]:
    result = []
    for call in calls:
        name = _call_name(call)
        if name not in BOUNDED_WRITES:
            continue
        destination_index, length_index = BOUNDED_WRITES[name]
        destination = _call_argument(call, destination_index)
        length = _call_argument(call, length_index)
        buffer_size = destination.get("buffer_size")
        requested = length.get("value") if length.get("kind") == "constant" else None
        if isinstance(buffer_size, int) and buffer_size > 0 and isinstance(requested, int) and requested > buffer_size:
            result.append({"call": call, "name": name, "buffer_size": buffer_size, "requested": requested, "destination": destination})
    return result


def _exact_ret2win(info: BinaryInfo, bounded: Sequence[dict], win_symbols: Sequence[str], symbol_addresses: dict) -> Finding | None:
    address_key = "pie" if info.format in {"ELF", "Mach-O"} else "aslr"
    if info.mitigations.get("stack_canary") is not False or info.mitigations.get(address_key) is not False:
        return None
    if info.bits not in {32, 64} or info.endian not in {"little", "big"}:
        return None
    addressed = [(name, symbol_addresses.get(name)) for name in win_symbols]
    addressed = [(name, address) for name, address in addressed if isinstance(address, int) and address > 0]
    if not addressed:
        return None
    chosen_name, chosen_address = addressed[0]
    pointer_size = info.bits // 8
    for item in bounded:
        return_offset = item["destination"].get("return_address_offset")
        if not isinstance(return_offset, int) or return_offset <= 0:
            continue
        if item["requested"] < return_offset + pointer_size:
            continue
        payload = (b"A" * return_offset) + chosen_address.to_bytes(pointer_size, info.endian)
        call = item["call"]
        payload_hex = payload.hex()
        return _finding(
            "PWN-FLAG-CHAIN-001", "Verified direct flag-path overwrite", "critical", "high",
            [
                "Ghidra recovered saved return address offset %d for %s at %s" % (return_offset, item["name"], call.get("from")),
                "fixed %s address: 0x%x" % (chosen_name, chosen_address),
                "stack canary disabled; %s disabled" % address_key,
            ],
            "payload_hex=%s; send bytes.fromhex(\"%s\") to the input consumed by %s at %s."
            % (payload_hex, payload_hex, item["name"], call.get("from")),
            [
                "Run only against the authorized challenge instance.",
                "Confirm execution reaches %s and capture its flag output." % chosen_name,
            ],
            "Bound the write to the destination capacity and enable stack canaries plus position-independent code.",
            "payload-ready",
            "The payload overwrites the saved return address with %s (0x%x), the statically identified flag path." % (chosen_name, chosen_address),
        )
    return None


def analyze(info: BinaryInfo) -> List[Finding]:
    imports = set(info.imports)
    symbols = set(info.symbols)
    parsed_imports = set(info.metadata.get("parsed_imports", []))
    string_hints = set(info.metadata.get("string_import_hints", []))
    symbol_addresses = info.metadata.get("symbol_addresses", {})
    ghidra_calls = info.metadata.get("ghidra", {}).get("calls", [])
    findings: List[Finding] = []

    bounded = _bounded_overflows(ghidra_calls)
    if bounded:
        evidence = []
        validation = []
        for item in bounded:
            call = item["call"]
            variable = item["destination"].get("variable") or "stack destination"
            delta = item["requested"] - item["buffer_size"]
            evidence.append(
                "Ghidra call %s at %s in %s writes up to %d bytes into %s (%d bytes); overflow window %d bytes"
                % (item["name"], call.get("from"), call.get("function") or "<unknown>", item["requested"], variable, item["buffer_size"], delta)
            )
            validation.append("Send exactly %d non-newline bytes to the input reaching %s and confirm saved-state corruption in a debugger." % (item["requested"], call.get("from")))
        findings.append(_finding(
            "PWN-BOUNDS-001", "Proven constant-length stack overwrite", "critical", "high", evidence,
            "The decompiler recovered a destination smaller than the requested write. Use a cyclic pattern of the reported request length, measure the saved-state offset, then select ret2win or ROP from the reported mitigations and addresses.",
            validation,
            "Cap each write at the recovered destination size minus required terminator space and reject larger input before the call.",
        ))

    dangerous = sorted(imports & set(UNBOUNDED), key=str.lower)
    if dangerous:
        proven = sorted(set(dangerous) & parsed_imports, key=str.lower)
        hints = sorted(set(dangerous) & string_hints, key=str.lower)
        callsites = [item for item in ghidra_calls if str(item.get("to", "")).rsplit("::", 1)[-1] in dangerous]
        reasons = (["parsed import: %s (%s)" % (name, UNBOUNDED[name]) for name in proven] +
                   ["unverified string hint: %s" % name for name in hints] +
                   ["Ghidra reference: %s in %s -> %s" % (item.get("from"), item.get("function") or "<unknown>", item.get("to")) for item in callsites])
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
            "PWN-BOF-001", "Unbounded memory-write surface", "high" if callsites and "gets" in proven else ("medium" if proven else "low"), "high" if callsites and "gets" in proven else ("medium" if proven else "low"), reasons, vector,
            ["Inspect each call site and destination size.", "Generate a cyclic pattern in an isolated challenge runner.", "Confirm control of saved state with a debugger."],
            "Replace unbounded calls with length-aware APIs and reject input larger than the destination.",
        ))

    format_evidence = sorted(imports & FORMAT_SINKS, key=str.lower)
    format_clues = sorted(value for value in info.strings if "%n" in value or re.search(r"%\d+\$[pxsn]", value))[:8]
    parsed_format = sorted(set(format_evidence) & parsed_imports, key=str.lower)
    dynamic_format_calls = []
    format_indexes = {"printf": 0, "fprintf": 1, "syslog": 1}
    for call in ghidra_calls:
        name = _call_name(call)
        if name in format_indexes and _dynamic_argument(_call_argument(call, format_indexes[name])):
            dynamic_format_calls.append(call)
    if dynamic_format_calls:
        call_evidence = [
            "dynamic format argument at %s in %s -> %s" % (item.get("from"), item.get("function") or "<unknown>", item.get("to"))
            for item in dynamic_format_calls
        ]
        findings.append(_finding(
            "PWN-FMT-001", "Attacker-reachable dynamic format candidate", "high", "high", call_evidence,
            "Send `%p.%p.%p` to confirm pointer disclosure. If the same input reaches `%n`, use a positional write only after mapping the argument index in the isolated CTF runner.",
            ["Compare output for a literal marker and `%p.%p.%p`.", "Confirm the decompiled format argument comes from challenge input."],
            "Pass a constant format such as `%s` and move the dynamic value to a separate argument.",
        ))
    elif parsed_format and format_clues:
        findings.append(_finding(
            "PWN-FMT-001", "Format-string review required", "medium", "low",
            ["parsed format sink: %s" % item for item in parsed_format] + ["format token in binary: %s" % item for item in format_clues],
            "Supply positional format specifiers to map the stack. Use reads to disclose pointers or a controlled %n write if the program passes user data as the format string.",
            ["Decompile each sink call and identify the format argument.", "Check whether input reaches that argument unchanged."],
            "Pass a constant format string and provide user data through a value argument.",
        ))

    commands = sorted(parsed_imports & COMMAND_SINKS, key=str.lower)
    dynamic_command_calls = [
        item for item in ghidra_calls
        if _call_name(item) in COMMAND_SINKS and _dynamic_argument(_call_argument(item, 0))
    ]
    if dynamic_command_calls:
        findings.append(_finding(
            "PWN-CMD-001", "Dynamic command execution candidate", "high", "high",
            ["dynamic command at %s in %s -> %s" % (item.get("from"), item.get("function") or "<unknown>", item.get("to")) for item in dynamic_command_calls],
            "The decompiler recovered a non-constant command argument. Preserve the known prefix and test a shell separator followed by `cat /flag` only inside the authorized challenge runner.",
            ["Inspect how input reaches the command argument.", "Record quoting, allowlists and the invoked shell before choosing a separator."],
            "Avoid shell command construction. Use fixed executable paths and validated argument arrays.",
        ))
    elif commands:
        findings.append(_finding(
            "PWN-CMD-001", "Command execution sink requires data-flow review", "low", "low",
            ["parsed command sink without proven dynamic argument: %s" % name for name in commands],
            "Inspect the command argument. Build a flag-read probe only if challenge input reaches it after quoting and validation.",
            ["Decompile the sink call and trace argument zero."],
            "Keep the executable and argument vector constant or validate each token against an allowlist.",
        ))

    win_symbols = sorted(name for name in symbols if WIN_NAMES.search(name))
    win_strings = sorted((value for value in info.strings if FLAG_TEXT.search(value)), key=str.lower)[:12]
    exact_chain = _exact_ret2win(info, bounded, win_symbols, symbol_addresses)
    if exact_chain is not None:
        findings.append(exact_chain)
    if win_symbols or win_strings:
        addressed = [(name, symbol_addresses[name]) for name in win_symbols if name in symbol_addresses]
        if addressed:
            chosen_name, chosen_address = addressed[0]
            pack = "p64" if info.bits == 64 else "p32"
            target = "ELF-relative offset" if info.mitigations.get("pie") else "virtual address"
            address_note = "%s %s=0x%x; scaffold: payload = b\"A\" * OFFSET + %s(0x%x)." % (target, chosen_name, chosen_address, pack, chosen_address)
        else:
            address_note = "PIE requires a code-pointer leak or relative transfer." if info.mitigations.get("pie") else "Resolve the routine address before building ret2win."
        findings.append(_finding(
            "PWN-WIN-001", "Hidden success path or flag material", "medium", "high" if win_symbols else "medium",
            ["symbol: %s" % name for name in win_symbols] + ["string: %s" % value for value in win_strings],
            "Reach the success routine through a corrupted return address, function pointer, or intended state transition. " + address_note,
            ["Cross-reference each clue.", "List callers and guard conditions for candidate success routines."],
            "Remove dormant privileged paths and keep secrets outside the challenge binary in production software.",
        ))

    rwx_sections = list(info.metadata.get("rwx_sections", []))
    if rwx_sections:
        findings.append(_finding(
            "PWN-RWX-001", "Writable executable memory", "medium", "high",
            ["writable executable section: %s" % name for name in rwx_sections],
            "Place staged code in the reported region only after proving an attacker-controlled write and control transfer.",
            ["Confirm section permissions in the challenge loader.", "Pair this enabler with a proven write primitive."],
            "Remove execute permission from writable sections and enforce W^X in the linker and loader.",
        ))

    gadgets = info.metadata.get("gadgets", {})
    useful_strings = info.metadata.get("useful_strings", {})
    if gadgets or useful_strings:
        evidence = []
        for name, addresses in sorted(gadgets.items()):
            evidence.append("%s: %s" % (name, ", ".join("0x%x" % value for value in addresses[:3])))
        for value, addresses in sorted(useful_strings.items()):
            evidence.append("string %r: %s" % (value, ", ".join("0x%x" % address for address in addresses)))
        findings.append(_finding(
            "PWN-ROP-001", "Addressed exploit primitives", "info", "high", evidence,
            "Use only primitives compatible with the architecture and mitigations. PIE addresses are image-relative until a base leak is known.",
            ["Validate instruction boundaries in a disassembler.", "Rebase addresses when PIE or ASLR is active."],
            "Reduce gadget density through control-flow protection; remove embedded command strings when unnecessary.",
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


def _merge_ghidra(info: BinaryInfo, export_path: Path) -> BinaryInfo:
    try:
        payload = json.loads(export_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid Ghidra export: %s" % exc) from exc
    if payload.get("schema") != "pwnscan-ghidra/v1":
        raise ValueError("invalid Ghidra export schema")
    functions = payload.get("functions")
    imports = payload.get("imports")
    calls = payload.get("calls", [])
    if not isinstance(functions, list) or not isinstance(imports, list) or not isinstance(calls, list):
        raise ValueError("invalid Ghidra export structure")
    function_names = {item.get("name") for item in functions if isinstance(item, dict) and isinstance(item.get("name"), str)}
    clean_imports = {value.rsplit("::", 1)[-1] for value in imports if isinstance(value, str)}
    metadata = dict(info.metadata)
    addresses = dict(metadata.get("symbol_addresses", {}))
    for item in functions:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("entry"), str):
            continue
        try:
            addresses[item["name"]] = int(item["entry"], 16)
        except ValueError:
            continue
    metadata["symbol_addresses"] = {name: addresses[name] for name in sorted(addresses, key=str.lower)}
    metadata["ghidra"] = {
        "language": payload.get("language"),
        "image_base": payload.get("image_base"),
        "calls": sorted((item for item in calls if isinstance(item, dict)), key=lambda item: (str(item.get("to", "")), str(item.get("from", "")))),
    }
    metadata["parsed_imports"] = sorted(set(metadata.get("parsed_imports", [])) | clean_imports, key=str.lower)
    return replace(
        info,
        imports=sorted(set(info.imports) | clean_imports, key=str.lower),
        symbols=sorted(set(info.symbols) | function_names, key=lambda value: (value.lower(), value)),
        metadata=metadata,
    )


def scan_file(path: Path, ghidra_export: Path = None) -> ScanReport:
    data = path.read_bytes()
    info = parse_binary(data)
    if ghidra_export is not None:
        info = _merge_ghidra(info, ghidra_export)
    return ScanReport("pwnscan/v1", str(path), hashlib.sha256(data).hexdigest(), len(data), info, analyze(info))

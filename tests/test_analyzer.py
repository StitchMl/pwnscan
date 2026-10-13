import json

from pwnscan.analyzer import analyze, scan_bytes
from pwnscan.model import BinaryInfo
from pwnscan.report import render_json, render_text
from test_parsers import minimal_elf64


def info(**updates):
    values = dict(
        format="ELF", bits=64, endian="little", architecture="x86_64",
        entrypoint=0x401000, imports=[], symbols=[], strings=[],
        mitigations={"nx": True, "pie": True, "stack_canary": True}, metadata={},
    )
    values.update(updates)
    return BinaryInfo(**values)


def test_overflow_vector_uses_mitigations():
    findings = analyze(info(
        imports=["gets"], mitigations={"nx": True, "pie": False, "stack_canary": False},
        metadata={"parsed_imports": ["gets"], "ghidra": {"calls": [{"from": "00401020", "function": "main", "to": "gets"}]}},
    ))
    overflow = next(item for item in findings if item.id == "PWN-BOF-001")
    assert overflow.severity == "high"
    assert "ROP/ret2libc" in overflow.attack_vector


def test_format_string_requires_sink_and_clue():
    findings = analyze(info(imports=["printf"], strings=["hello %7$p", "%n"], metadata={"parsed_imports": ["printf"]}))
    assert any(item.id == "PWN-FMT-001" for item in findings)
    assert not any(item.id == "PWN-FMT-001" for item in analyze(info(imports=["printf"])))


def test_constant_normal_format_does_not_raise_format_finding():
    findings = analyze(info(imports=["printf"], strings=["user: %s count: %d"], metadata={"parsed_imports": ["printf"]}))
    assert not any(item.id == "PWN-FMT-001" for item in findings)


def test_ghidra_dynamic_format_is_high_confidence():
    findings = analyze(info(
        imports=["printf"], metadata={"parsed_imports": ["printf"], "ghidra": {"calls": [
            {"from": "00401020", "function": "main", "to": "printf", "arguments": [{"kind": "stack", "stack_offset": -64}]},
        ]}},
    ))
    finding = next(item for item in findings if item.id == "PWN-FMT-001")
    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert "%p.%p.%p" in finding.attack_vector


def test_ghidra_constant_format_is_not_reported():
    findings = analyze(info(
        imports=["printf"], metadata={"parsed_imports": ["printf"], "ghidra": {"calls": [
            {"from": "00401020", "function": "main", "to": "printf", "arguments": [{"kind": "address_constant", "address": "00402000", "writable": False}]},
        ]}},
    ))
    assert not any(item.id == "PWN-FMT-001" for item in findings)


def test_ghidra_proves_constant_length_stack_overflow():
    findings = analyze(info(
        imports=["read"], metadata={"parsed_imports": ["read"], "ghidra": {"calls": [
            {"from": "00401110", "function": "read_name", "to": "read", "arguments": [
                {"kind": "constant", "value": 0},
                {"kind": "stack", "stack_offset": -80, "buffer_size": 64, "variable": "name"},
                {"kind": "constant", "value": 256},
            ]},
        ]}},
    ))
    finding = next(item for item in findings if item.id == "PWN-BOUNDS-001")
    assert finding.severity == "critical"
    assert "overflow window 192 bytes" in finding.evidence[0]
    assert "exactly 256" in finding.validation[0]


def test_ghidra_safe_constant_length_is_not_overflow():
    findings = analyze(info(
        imports=["read"], metadata={"parsed_imports": ["read"], "ghidra": {"calls": [
            {"from": "00401110", "function": "read_name", "to": "read", "arguments": [
                {"kind": "constant", "value": 0},
                {"kind": "stack", "stack_offset": -80, "buffer_size": 64},
                {"kind": "constant", "value": 63},
            ]},
        ]}},
    ))
    assert not any(item.id == "PWN-BOUNDS-001" for item in findings)


def test_exact_ret2win_payload_is_ready_only_with_complete_proof():
    findings = analyze(info(
        imports=["read"], symbols=["print_flag"],
        mitigations={"nx": True, "pie": False, "stack_canary": False},
        metadata={"symbol_addresses": {"print_flag": 0x401234}, "parsed_imports": ["read"], "ghidra": {"calls": [
            {"from": "00401110", "function": "main", "to": "read", "arguments": [
                {"kind": "constant", "value": 0},
                {"kind": "stack", "stack_offset": -80, "buffer_size": 64, "return_address_offset": 72, "variable": "name"},
                {"kind": "constant", "value": 256},
            ]},
        ]}},
    ))
    finding = next(item for item in findings if item.id == "PWN-FLAG-CHAIN-001")
    assert finding.exploit_status == "payload-ready"
    assert "print_flag" in finding.flag_path
    assert "3412400000000000" in finding.attack_vector
    assert "OFFSET" not in finding.attack_vector


def test_exact_ret2win_payload_is_withheld_when_pie_is_enabled():
    findings = analyze(info(
        imports=["read"], symbols=["print_flag"],
        mitigations={"nx": True, "pie": True, "stack_canary": False},
        metadata={"symbol_addresses": {"print_flag": 0x1234}, "ghidra": {"calls": [
            {"from": "00101110", "function": "main", "to": "read", "arguments": [
                {"kind": "constant", "value": 0},
                {"kind": "stack", "buffer_size": 64, "return_address_offset": 72},
                {"kind": "constant", "value": 256},
            ]},
        ]}},
    ))
    assert not any(item.id == "PWN-FLAG-CHAIN-001" for item in findings)


def test_command_sink_without_dynamic_callsite_is_low_confidence():
    finding = next(item for item in analyze(info(
        imports=["system"], metadata={"parsed_imports": ["system"]},
    )) if item.id == "PWN-CMD-001")
    assert finding.severity == "low"
    assert finding.confidence == "low"


def test_dynamic_command_callsite_is_high_confidence():
    finding = next(item for item in analyze(info(
        imports=["system"], metadata={"parsed_imports": ["system"], "ghidra": {"calls": [
            {"from": "00401220", "function": "run", "to": "system", "arguments": [{"kind": "dynamic", "repr": "input"}]},
        ]}},
    )) if item.id == "PWN-CMD-001")
    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert "cat /flag" in finding.attack_vector


def test_ret2win_clues():
    findings = analyze(info(symbols=["main", "print_flag"], strings=["Try again"]))
    finding = next(item for item in findings if item.id == "PWN-WIN-001")
    assert finding.confidence == "high"
    assert "symbol: print_flag" in finding.evidence


def test_no_signal_returns_manual_triage():
    findings = analyze(info())
    assert [item.id for item in findings] == ["PWN-TRIAGE-000"]


def test_json_is_deterministic_and_sorted():
    payload = minimal_elf64(b"gets\0win\0FLAG{demo}\0")
    first = render_json(scan_bytes(payload, "same"))
    second = render_json(scan_bytes(payload, "same"))
    assert first == second
    decoded = json.loads(first)
    assert decoded["schema"] == "pwnscan/v1"
    ids = [item["id"] for item in decoded["findings"]]
    assert "PWN-BOF-001" in ids
    assert "PWN-WIN-001" in ids


def test_text_has_vector_and_patch():
    text = render_text(scan_bytes(minimal_elf64(b"gets\0"), "fixture"), color=False)
    assert "vector:" in text
    assert "patch:" in text
    assert "exploit: validation-only" in text
    assert "flag path:" in text
    assert "\x1b[" not in text


def test_plain_api_name_is_only_low_confidence_hint():
    finding = next(item for item in analyze(info(
        imports=["strcpy"], metadata={"parsed_imports": [], "string_import_hints": ["strcpy"]},
    )) if item.id == "PWN-BOF-001")
    assert finding.severity == "low"
    assert finding.confidence == "low"
    assert finding.evidence == ["unverified string hint: strcpy"]

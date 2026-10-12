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
    assert "\x1b[" not in text


def test_plain_api_name_is_only_low_confidence_hint():
    finding = next(item for item in analyze(info(
        imports=["strcpy"], metadata={"parsed_imports": [], "string_import_hints": ["strcpy"]},
    )) if item.id == "PWN-BOF-001")
    assert finding.severity == "low"
    assert finding.confidence == "low"
    assert finding.evidence == ["unverified string hint: strcpy"]

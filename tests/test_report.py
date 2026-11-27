from types import SimpleNamespace

from pwnscan.model import BinaryInfo, Finding, ScanReport
from pwnscan.report import (
    render_batch_markdown,
    render_json,
    render_markdown,
    render_text,
    use_color,
)


def _sample_report() -> ScanReport:
    binary = BinaryInfo(
        format="PE",
        bits=64,
        endian="little",
        architecture="x86_64",
        entrypoint=None,
        imports=[],
        mitigations={"aslr": True, "cfg": None, "nx": False},
    )
    finding = Finding(
        id="PWN-MIT-001",
        title="Exploit mitigations disabled",
        severity="medium",
        confidence="high",
        evidence=["nx disabled"],
        attack_vector="Test vector",
        validation=["Confirm loader policy"],
        patch="Enable NX",
    )
    return ScanReport("pwnscan/v1", "sample.exe", "0" * 64, 512, binary, [finding])


def test_render_text_handles_unknown_entrypoint_no_imports_and_color():
    plain = render_text(_sample_report(), color=False)
    assert "entrypoint: unknown" in plain
    assert "imports: none found" in plain
    assert "aslr=on, cfg=unknown, nx=off" in plain
    assert "\x1b[" not in plain

    colored = render_text(_sample_report(), color=True)
    assert "\033[33m[MEDIUM] PWN-MIT-001 Exploit mitigations disabled\033[0m" in colored


def test_render_text_summary_alignment_and_rule():
    plain = render_text(_sample_report(), color=False)
    assert "findings: 1 (1 medium)" in plain
    assert "-" * 60 in plain
    assert "  confidence: high" in plain
    assert "  exploit:    validation-only" in plain
    assert "  flag path:  Manual confirmation required" in plain
    assert "  evidence:   nx disabled" in plain
    assert "  vector:     Test vector" in plain
    assert "  validate:   Confirm loader policy" in plain
    assert "  patch:      Enable NX" in plain


def test_render_text_summary_none_and_multiple_severities():
    binary = _sample_report().binary
    empty = ScanReport("pwnscan/v1", "empty.exe", "0" * 64, 1, binary, [])
    assert "findings: none" in render_text(empty, color=False)

    findings = [
        Finding("A", "t", "critical", "high", [], "v", [], "p"),
        Finding("B", "t", "critical", "high", [], "v", [], "p"),
        Finding("C", "t", "low", "low", [], "v", [], "p"),
    ]
    report = ScanReport("pwnscan/v1", "multi.exe", "0" * 64, 1, binary, findings)
    assert "findings: 3 (2 critical, 1 low)" in render_text(report, color=False)


def test_render_json_compact_and_pretty():
    compact = render_json(_sample_report(), pretty=False)
    pretty = render_json(_sample_report(), pretty=True)
    assert "\n" not in compact
    assert "\n  " in pretty
    assert '"schema": "pwnscan/v1"' in pretty


def test_use_color_modes_and_no_color_env(monkeypatch):
    assert use_color("always") is True
    assert use_color("never") is False

    monkeypatch.setattr("pwnscan.report.sys.stdout", SimpleNamespace(isatty=lambda: True))
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert use_color("auto") is True

    monkeypatch.setenv("NO_COLOR", "1")
    assert use_color("auto") is False

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr("pwnscan.report.sys.stdout", SimpleNamespace(isatty=lambda: False))
    assert use_color("auto") is False


def test_render_text_color_hierarchy_mitigations_and_status():
    binary = BinaryInfo(
        format="ELF", bits=64, endian="little", architecture="x86_64", entrypoint=0x401000,
        imports=["gets"], mitigations={"nx": True, "pie": False, "stack_canary": None},
    )
    finding = Finding(
        id="PWN-FLAG-CHAIN-001", title="Exact ret2win chain", severity="critical", confidence="high",
        evidence=["[guarded] blocked path", "direct path"], attack_vector="Vector", validation=["Step 1"],
        patch="Fix", exploit_status="payload-ready",
    )
    colored = render_text(ScanReport("pwnscan/v1", "a.out", "0" * 64, 100, binary, [finding]), color=True)
    assert "nx=\033[32mon\033[0m" in colored
    assert "pie=\033[31moff\033[0m" in colored
    assert "stack_canary=\033[2munknown\033[0m" in colored
    assert "\033[1;36mhigh\033[0m" in colored
    assert "\033[1;32mpayload-ready\033[0m" in colored
    assert "\033[2m[guarded] blocked path\033[0m" in colored


def test_render_text_wraps_long_fields_and_imports_aligned():
    binary = BinaryInfo(
        format="ELF", bits=64, endian="little", architecture="x86_64", entrypoint=0x401000,
        imports=["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india"],
        mitigations={"nx": True},
    )
    finding = Finding(
        id="PWN-BOF-001", title="Overflow", severity="high", confidence="high",
        evidence=["ev"], attack_vector="word " * 20, validation=["v"], patch="p",
    )
    rendered = render_text(ScanReport("pwnscan/v1", "a.out", "0" * 64, 100, binary, [finding]), color=False, width=60)
    lines = rendered.splitlines()
    imports_idx = next(i for i, line in enumerate(lines) if line.startswith("imports: "))
    assert lines[imports_idx + 1].startswith(" " * len("imports: "))
    vector_idx = next(i for i, line in enumerate(lines) if line.startswith("  vector:"))
    assert lines[vector_idx + 1].startswith(" " * 14)


def test_render_markdown_single_and_empty():
    md = render_markdown(_sample_report())
    assert "# pwnscan Report: `sample.exe`" in md
    assert "| `aslr` | on |" in md
    assert "| `cfg` | unknown |" in md
    assert "| `nx` | off |" in md
    assert "_none found_" in md
    assert "### [MEDIUM] `PWN-MIT-001` Exploit mitigations disabled" in md
    assert "- **Evidence:**\n  - nx disabled" in md

    empty = ScanReport("pwnscan/v1", "empty.exe", "0" * 64, 1, _sample_report().binary, [])
    assert "No findings." in render_markdown(empty)


def test_render_batch_markdown():
    md = render_batch_markdown([_sample_report()])
    assert "# pwnscan Batch Report" in md
    assert "| `sample.exe` | `PE/64/x86_64` | medium | `PWN-MIT-001` |" in md
    assert "## `sample.exe`" in md
    assert "### [MEDIUM] `PWN-MIT-001` Exploit mitigations disabled" in md

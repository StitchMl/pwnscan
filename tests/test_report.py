from types import SimpleNamespace

from pwnscan.model import BinaryInfo, Finding, ScanReport
from pwnscan.report import render_json, render_text, use_color


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

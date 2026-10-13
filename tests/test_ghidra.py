import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from pwnscan.ghidra import GhidraError, export_headless


def test_headless_export_builds_isolated_command(tmp_path, monkeypatch):
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    executable = support / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    executable.write_text("", encoding="utf-8")
    script = tmp_path / "PwnscanExport.py"
    script.write_text("", encoding="utf-8")
    target = tmp_path / "challenge.exe"
    target.write_bytes(b"MZ")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        Path(command[-2]).write_text('{"schema":"pwnscan-ghidra/v1"}', encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="analysis complete")

    monkeypatch.setattr("pwnscan.ghidra.subprocess.run", fake_run)
    output = export_headless(target, home, script, 17)
    try:
        assert output.read_text(encoding="utf-8") == '{"schema":"pwnscan-ghidra/v1"}'
        assert captured["command"][0] == str(executable)
        assert captured["command"][3:5] == ["-import", str(target.resolve())]
        assert "-postScript" in captured["command"]
        assert captured["kwargs"]["timeout"] == 17
        assert captured["kwargs"]["check"] is False
    finally:
        output.unlink(missing_ok=True)


def test_headless_failure_reports_tail_and_removes_output(tmp_path, monkeypatch):
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")).write_text("", encoding="utf-8")
    script = tmp_path / "PwnscanExport.py"
    script.write_text("", encoding="utf-8")
    target = tmp_path / "challenge"
    target.write_bytes(b"\x7fELF")

    monkeypatch.setattr(
        "pwnscan.ghidra.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="fatal analysis error"),
    )
    with pytest.raises(GhidraError, match="fatal analysis error"):
        export_headless(target, home, script, 17)

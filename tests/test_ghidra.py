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


def test_headless_executable_discovery_and_errors(tmp_path, monkeypatch):
    from pwnscan.ghidra import _export_script, _headless_executable

    monkeypatch.setattr("pwnscan.ghidra.shutil.which", lambda _: None)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    with pytest.raises(GhidraError, match="Ghidra headless not found"):
        _headless_executable(None)

    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    executable = support / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    executable.write_text("", encoding="utf-8")
    monkeypatch.setenv("GHIDRA_HOME", str(home))
    assert _headless_executable(None) == executable

    located = str(tmp_path / "on-path-headless")
    monkeypatch.setattr("pwnscan.ghidra.shutil.which", lambda _: located)
    assert _headless_executable(None) == Path(located)

    monkeypatch.setattr("pwnscan.ghidra.Path.is_file", lambda _self: False)
    with pytest.raises(GhidraError, match=r"PwnscanExport\.java not found"):
        _export_script(tmp_path / "missing.java")


def test_headless_timeout_raises_ghidra_error(tmp_path, monkeypatch):
    import subprocess

    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")).write_text("", encoding="utf-8")
    script = tmp_path / "PwnscanExport.java"
    script.write_text("", encoding="utf-8")
    target = tmp_path / "challenge"
    target.write_bytes(b"\x7fELF")

    def fake_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="analyzeHeadless", timeout=5)

    monkeypatch.setattr("pwnscan.ghidra.subprocess.run", fake_timeout)
    with pytest.raises(GhidraError, match="Ghidra headless failed"):
        export_headless(target, home, script, 5)

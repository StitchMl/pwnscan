import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from pwnscan.ghidra import GhidraError, export_headless


def fixtures(tmp_path):
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    executable = support / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    executable.write_text("", encoding="utf-8")
    script = tmp_path / "PwnscanExport.java"
    script.write_text("", encoding="utf-8")
    target = tmp_path / "challenge"
    target.write_bytes(b"\x7fELF")
    return home, executable, script, target


def test_headless_export_builds_isolated_command(tmp_path, monkeypatch):
    home, executable, script, target = fixtures(tmp_path)
    captured = {}

    class FakeProcess:
        def wait(self, timeout=None):
            captured["timeout"] = timeout
            command = captured["command"]
            output = Path(command[command.index("-postScript") + 2])
            output.write_text('{"schema":"pwnscan-ghidra/v1"}', encoding="utf-8")
            return 0

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr("pwnscan.ghidra.subprocess.Popen", fake_popen)
    output = export_headless(target, home, script, 17)
    try:
        assert output.read_text(encoding="utf-8") == '{"schema":"pwnscan-ghidra/v1"}'
        assert captured["command"][0] == str(executable)
        assert captured["command"][3:5] == ["-import", str(target.resolve())]
        assert captured["command"][captured["command"].index("-postScript") + 1] == script.name
        assert captured["timeout"] == 17
        assert captured["kwargs"]["stderr"] == subprocess.STDOUT
    finally:
        output.unlink(missing_ok=True)


def test_headless_failure_reports_tail_and_removes_output(tmp_path, monkeypatch):
    home, _, script, target = fixtures(tmp_path)

    class FakeProcess:
        def wait(self, timeout=None):
            return 1

    def fake_popen(command, **kwargs):
        kwargs["stdout"].write(b"fatal analysis error\n")
        kwargs["stdout"].flush()
        return FakeProcess()

    monkeypatch.setattr("pwnscan.ghidra.subprocess.Popen", fake_popen)
    with pytest.raises(GhidraError, match="fatal analysis error"):
        export_headless(target, home, script, 17)


def test_headless_executable_discovery_and_errors(tmp_path, monkeypatch):
    from pwnscan.ghidra import _export_script, _headless_executable

    monkeypatch.setattr("pwnscan.ghidra.shutil.which", lambda _: None)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    with pytest.raises(GhidraError, match="Ghidra headless not found"):
        _headless_executable(None)

    home, executable, _, _ = fixtures(tmp_path)
    monkeypatch.setenv("GHIDRA_HOME", str(home))
    assert _headless_executable(None) == executable

    located = str(tmp_path / "on-path-headless")
    monkeypatch.setattr("pwnscan.ghidra.shutil.which", lambda _: located)
    # Explicit/configured installation takes precedence over the PATH version.
    assert _headless_executable(None) == executable

    monkeypatch.delenv("GHIDRA_HOME")
    assert _headless_executable(None) == Path(located)

    monkeypatch.setattr("pwnscan.ghidra.Path.is_file", lambda _self: False)
    with pytest.raises(GhidraError, match=r"PwnscanExport\.java not found"):
        _export_script(tmp_path / "missing.java")


def test_headless_timeout_raises_ghidra_error(tmp_path, monkeypatch):
    home, _, script, target = fixtures(tmp_path)
    calls = []

    class FakeProcess:
        pid = 1234

        def wait(self, timeout=None):
            calls.append("wait")
            if timeout is not None:
                raise subprocess.TimeoutExpired(cmd="analyzeHeadless", timeout=timeout)
            return 1

        def kill(self):
            calls.append("kill")

    monkeypatch.setattr("pwnscan.ghidra.subprocess.Popen", lambda *a, **kw: FakeProcess())
    monkeypatch.setattr("pwnscan.ghidra.subprocess.run", lambda *a, **kw: SimpleNamespace(returncode=0))
    if os.name != "nt":
        monkeypatch.setattr("os.killpg", lambda *a, **kw: None)
    with pytest.raises(GhidraError, match="timed out after 5 seconds"):
        export_headless(target, home, script, 5)
    assert "kill" in calls

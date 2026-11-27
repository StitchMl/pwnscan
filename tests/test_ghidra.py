import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import pwnscan.ghidra as ghidra
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
    monkeypatch.setattr("pwnscan.ghidra._common_ghidra_homes", list)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setattr("pwnscan.ghidra.Path.home", lambda: tmp_path / "empty-home")
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "APPDATA", "USERPROFILE"):
        monkeypatch.delenv(variable, raising=False)
    with pytest.raises(GhidraError, match="Ghidra headless was not found"):
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


def test_headless_executable_discovers_common_user_install(tmp_path, monkeypatch):
    from pwnscan.ghidra import _headless_executable

    install = tmp_path / "tools" / "ghidra_12.0_PUBLIC"
    support = install / "support"
    support.mkdir(parents=True)
    executable = support / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    executable.write_text("", encoding="utf-8")

    monkeypatch.setattr("pwnscan.ghidra.Path.home", lambda: tmp_path)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setattr("pwnscan.ghidra.shutil.which", lambda _: None)
    assert _headless_executable() == executable


def test_headless_executable_discovers_downloaded_ghidra(tmp_path, monkeypatch):
    from pwnscan.ghidra import _headless_executable

    install = tmp_path / "Downloads" / "ghidra_12.0_PUBLIC"
    support = install / "support"
    support.mkdir(parents=True)
    executable = support / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    executable.write_text("", encoding="utf-8")

    monkeypatch.setattr("pwnscan.ghidra.Path.home", lambda: tmp_path)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setattr("pwnscan.ghidra.shutil.which", lambda _: None)
    assert _headless_executable() == executable


def test_jdk_is_discovered_from_java_on_path(monkeypatch, tmp_path):
    jdk = tmp_path / "jdk-21"
    java = jdk / "bin" / ("java.exe" if os.name == "nt" else "java")
    java.parent.mkdir(parents=True)
    java.write_bytes(b"")
    monkeypatch.setenv("JAVA_HOME", str(tmp_path / "missing-jdk"))
    monkeypatch.setattr(ghidra.shutil, "which", lambda _name: str(java))

    assert ghidra._java_home() == jdk


def test_headless_environment_uses_temporary_appdata_on_windows(tmp_path):
    environment = ghidra._headless_environment(tmp_path / "appdata")

    if os.name == "nt":
        assert environment["APPDATA"] == str(tmp_path / "appdata")
        assert (tmp_path / "appdata").is_dir()


def test_headless_temp_root_rejects_paths_ghidra_cannot_use(monkeypatch, tmp_path):
    from pwnscan.ghidra import _headless_temp_root

    sandbox_temp = tmp_path / "sandbox#temp"
    sandbox_temp.mkdir()
    monkeypatch.setattr(ghidra.tempfile, "gettempdir", lambda: str(sandbox_temp))
    monkeypatch.setattr(ghidra.Path, "home", lambda: sandbox_temp)

    with pytest.raises(GhidraError, match="without '#' is available"):
        _headless_temp_root()


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


def test_ghidra_cache_validation_and_write(tmp_path):
    from pwnscan.ghidra import default_cache_path, is_cache_valid, write_cached_export

    target = tmp_path / "chal"
    target.write_bytes(b"\x7fELFdata")
    cache_path = default_cache_path(target)
    assert cache_path == tmp_path / "chal.ghidra.json"
    assert not is_cache_valid(target, cache_path)

    raw_export = tmp_path / "raw.json"
    raw_export.write_text('{"schema":"pwnscan-ghidra/v1","functions":[],"imports":[],"calls":[]}', encoding="utf-8")
    write_cached_export(target, raw_export, cache_path)
    assert is_cache_valid(target, cache_path)

    target.write_bytes(b"\x7fELFmodified")
    assert not is_cache_valid(target, cache_path)

    cache_path.write_text("{bad-json", encoding="utf-8")
    assert not is_cache_valid(target, cache_path)

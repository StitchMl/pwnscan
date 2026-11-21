from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from pwnscan import solve


def test_token_length_is_inferred_from_binary_text():
    assert solve.inferred_length(["15-character uppercase secret password"]) == 15
    assert solve.inferred_length(["no token length"]) is None


def test_solver_generates_standalone_script(tmp_path, monkeypatch):
    binary = tmp_path / "arbitrary-ctf-file"
    binary.write_bytes(b"\x7fELFfake")

    class Report:
        findings = [SimpleNamespace(id="PWN-FMT-001")]
        binary = SimpleNamespace(strings=["15-character uppercase secret password"])

    monkeypatch.setattr(solve, "scan_file", lambda path, export=None: Report())
    result = solve.main([str(binary), "--no-ghidra"])
    assert result == 0
    script = binary.with_name(binary.name + ".solve.py")
    content = script.read_text()
    assert 'TOKEN_LENGTH = 15' in content
    assert "%d$s" in content
    compile(content, str(script), "exec")


def test_solver_rejects_unsupported_without_generating(tmp_path, monkeypatch):
    binary = tmp_path / "arbitrary-ctf-file"
    binary.write_bytes(b"\x7fELFfake")

    class Report:
        findings = []
        binary = SimpleNamespace(strings=[])

    monkeypatch.setattr(solve, "scan_file", lambda path, export=None: Report())
    assert solve.main([str(binary), "--no-ghidra"]) == 2
    assert not binary.with_name(binary.name + ".solve.py").exists()


def test_solver_removes_ghidra_temp_export(tmp_path, monkeypatch):
    binary = tmp_path / "challenge"
    binary.write_bytes(b"\x7fELFfake")
    export = tmp_path / "export.json"
    export.write_text("{}")
    monkeypatch.setattr(solve, "export_headless", lambda *a, **kw: export)

    class Report:
        findings = [SimpleNamespace(id="PWN-FMT-001")]
        binary = SimpleNamespace(strings=["15-character uppercase secret password"])

    monkeypatch.setattr(solve, "scan_file", lambda path, metadata=None: Report())
    assert solve.main([str(binary)]) == 0
    assert not export.exists()

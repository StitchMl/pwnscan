from __future__ import annotations

from types import SimpleNamespace

from pwnscan import solve


def test_token_length_is_inferred_from_binary_text():
    assert solve.inferred_length(["15-character uppercase secret password"]) == 15
    assert solve.inferred_length(["no token length"]) is None


def test_solver_generates_standalone_script(tmp_path, monkeypatch):
    binary = tmp_path / "arbitrary-ctf-file"
    binary.write_bytes(b"\x7fELFfake")

    report = SimpleNamespace(
        findings=[SimpleNamespace(id="PWN-FMT-001", confidence="high", evidence=["dynamic format argument at 0010234 in main -> printf"])],
        binary=SimpleNamespace(strings=["15-character uppercase secret password"], mitigations={"pie": True, "stack_canary": True}, format="ELF"),
    )

    monkeypatch.setattr(solve, "scan_file", lambda path, export=None: report)
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

    report = SimpleNamespace(findings=[], binary=SimpleNamespace(strings=[]))

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
        findings = [SimpleNamespace(id="PWN-FMT-001", confidence="high", evidence=["dynamic format argument at 0010234 in main -> printf"])]
        binary = SimpleNamespace(strings=["15-character uppercase secret password"], mitigations={"pie": True, "stack_canary": True}, format="ELF")

    monkeypatch.setattr(solve, "scan_file", lambda path, metadata=None: report)
    assert solve.main([str(binary)]) == 0
    assert not export.exists()



def _report_for_ret2win(*, canary=False, pie=False, status="payload-ready"):
    payload = (b"A" * 24 + (0x401234).to_bytes(8, "little")).hex()
    finding = SimpleNamespace(
        id="PWN-FLAG-CHAIN-001", exploit_status=status, confidence="high",
        evidence=["Ghidra recovered saved return address offset 24 for read at 00401234",
                  "stack canary disabled; pie disabled"],
        attack_vector='payload_hex=%s; send bytes.fromhex("%s")' % (payload, payload),
    )
    return SimpleNamespace(
        findings=[finding],
        binary=SimpleNamespace(strings=[], mitigations={"pie": pie, "stack_canary": canary},
                               format="ELF"),
    )


def test_ret2win_requires_complete_evidence_and_disabled_mitigations():
    good = _report_for_ret2win()
    assert solve.proven_ret2win(good) is not None
    assert solve.proven_ret2win(_report_for_ret2win(pie=True)) is None
    assert solve.proven_ret2win(_report_for_ret2win(canary=True)) is None
    assert solve.proven_ret2win(_report_for_ret2win(status="validation-only")) is None


def test_ret2win_generation_is_byte_exact_and_independent_of_ctf_name(tmp_path, monkeypatch):
    target = tmp_path / "arbitrary-program.bin"
    target.write_bytes(b"\x7fELFdummy")
    monkeypatch.setattr(solve, "scan_file", lambda path, export=None: _report_for_ret2win())
    assert solve.main([str(target), "--no-ghidra", "--strategy", "ret2win"]) == 0
    script = target.with_name(target.name + ".solve.py")
    source = script.read_text()
    assert 'PAYLOAD_HEX = ' in source
    assert "(b\"A\" * 24 + (0x401234).to_bytes(8, \"little\")).hex()" not in source
    compile(source, str(script), "exec")


def test_format_strategy_rejects_low_confidence_finding(tmp_path, monkeypatch):
    target = tmp_path / "program"
    target.write_bytes(b"\x7fELF")
    report = SimpleNamespace(
        findings=[SimpleNamespace(id="PWN-FMT-001", confidence="low",
                                  evidence=["parsed format sink: printf"])],
        binary=SimpleNamespace(strings=["15-character uppercase secret password"]),
    )
    monkeypatch.setattr(solve, "scan_file", lambda path, export=None: report)
    assert solve.main([str(target), "--no-ghidra", "--strategy", "format-token"]) == 2
    assert not target.with_name(target.name + ".solve.py").exists()

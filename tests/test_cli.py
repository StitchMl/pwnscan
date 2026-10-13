from pathlib import Path

from pwnscan.cli import main
from test_parsers import minimal_elf64


def test_cli_json(tmp_path, capsys):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64(b"gets\0"))
    assert main([str(target), "--format", "json"]) == 0
    assert '"schema":"pwnscan/v1"' in capsys.readouterr().out


def test_cli_fail_on(tmp_path):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64(b"gets\0"))
    assert main([str(target), "--format", "json", "--fail-on", "medium"]) == 3


def test_cli_merges_valid_ghidra_export(tmp_path, capsys):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64())
    export = tmp_path / "ghidra.json"
    export.write_text('{"schema":"pwnscan-ghidra/v1","functions":[{"name":"win","entry":"00401100"}],"imports":["gets"],"calls":[{"from":"00401020","function":"main","to":"gets"}]}', encoding="utf-8")
    assert main([str(target), "--ghidra", str(export), "--format", "json"]) == 0
    output = capsys.readouterr().out
    assert 'Ghidra reference' in output
    assert '"confidence":"high"' in output
    assert 'p64(0x401100)' in output


def test_cli_rejects_malformed_ghidra_export(tmp_path, capsys):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64())
    export = tmp_path / "ghidra.json"
    export.write_text("{}", encoding="utf-8")
    assert main([str(target), "--ghidra", str(export)]) == 2
    assert "invalid Ghidra export schema" in capsys.readouterr().err


def test_cli_runs_optional_headless_export(tmp_path, capsys, monkeypatch):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64())
    export = tmp_path / "generated.json"
    export.write_text('{"schema":"pwnscan-ghidra/v1","functions":[],"imports":[],"calls":[]}', encoding="utf-8")
    calls = []

    def fake_export(actual_target, home, script, timeout):
        calls.append((actual_target, home, script, timeout))
        return export

    monkeypatch.setattr("pwnscan.cli.export_headless", fake_export)
    assert main([str(target), "--ghidra-auto", "--ghidra-timeout", "19", "--format", "json"]) == 0
    assert calls == [(target, None, None, 19)]
    assert not export.exists()
    assert '"schema":"pwnscan/v1"' in capsys.readouterr().out


def test_cli_rejects_two_ghidra_sources(tmp_path, capsys):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64())
    export = tmp_path / "manual.json"
    export.write_text("{}", encoding="utf-8")
    assert main([str(target), "--ghidra", str(export), "--ghidra-auto"]) == 2
    assert "choose either --ghidra or --ghidra-auto" in capsys.readouterr().err


def test_cli_rejects_non_file(tmp_path, capsys):
    assert main([str(tmp_path / "missing")]) == 2
    assert "target is not a file" in capsys.readouterr().err

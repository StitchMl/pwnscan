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
    assert main([str(target), "--format", "json", "--fail-on", "high"]) == 3


def test_cli_rejects_non_file(tmp_path, capsys):
    assert main([str(tmp_path / "missing")]) == 2
    assert "target is not a file" in capsys.readouterr().err

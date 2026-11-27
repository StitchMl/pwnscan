
import pytest
from test_parsers import minimal_elf64

from pwnscan.cli import main


@pytest.fixture(autouse=True)
def disable_machine_ghidra_for_cli_tests(monkeypatch):
    monkeypatch.setattr("pwnscan.cli.find_headless_executable", lambda _home: None)


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
    captured = capsys.readouterr()
    assert '"schema":"pwnscan/v1"' in captured.out
    assert "running Ghidra headless analysis (timeout: 19s)" in captured.err


def test_cli_detects_ghidra_and_runs_it_by_default(tmp_path, capsys, monkeypatch):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64())
    export = tmp_path / "generated.json"
    export.write_text('{"schema":"pwnscan-ghidra/v1","functions":[],"imports":[],"calls":[]}', encoding="utf-8")
    detected_home = tmp_path / "ghidra_12.0_PUBLIC"
    calls = []

    monkeypatch.setattr("pwnscan.cli.find_headless_executable", lambda _home: detected_home / "support" / "analyzeHeadless.bat")

    def fake_export(actual_target, home, script, timeout):
        calls.append((actual_target, home, script, timeout))
        return export

    monkeypatch.setattr("pwnscan.cli.export_headless", fake_export)
    assert main([str(target), "--format", "json"]) == 0
    assert calls == [(target, None, None, 300)]
    assert not export.exists()
    assert "running Ghidra headless analysis" in capsys.readouterr().err


def test_cli_can_disable_automatic_ghidra(tmp_path, capsys, monkeypatch):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64())
    monkeypatch.setattr("pwnscan.cli.find_headless_executable", lambda _home: pytest.fail("unexpected Ghidra lookup"))
    assert main([str(target), "--no-ghidra-auto", "--format", "json"]) == 0
    assert '"schema":"pwnscan/v1"' in capsys.readouterr().out


def test_cli_falls_back_when_detected_ghidra_cannot_start(tmp_path, capsys, monkeypatch):
    from pwnscan.ghidra import GhidraError

    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64(b"gets\0"))
    monkeypatch.setattr("pwnscan.cli.find_headless_executable", lambda _home: tmp_path / "headless")

    def fail_start(*_args):
        raise GhidraError("JDK unavailable")

    monkeypatch.setattr("pwnscan.cli.export_headless", fail_start)
    assert main([str(target), "--format", "json"]) == 0
    captured = capsys.readouterr()
    assert '"schema":"pwnscan/v1"' in captured.out
    assert "continuing with static triage: JDK unavailable" in captured.err


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


def test_cli_text_output_and_min_severity(tmp_path, capsys):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64(b"gets\0"))
    assert main([str(target), "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "PWN-MIT-001" in out
    assert "PWN-BOF-001" in out

    assert main([str(target), "--format", "json", "--min-severity", "medium"]) == 0
    filtered = capsys.readouterr().out
    assert "PWN-MIT-001" in filtered
    assert "PWN-BOF-001" not in filtered


def test_cli_output_file_and_invalid_timeout(tmp_path, capsys):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64(b"gets\0"))
    report_path = tmp_path / "report.txt"
    assert main([str(target), "--output", str(report_path)]) == 0
    assert capsys.readouterr().out == ""
    content = report_path.read_text(encoding="utf-8")
    assert "pwnscan ELF 64-bit x86_64" in content
    assert "\x1b[" not in content

    assert main([str(target), "--ghidra-timeout", "0"]) == 2
    assert "--ghidra-timeout must be positive" in capsys.readouterr().err


def test_cli_ghidra_keep_saves_export_and_requires_auto(tmp_path, capsys, monkeypatch):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64())
    export = tmp_path / "generated.json"
    export.write_text('{"schema":"pwnscan-ghidra/v1","functions":[],"imports":[],"calls":[]}', encoding="utf-8")
    kept = tmp_path / "kept.json"

    def fake_export(actual_target, home, script, timeout):
        return export

    monkeypatch.setattr("pwnscan.cli.export_headless", fake_export)
    assert main([str(target), "--ghidra-keep", str(kept)]) == 2
    assert "--ghidra-keep requires --ghidra-auto" in capsys.readouterr().err
    assert main([str(target), "--ghidra-auto", "--ghidra-keep", str(kept)]) == 0
    assert kept.is_file()
    assert kept.read_text(encoding="utf-8").startswith('{"schema":"pwnscan-ghidra/v1"')
    assert not export.exists()


def test_cli_ghidra_cache_requires_auto_and_reuses_up_to_date_export(tmp_path, capsys, monkeypatch):
    target = tmp_path / "challenge"
    target.write_bytes(minimal_elf64())
    assert main([str(target), "--ghidra-cache"]) == 2
    assert "--ghidra-cache requires --ghidra-auto" in capsys.readouterr().err

    calls = []

    def fake_export(actual_target, home, script, timeout):
        export = tmp_path / ("gen_%d.json" % len(calls))
        export.write_text('{"schema":"pwnscan-ghidra/v1","functions":[],"imports":[],"calls":[]}', encoding="utf-8")
        calls.append(actual_target)
        return export

    monkeypatch.setattr("pwnscan.cli.export_headless", fake_export)
    assert main([str(target), "--ghidra-auto", "--ghidra-cache"]) == 0
    assert len(calls) == 1
    cache_file = tmp_path / "challenge.ghidra.json"
    assert cache_file.is_file()

    assert main([str(target), "--ghidra-auto", "--ghidra-cache"]) == 0
    assert len(calls) == 1
    assert "reusing cached Ghidra export" in capsys.readouterr().err

    target.write_bytes(minimal_elf64(b"gets\0"))
    assert main([str(target), "--ghidra-auto", "--ghidra-cache"]) == 0
    assert len(calls) == 2


def test_cli_batch_directory_scan_text_and_json(tmp_path, capsys):
    chal1 = tmp_path / "chal1"
    chal1.write_bytes(minimal_elf64(b"gets\0"))
    chal2 = tmp_path / "chal2"
    chal2.write_bytes(minimal_elf64(b"puts\0"))
    (tmp_path / "notes.txt").write_text("not a binary", encoding="utf-8")
    (tmp_path / "chal2.ghidra.json").write_text(
        '{"schema":"pwnscan-ghidra/v1","functions":[{"name":"win","entry":"00401100"}],"imports":[],"calls":[]}',
        encoding="utf-8",
    )

    assert main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "TARGET" in out
    assert "chal1" in out
    assert "chal2" in out
    assert "PWN-BOF-001" in out
    assert "PWN-WIN-001" in out

    assert main([str(tmp_path), "--format", "json", "--fail-on", "medium"]) == 3
    json_out = capsys.readouterr().out
    assert '"target":' in json_out
    assert json_out.strip().startswith("[")

    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    assert main([str(empty_dir)]) == 2
    assert "no supported binaries found" in capsys.readouterr().err


def test_cli_markdown_single_and_batch(tmp_path, capsys):
    chal1 = tmp_path / "chal1"
    chal1.write_bytes(minimal_elf64(b"gets\0"))
    assert main([str(chal1), "--format", "markdown"]) == 0
    single_out = capsys.readouterr().out
    assert "# pwnscan Report: `chal1`" in single_out
    assert "`PWN-BOF-001`" in single_out

    assert main([str(tmp_path), "--format", "markdown"]) == 0
    batch_out = capsys.readouterr().out
    assert "# pwnscan Batch Report" in batch_out
    assert "| `chal1` | `ELF/64/x86_64` |" in batch_out

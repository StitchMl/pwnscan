from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from pwnscan import batch


def test_collect_identifies_binary_magic_independent_of_filename(tmp_path):
    (tmp_path / "mystery.data").write_bytes(b"\x7fELF" + b"\0" * 32)
    (tmp_path / "windows.bin").write_bytes(b"MZ" + b"\0" * 32)
    (tmp_path / "notes.txt").write_text("not a binary")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "mach").write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 32)

    assert len(batch.collect([tmp_path])) == 2
    assert len(batch.collect([tmp_path], recursive=True)) == 3
    assert len(batch.collect([tmp_path / "mystery.data", tmp_path / "mystery.data"])) == 1


def test_batch_writes_reports_and_records_per_file_failures(tmp_path, monkeypatch):
    good = tmp_path / "ok"
    bad = tmp_path / "bad"
    good.write_bytes(b"\x7fELFok")
    bad.write_bytes(b"\x7fELFbad")

    def scan(path, ghidra=None):
        if path == bad:
            raise ValueError("unsupported variant")
        return SimpleNamespace(findings=[1], as_dict=lambda: {"schema": "pwnscan/v1"})

    monkeypatch.setattr(batch, "scan_file", scan)
    output = tmp_path / "reports"
    assert batch.main([str(tmp_path), "-o", str(output)]) == 2
    index = json.loads((output / "index.json").read_text())
    assert [row["status"] for row in index["results"]] == ["error", "ok"]
    assert index["results"][0]["error"] == "unsupported variant"
    assert json.loads(Path(index["results"][1]["report"]).read_text())["schema"] == "pwnscan/v1"


def test_batch_ghidra_export_is_merged_and_cleaned(tmp_path, monkeypatch):
    target = tmp_path / "challenge"
    target.write_bytes(b"\x7fELFexample")
    export = tmp_path / "temp-export.json"
    export.write_text('{"schema":"pwnscan-ghidra/v1"}')

    seen = []

    def export_headless(path, home, script, timeout):
        seen.append(("export", path, timeout))
        return export

    def scan_file(path, ghidra):
        seen.append(("scan", path, ghidra))
        return SimpleNamespace(findings=[], as_dict=lambda: {"schema": "pwnscan/v1"})

    monkeypatch.setattr(batch, "export_headless", export_headless)
    monkeypatch.setattr(batch, "scan_file", scan_file)
    output = tmp_path / "reports"
    assert batch.main([str(target), "--ghidra-auto", "--keep-ghidra-export",
                       "--ghidra-timeout", "42", "-o", str(output)]) == 0
    index = json.loads((output / "index.json").read_text())
    assert Path(index["results"][0]["ghidra_export"]).exists()
    assert not export.exists()
    assert seen == [("export", target.resolve(), 42), ("scan", target.resolve(), export)]


def test_batch_rejects_invalid_options(tmp_path):
    target = tmp_path / "program"
    target.write_bytes(b"\x7fELF")
    try:
        batch.main([str(target), "--keep-ghidra-export"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("must reject --keep-ghidra-export without --ghidra-auto")

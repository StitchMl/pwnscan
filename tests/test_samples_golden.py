"""Golden regression: scanning the real binaries in ../samples must reproduce
the (id, severity) set stored in each ``*.report.json`` reference file."""

import json
from pathlib import Path

import pytest

from pwnscan.analyzer import scan_file

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def _sample_binaries():
    if not SAMPLES.is_dir():
        return []
    return sorted(
        path for path in SAMPLES.iterdir()
        if path.is_file() and ".ghidra." not in path.name and ".report." not in path.name
    )


@pytest.mark.parametrize("binary", _sample_binaries(), ids=lambda path: path.name)
def test_sample_report_matches_golden(binary):
    reference_path = binary.parent / (binary.name + ".report.json")
    if not reference_path.is_file() or not (binary.parent / (binary.name + ".ghidra.json")).is_file():
        pytest.skip("missing reference files")
    report = scan_file(binary, binary.parent / (binary.name + ".ghidra.json"))
    with open(reference_path, encoding="utf-8") as handle:
        reference = json.load(handle)
    current = {(item.id, item.severity) for item in report.findings}
    expected = {(item["id"], item["severity"]) for item in reference["findings"]}
    assert current == expected

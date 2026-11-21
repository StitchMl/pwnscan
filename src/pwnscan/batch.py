"""Batch static triage for arbitrary ELF, PE, and thin Mach-O challenge files.

No scanned binary is executed. Each supported input can optionally be enriched
with an isolated Ghidra headless export.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

from .analyzer import scan_file
from .ghidra import GhidraError, export_headless


MAGICS = (b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
          b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")


def is_candidate(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4).startswith(MAGICS)
    except OSError:
        return False


def collect(paths, recursive=False):
    """Use magic bytes rather than extension or CTF-specific naming."""
    found = {}
    for source in paths:
        path = Path(source)
        if path.is_file():
            found[str(path.resolve())] = path.resolve()
        elif path.is_dir():
            iterator = path.rglob("*") if recursive else path.iterdir()
            for item in iterator:
                if item.is_file() and is_candidate(item):
                    found[str(item.resolve())] = item.resolve()
        else:
            raise ValueError("input does not exist: %s" % path)
    return [found[key] for key in sorted(found)]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pwnscan-batch", description="Offline batch CTF triage with optional Ghidra analysis"
    )
    parser.add_argument("targets", nargs="+", type=Path, help="binary files or directories")
    parser.add_argument("-r", "--recursive", action="store_true", help="walk directories recursively")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("pwnscan-reports"))
    parser.add_argument("--ghidra-auto", action="store_true", help="run Ghidra headless for each binary")
    parser.add_argument("--ghidra-home", type=Path, help="Ghidra installation root")
    parser.add_argument("--ghidra-script", type=Path, help="override PwnscanExport.java")
    parser.add_argument("--ghidra-timeout", type=int, default=300, metavar="SECONDS")
    parser.add_argument("--keep-ghidra-export", action="store_true", help="save per-target Ghidra JSON")
    args = parser.parse_args(argv)
    if args.ghidra_timeout < 1:
        parser.error("--ghidra-timeout must be positive")
    if args.keep_ghidra_export and not args.ghidra_auto:
        parser.error("--keep-ghidra-export requires --ghidra-auto")
    try:
        targets = collect(args.targets, args.recursive)
        if not targets:
            raise ValueError("no supported binary candidates found")
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        if not output_dir.is_dir():
            raise ValueError("output path is not a directory: %s" % output_dir)
    except (OSError, ValueError) as exc:
        print("pwnscan-batch: %s" % exc, file=sys.stderr)
        return 2

    index = {"schema": "pwnscan-batch/v1", "results": []}
    failures = 0
    for target in targets:
        export = None
        entry = {"target": str(target), "status": "error"}
        try:
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            # Include the digest to prevent collisions between equal basenames.
            prefix = target.name.replace("/", "_").replace("\\", "_") + "-" + digest[:16]
            if args.ghidra_auto:
                export = export_headless(
                    target, args.ghidra_home, args.ghidra_script, args.ghidra_timeout
                )
            report = scan_file(target, export)
            report_file = output_dir / (prefix + ".json")
            report_file.write_text(
                json.dumps(report.as_dict(), sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            entry.update(status="ok", sha256=digest, report=str(report_file),
                         findings=len(report.findings))
            if export is not None and args.keep_ghidra_export:
                ghidra_file = output_dir / (prefix + ".ghidra.json")
                shutil.copyfile(export, ghidra_file)
                entry["ghidra_export"] = str(ghidra_file)
        except (OSError, ValueError, GhidraError) as exc:
            failures += 1
            entry["error"] = str(exc)
        finally:
            if export is not None:
                export.unlink(missing_ok=True)
        index["results"].append(entry)
        print("%s %s" % (entry["status"].upper(), target), file=sys.stderr)

    (output_dir / "index.json").write_text(
        json.dumps(index, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print("Reports: %s" % (output_dir / "index.json"))
    return 2 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

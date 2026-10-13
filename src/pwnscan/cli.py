from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import scan_file
from .ghidra import GhidraError, export_headless
from .parsers import ParseError
from .report import render_json, render_text, use_color


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="pwnscan", description="Deterministic offline triage for CTF binaries. Files are never executed.")
    result.add_argument("target", type=Path, help="ELF, PE, or Mach-O file")
    result.add_argument("--format", choices=("text", "json"), default="text", dest="output_format")
    result.add_argument("--pretty", action="store_true", help="indent JSON output")
    result.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    result.add_argument("--ghidra", type=Path, metavar="EXPORT.json", help="merge deterministic metadata exported by PwnscanExport.py")
    result.add_argument("--ghidra-auto", action="store_true", help="run optional Ghidra headless analysis and merge its export")
    result.add_argument("--ghidra-home", type=Path, help="Ghidra installation directory for --ghidra-auto")
    result.add_argument("--ghidra-script", type=Path, help=argparse.SUPPRESS)
    result.add_argument("--ghidra-timeout", type=int, default=300, metavar="SECONDS", help="headless timeout; default: 300")
    result.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"), help="return 3 if this severity or higher exists")
    result.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if not args.target.is_file():
        print("pwnscan: target is not a file: %s" % args.target, file=sys.stderr)
        return 2
    generated_export = None
    try:
        if args.ghidra and args.ghidra_auto:
            raise ValueError("choose either --ghidra or --ghidra-auto")
        if args.ghidra_timeout < 1:
            raise ValueError("--ghidra-timeout must be positive")
        generated_export = export_headless(args.target, args.ghidra_home, args.ghidra_script, args.ghidra_timeout) if args.ghidra_auto else None
        report = scan_file(args.target, generated_export or args.ghidra)
    except (OSError, ParseError, ValueError, GhidraError) as exc:
        print("pwnscan: %s" % exc, file=sys.stderr)
        return 2
    finally:
        if generated_export is not None:
            generated_export.unlink(missing_ok=True)
    if args.output_format == "json":
        print(render_json(report, args.pretty))
    else:
        sys.stdout.write(render_text(report, use_color(args.color)))
    if args.fail_on:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if any(order[item.severity] <= order[args.fail_on] for item in report.findings):
            return 3
    return 0

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import scan_file
from .parsers import ParseError
from .report import render_json, render_text, use_color


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="pwnscan", description="Deterministic offline triage for CTF binaries. Files are never executed.")
    result.add_argument("target", type=Path, help="ELF, PE, or Mach-O file")
    result.add_argument("--format", choices=("text", "json"), default="text", dest="output_format")
    result.add_argument("--pretty", action="store_true", help="indent JSON output")
    result.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    result.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"), help="return 3 if this severity or higher exists")
    result.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if not args.target.is_file():
        print("pwnscan: target is not a file: %s" % args.target, file=sys.stderr)
        return 2
    try:
        report = scan_file(args.target)
    except (OSError, ParseError) as exc:
        print("pwnscan: %s" % exc, file=sys.stderr)
        return 2
    if args.output_format == "json":
        print(render_json(report, args.pretty))
    else:
        sys.stdout.write(render_text(report, use_color(args.color)))
    if args.fail_on:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if any(order[item.severity] <= order[args.fail_on] for item in report.findings):
            return 3
    return 0

from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__
from .analyzer import SEVERITY_ORDER, scan_file
from .ghidra import (
    GhidraError,
    default_cache_path,
    export_headless,
    is_cache_valid,
    write_cached_export,
)
from .report import render_json, render_text, use_color


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="pwnscan", description="Deterministic offline triage for CTF binaries. Files are never executed.")
    result.add_argument("target", type=Path, help="ELF, PE, or Mach-O file")
    result.add_argument("--format", choices=("text", "json"), default="text", dest="output_format")
    result.add_argument("--pretty", action="store_true", help="indent JSON output")
    result.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    result.add_argument("--output", "-o", type=Path, metavar="FILE", help="write report to a file instead of stdout")
    result.add_argument("--min-severity", choices=("critical", "high", "medium", "low", "info"), help="only include findings at this severity or higher")
    result.add_argument("--ghidra", type=Path, metavar="EXPORT.json", help="merge deterministic metadata exported by PwnscanExport.java")
    result.add_argument("--ghidra-auto", action="store_true", help="run optional Ghidra headless analysis and merge its export")
    result.add_argument("--ghidra-cache", action="store_true", help="with --ghidra-auto, reuse or save <target>.ghidra.json (or --ghidra-keep) when up-to-date")
    result.add_argument("--ghidra-keep", type=Path, metavar="EXPORT.json", help="with --ghidra-auto, also save the generated Ghidra export to this file")
    result.add_argument("--ghidra-home", type=Path, help="Ghidra installation directory for --ghidra-auto")
    result.add_argument("--ghidra-script", type=Path, help=argparse.SUPPRESS)
    result.add_argument("--ghidra-timeout", type=int, default=300, metavar="SECONDS", help="headless timeout; default: 300")
    result.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"), help="return 3 if this severity or higher exists")
    result.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return result


def _check_args(args: argparse.Namespace) -> None:
    if args.ghidra and args.ghidra_auto:
        raise ValueError("choose either --ghidra or --ghidra-auto")
    if args.ghidra_keep and not args.ghidra_auto:
        raise ValueError("--ghidra-keep requires --ghidra-auto")
    if args.ghidra_cache and not args.ghidra_auto:
        raise ValueError("--ghidra-cache requires --ghidra-auto")
    if args.ghidra_keep is not None:
        keep = args.ghidra_keep.resolve()
        if keep.is_dir() or not keep.parent.is_dir():
            raise ValueError("invalid Ghidra export path: %s" % args.ghidra_keep)
    if args.ghidra_timeout < 1:
        raise ValueError("--ghidra-timeout must be positive")
    if args.output is not None:
        output = args.output.resolve()
        if output.is_dir() or not output.parent.is_dir():
            raise ValueError("invalid output path: %s" % args.output)


def _render(args: argparse.Namespace, report) -> str:
    if args.output_format == "json":
        return render_json(report, args.pretty) + "\n"
    color_mode = "never" if (args.output is not None and args.color == "auto") else args.color
    return render_text(report, use_color(color_mode))


def _filtered(args: argparse.Namespace, report):
    if not args.min_severity:
        return report
    threshold = SEVERITY_ORDER[args.min_severity]
    return replace(report, findings=[item for item in report.findings if SEVERITY_ORDER[item.severity] <= threshold])


def _resolve_ghidra_export(args: argparse.Namespace) -> tuple[Path | None, Path | None]:
    if not args.ghidra_auto:
        return args.ghidra, None
    cache_path = args.ghidra_keep.resolve() if args.ghidra_keep is not None else default_cache_path(args.target)
    if args.ghidra_cache and is_cache_valid(args.target, cache_path):
        print("pwnscan: reusing cached Ghidra export %s" % cache_path, file=sys.stderr)
        return cache_path, None
    print("pwnscan: running Ghidra headless analysis (timeout: %ds)..." % args.ghidra_timeout, file=sys.stderr)
    generated = export_headless(args.target, args.ghidra_home, args.ghidra_script, args.ghidra_timeout)
    if args.ghidra_cache:
        write_cached_export(args.target, generated, cache_path)
    elif args.ghidra_keep is not None:
        shutil.copyfile(generated, cache_path)
    return generated, generated


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if not args.target.is_file():
        print("pwnscan: target is not a file: %s" % args.target, file=sys.stderr)
        return 2
    generated_export = None
    try:
        _check_args(args)
        ghidra_export, generated_export = _resolve_ghidra_export(args)
        report = _filtered(args, scan_file(args.target, ghidra_export))
        rendered = _render(args, report)
        if args.output is not None:
            args.output.resolve().write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (OSError, ValueError, GhidraError) as exc:
        print("pwnscan: %s" % exc, file=sys.stderr)
        return 2
    finally:
        if generated_export is not None:
            generated_export.unlink(missing_ok=True)
    if args.fail_on and any(SEVERITY_ORDER[item.severity] <= SEVERITY_ORDER[args.fail_on] for item in report.findings):
        return 3
    return 0

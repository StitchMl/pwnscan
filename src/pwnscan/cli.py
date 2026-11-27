from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from typing import Optional

from . import __version__
from .analyzer import SEVERITY_ORDER, scan_file
from .ghidra import (
    GhidraError,
    default_cache_path,
    export_headless,
    find_headless_executable,
    is_cache_valid,
    write_cached_export,
)
from .report import (
    render_batch_markdown,
    render_json,
    render_markdown,
    render_text,
    use_color,
)


def parser() -> argparse.ArgumentParser:
    examples = (
        "examples:\n"
        "  pwnscan ./challenge\n"
        "  pwnscan ./challenge --ghidra-auto --ghidra-cache\n"
        "  pwnscan ./challenge --ghidra ./challenge.ghidra.json --min-severity medium\n"
        "  pwnscan ./challenges_dir/ --min-severity medium\n"
        "  pwnscan ./challenges_dir/ --format json --pretty -o triage.json"
    )
    result = argparse.ArgumentParser(
        prog="pwnscan",
        description="Deterministic offline triage for CTF binaries. Files are never executed.",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    result.add_argument("target", type=Path, help="ELF, PE, or Mach-O file, or a directory for batch triage (auto-pairs <file>.ghidra.json)")
    result.add_argument("--format", choices=("text", "json", "markdown"), default="text", dest="output_format")
    result.add_argument("--pretty", action="store_true", help="indent JSON output")
    result.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    result.add_argument("--output", "-o", type=Path, metavar="FILE", help="write report to a file instead of stdout")
    result.add_argument("--min-severity", choices=("critical", "high", "medium", "low", "info"), help="only include findings at this severity or higher")
    result.add_argument("--ghidra", type=Path, metavar="EXPORT.json", help="merge deterministic metadata exported by PwnscanExport.java")
    ghidra_mode = result.add_mutually_exclusive_group()
    ghidra_mode.add_argument("--ghidra-auto", dest="ghidra_auto", action="store_true", default=None,
                             help="run Ghidra headless analysis (also detected automatically when installed)")
    ghidra_mode.add_argument("--no-ghidra-auto", dest="ghidra_auto", action="store_false",
                             help="disable automatic Ghidra analysis")
    result.add_argument("--ghidra-cache", action="store_true", help="with --ghidra-auto, reuse or save <target>.ghidra.json (or --ghidra-keep) when up-to-date")
    result.add_argument("--ghidra-keep", type=Path, metavar="EXPORT.json", help="with --ghidra-auto, also save the generated Ghidra export to this file")
    result.add_argument("--ghidra-home", type=Path, help="Ghidra installation directory for --ghidra-auto")
    result.add_argument("--ghidra-script", type=Path, help=argparse.SUPPRESS)
    result.add_argument("--ghidra-timeout", type=int, default=300, metavar="SECONDS", help="headless timeout; default: 300")
    result.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"), help="return 3 if this severity or higher exists")
    result.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return result


def _check_args(args: argparse.Namespace) -> None:
    _check_ghidra_options(args)
    _check_output_paths(args)
    _check_target_options(args)


def _check_ghidra_options(args: argparse.Namespace) -> None:
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


def _check_output_paths(args: argparse.Namespace) -> None:
    if args.output is not None:
        output = args.output.resolve()
        if output.is_dir() or not output.parent.is_dir():
            raise ValueError("invalid output path: %s" % args.output)


def _check_target_options(args: argparse.Namespace) -> None:
    if args.target.is_dir() and (args.ghidra is not None or args.ghidra_keep is not None):
        raise ValueError("--ghidra and --ghidra-keep cannot be used with a directory target")


def _render(args: argparse.Namespace, report) -> str:
    if args.output_format == "json":
        return render_json(report, args.pretty) + "\n"
    if args.output_format == "markdown":
        return render_markdown(report)
    color_mode = "never" if (args.output is not None and args.color == "auto") else args.color
    return render_text(report, use_color(color_mode))


def _filtered(args: argparse.Namespace, report):
    if not args.min_severity:
        return report
    threshold = SEVERITY_ORDER[args.min_severity]
    return replace(report, findings=[item for item in report.findings if SEVERITY_ORDER[item.severity] <= threshold])


def _resolve_ghidra_export(target: Path, args: argparse.Namespace) -> tuple[Optional[Path], Optional[Path]]:
    if args.ghidra is not None:
        return args.ghidra, None
    automatic = args.ghidra_auto is None
    auto = _automatic_ghidra_enabled(args)
    if not auto:
        return _sidecar_export(target, args)
    cache_path = args.ghidra_keep.resolve() if args.ghidra_keep is not None else default_cache_path(target)
    if args.ghidra_cache and is_cache_valid(target, cache_path):
        print("pwnscan: reusing cached Ghidra export %s" % cache_path, file=sys.stderr)
        return cache_path, None
    return _run_ghidra_export(target, args, automatic, cache_path)


def _automatic_ghidra_enabled(args: argparse.Namespace) -> bool:
    if args.ghidra_auto is not None:
        return args.ghidra_auto
    found = find_headless_executable(args.ghidra_home) is not None
    if not found and args.ghidra_home is not None:
        raise GhidraError("no Ghidra headless executable found under --ghidra-home")
    return found


def _sidecar_export(target: Path, args: argparse.Namespace) -> tuple[Optional[Path], Optional[Path]]:
    if not args.target.is_dir():
        return None, None
    sidecar = default_cache_path(target)
    return (sidecar, None) if sidecar.is_file() else (None, None)


def _run_ghidra_export(target: Path, args: argparse.Namespace, automatic: bool,
                       cache_path: Path) -> tuple[Optional[Path], Optional[Path]]:
    print("pwnscan: running Ghidra headless analysis (timeout: %ds)..." % args.ghidra_timeout, file=sys.stderr)
    try:
        generated = export_headless(target, args.ghidra_home, args.ghidra_script, args.ghidra_timeout)
    except (OSError, GhidraError) as exc:
        if not automatic:
            raise
        print("pwnscan: automatic Ghidra analysis unavailable; continuing with static triage: %s" % exc,
              file=sys.stderr)
        return None, None
    if args.ghidra_cache:
        write_cached_export(target, generated, cache_path)
    elif args.ghidra_keep is not None:
        shutil.copyfile(generated, cache_path)
    return generated, generated


def _batch_targets(directory: Path) -> list[Path]:
    ignored_suffixes = (".ghidra.json", ".report.json", ".report.txt", ".report.md")
    return sorted(
        path for path in directory.iterdir()
        if path.is_file() and not any(path.name.endswith(suffix) for suffix in ignored_suffixes)
    )


def _scan_single(target: Path, args: argparse.Namespace):
    generated_export = None
    try:
        ghidra_export, generated_export = _resolve_ghidra_export(target, args)
        return _filtered(args, scan_file(target, ghidra_export))
    finally:
        if generated_export is not None:
            generated_export.unlink(missing_ok=True)


def _render_batch(args: argparse.Namespace, reports: list) -> str:
    if args.output_format == "json":
        return json.dumps(
            [report.as_dict() for report in reports],
            indent=2 if args.pretty else None,
            sort_keys=True,
            separators=None if args.pretty else (",", ":"),
            ensure_ascii=True,
        ) + "\n"
    if args.output_format == "markdown":
        return render_batch_markdown(reports)
    lines = ["%-30s %-18s %-10s %s" % ("TARGET", "ARCH", "TOP", "FINDINGS")]
    for report in reports:
        arch = "%s/%s/%s" % (report.binary.format, report.binary.bits, report.binary.architecture)
        top = report.findings[0].severity if report.findings else "none"
        ids = ", ".join(item.id for item in report.findings) if report.findings else "none"
        lines.append("%-30s %-18s %-10s %s" % (Path(report.target).name, arch, top, ids))
    return "\n".join(lines) + "\n"


def _write_output(args: argparse.Namespace, rendered: str) -> None:
    if args.output is not None:
        args.output.resolve().write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


def _has_fail_severity(args: argparse.Namespace, reports: list) -> bool:
    if not args.fail_on:
        return False
    threshold = SEVERITY_ORDER[args.fail_on]
    return any(SEVERITY_ORDER[item.severity] <= threshold for report in reports for item in report.findings)


def _run_batch(args: argparse.Namespace) -> int:
    reports = []
    for entry in _batch_targets(args.target):
        try:
            reports.append(_scan_single(entry, args))
        except ValueError:
            continue
    if not reports:
        raise ValueError("no supported binaries found in directory: %s" % args.target)
    _write_output(args, _render_batch(args, reports))
    return 3 if _has_fail_severity(args, reports) else 0


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if not args.target.is_file() and not args.target.is_dir():
        print("pwnscan: target is not a file: %s" % args.target, file=sys.stderr)
        return 2
    try:
        _check_args(args)
        if args.target.is_dir():
            return _run_batch(args)
        report = _scan_single(args.target, args)
        _write_output(args, _render(args, report))
    except (OSError, ValueError, GhidraError) as exc:
        print("pwnscan: %s" % exc, file=sys.stderr)
        return 2
    return 3 if _has_fail_severity(args, [report]) else 0

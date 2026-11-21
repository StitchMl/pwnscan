"""Generate and optionally execute a proof-oriented CTF solver.

Only a proven format-string finding plus a token-length clue enables the
built-in template. Unsupported challenges are reported, never guessed.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

from .analyzer import scan_file
from .ghidra import export_headless, GhidraError


def inferred_length(strings) -> int | None:
    patterns = (
        r"(\d{1,3})[- ]character\s+uppercase",
        r"uppercase\s+(?:secret\s+)?(?:password|token)\s+.{0,32}?(\d{1,3})",
    )
    for string in strings:
        for pattern in patterns:
            match = re.search(pattern, string, re.I)
            if match and 1 <= int(match.group(1)) <= 128:
                return int(match.group(1))
    return None


def _wsl_path(path: Path) -> str:
    completed = subprocess.run(
        ["wsl.exe", "--exec", "wslpath", "-a", str(path.resolve())],
        capture_output=True, text=True, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("WSL path translation failed: " + completed.stderr.strip())
    return completed.stdout.strip()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pwnscan-solve",
        description="Generate a local proof-of-concept from supported static findings",
    )
    parser.add_argument("target", type=Path)
    parser.add_argument("-o", "--output", type=Path, help="save standalone solver script")
    parser.add_argument("--execute", action="store_true",
                        help="opt in to running the target locally (untrusted code)")
    parser.add_argument("--wsl", action="store_true",
                        help="run generated Linux solver under installed WSL")
    parser.add_argument("--token-length", type=int,
                        help="known length of an uppercase token, when not in strings")
    parser.add_argument("--max-position", type=int, default=48)
    parser.add_argument("--ghidra-home", type=Path)
    parser.add_argument("--ghidra-timeout", type=int, default=300)
    parser.add_argument("--no-ghidra", action="store_true", help="disable automatic Ghidra enrichment")
    args = parser.parse_args(argv)
    if args.wsl and not args.execute:
        parser.error("--wsl requires --execute")
    if not 1 <= args.max_position <= 256:
        parser.error("--max-position must be between 1 and 256")
    if not args.target.is_file():
        parser.error("target is not a file: %s" % args.target)
    try:
        # Use Ghidra evidence when available; report unsupported cases explicitly.
        export = None
        try:
            if not args.no_ghidra:
                export = export_headless(args.target, args.ghidra_home, timeout=args.ghidra_timeout)
            report = scan_file(args.target, export)
        finally:
            if export is not None:
                export.unlink(missing_ok=True)
        finding_ids = {item.id for item in report.findings}
        if "PWN-FMT-001" not in finding_ids:
            print("No supported format-string exploit candidate in static findings.", file=sys.stderr)
            return 2
        length = args.token_length or inferred_length(report.binary.strings)
        if length is None:
            print("No token-length evidence. Supply --token-length N if known.", file=sys.stderr)
            return 2
        if not 1 <= length <= 128:
            parser.error("--token-length must be between 1 and 128")
        runtime = Path(__file__).with_name("solver_runtime.py").read_text(encoding="utf-8")
        output = (args.output or args.target.with_name(args.target.name + ".solve.py")).resolve()
        if output == args.target.resolve():
            parser.error("output would overwrite target")
        output.write_text(
            "#!/usr/bin/env python3\n"
            + "TARGET = " + repr(str(args.target.resolve())) + "\n"
            + "TOKEN_LENGTH = " + repr(length) + "\n\n" + runtime,
            encoding="utf-8",
        )
        print("Generated solver: %s (token length: %d)" % (output, length))
        if not args.execute:
            print("Execution disabled. Use --execute --wsl on Windows with WSL installed.")
            return 0
        if args.wsl:
            command = ["wsl.exe", "--exec", "python3", _wsl_path(output),
                       _wsl_path(args.target), "--max-position", str(args.max_position)]
        elif os.name == "nt":
            print("Cannot natively execute ELF on Windows; use --execute --wsl.", file=sys.stderr)
            return 2
        else:
            command = [sys.executable, str(output), str(args.target.resolve()),
                       "--max-position", str(args.max_position)]
        return subprocess.run(command, check=False).returncode
    except (OSError, ValueError, RuntimeError, GhidraError) as exc:
        print("pwnscan-solve: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

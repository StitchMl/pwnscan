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


def proven_ret2win(report):
    """Accept only the complete payload already proved by the static analyzer."""
    for finding in report.findings:
        if finding.id != "PWN-FLAG-CHAIN-001" or finding.exploit_status != "payload-ready":
            continue
        evidence = finding.evidence
        if not any("saved return address offset" in item for item in evidence):
            continue
        if not any("stack canary disabled" in item for item in evidence):
            continue
        match = re.search(r"(?:^|[;\s])payload_hex=([0-9a-fA-F]+)(?:[;\s]|$)", finding.attack_vector)
        if not match or len(match.group(1)) % 2:
            continue
        payload = bytes.fromhex(match.group(1))
        if len(payload) < 8 or len(payload) > 65536:
            continue
        # The analyzer only emits this finding for non-PIE, non-canary binaries,
        # but validate the mitigation state again before handing bytes to a runner.
        mitigations = report.binary.mitigations
        aslr_key = "pie" if report.binary.format in ("ELF", "Mach-O") else "aslr"
        if mitigations.get("stack_canary") is not False or mitigations.get(aslr_key) is not False:
            continue
        return payload.hex()
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
    parser.add_argument("--strategy", choices=("auto", "format-token", "ret2win"), default="auto")
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
        ret2win_hex = proven_ret2win(report)
        fmt = next(
            (finding for finding in report.findings
             if finding.id == "PWN-FMT-001" and finding.confidence == "high"
             and any("dynamic format argument at " in evidence for evidence in finding.evidence)),
            None,
        )
        length = args.token_length or inferred_length(report.binary.strings)
        if args.strategy == "ret2win" and ret2win_hex is None:
            print("No proven direct ret2win payload in the Ghidra findings.", file=sys.stderr)
            return 2
        if args.strategy == "format-token" and (fmt is None or length is None):
            print("No high-confidence dynamic format call or token length.", file=sys.stderr)
            return 2
        if args.strategy != "format-token" and ret2win_hex is not None:
            strategy = "ret2win"
            runtime_name = "ret2win_runtime.py"
            definitions = "PAYLOAD_HEX = " + repr(ret2win_hex) + "\n"
        elif fmt is not None and length is not None:
            strategy = "format-token"
            runtime_name = "solver_runtime.py"
            if not 1 <= length <= 128:
                parser.error("--token-length must be between 1 and 128")
            definitions = "TOKEN_LENGTH = " + repr(length) + "\n"
        else:
            print("No supported proven strategy. A format finding alone does not prove exploitability.",
                  file=sys.stderr)
            return 2
        runtime = Path(__file__).with_name(runtime_name).read_text(encoding="utf-8")
        output = (args.output or args.target.with_name(args.target.name + ".solve.py")).resolve()
        if output == args.target.resolve():
            parser.error("output would overwrite target")
        output.write_text(
            "#!/usr/bin/env python3\n"
            + "TARGET = " + repr(str(args.target.resolve())) + "\n"
            + definitions + "\n" + runtime,
            encoding="utf-8",
        )
        print("Generated solver: %s (strategy: %s)" % (output, strategy))
        if not args.execute:
            print("Execution disabled. Use --execute --wsl on Windows with WSL installed.")
            return 0
        if args.wsl:
            command = ["wsl.exe", "--exec", "python3", _wsl_path(output),
                       _wsl_path(args.target)]
            if strategy == "format-token":
                command += ["--max-position", str(args.max_position)]
        elif os.name == "nt":
            print("Cannot natively execute ELF on Windows; use --execute --wsl.", file=sys.stderr)
            return 2
        else:
            command = [sys.executable, str(output), str(args.target.resolve())]
            if strategy == "format-token":
                command += ["--max-position", str(args.max_position)]
        return subprocess.run(command, check=False).returncode
    except (OSError, ValueError, RuntimeError, GhidraError) as exc:
        print("pwnscan-solve: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

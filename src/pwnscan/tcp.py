"""Bounded, opt-in TCP transcript runner for local CTF protocol validation.

A JSON transcript contains steps with "send" (UTF-8), "send_hex" (raw bytes),
or "recv_until" (UTF-8). This is a protocol harness, NOT an automatic
heap exploit generator or a remote exploitation service.
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import sys
from pathlib import Path


MAX_TRANSCRIPT = 131072
MAX_STEPS = 64
MAX_SEND = 4096
FLAGS = re.compile(rb"[A-Za-z0-9_]+\{[^\s{}]{1,256}\}")


def load_steps(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not 1 <= len(data) <= MAX_STEPS:
        raise ValueError("transcript must be an array of 1..64 steps")
    for index, step in enumerate(data):
        if not isinstance(step, dict) or len(step) != 1:
            raise ValueError("step %d must have exactly one action" % (index + 1))
        key, value = next(iter(step.items()))
        if key not in {"send", "send_hex", "recv_until"} or not isinstance(value, str):
            raise ValueError("unsupported step %d" % (index + 1))
        if key == "send":
            payload = value.encode("utf-8")
        elif key == "send_hex":
            payload = bytes.fromhex(value)
        else:
            payload = value.encode("utf-8")
            if not payload:
                raise ValueError("empty receive delimiter")
        if len(payload) > MAX_SEND:
            raise ValueError("step %d exceeds 4096-byte limit" % (index + 1))
    return data


def read_until(sock: socket.socket, delimiter: bytes, budget: int) -> bytes:
    output = bytearray()
    while delimiter not in output:
        chunk = sock.recv(min(4096, budget - len(output)))
        if not chunk:
            break
        output.extend(chunk)
        if len(output) >= budget and delimiter not in output:
            raise ValueError("receive budget exceeded")
    return bytes(output)


def execute(host: str, port: int, steps: list[dict], timeout: float) -> bytes:
    transcript = bytearray()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        for step in steps:
            action, value = next(iter(step.items()))
            if action == "recv_until":
                received = read_until(sock, value.encode("utf-8"), MAX_TRANSCRIPT - len(transcript))
                transcript.extend(received)
                if value.encode("utf-8") not in received:
                    raise ValueError("receive delimiter missing before EOF")
            elif action == "send":
                sock.sendall(value.encode("utf-8"))
            else:
                sock.sendall(bytes.fromhex(value))
            if len(transcript) >= MAX_TRANSCRIPT:
                raise ValueError("transcript output limit exceeded")
    return bytes(transcript)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pwnscan-tcp",
        description="Opt-in, bounded TCP protocol transcript runner (not an exploit solver)",
    )
    parser.add_argument("steps", type=Path, help="JSON array of send/recv_until actions")
    parser.add_argument("--host", default="127.0.0.1", help="authorized CTF endpoint")
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--execute", action="store_true", help="explicitly connect and send transcript")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535 or not 0 < args.timeout <= 30:
        parser.error("invalid port or timeout")
    try:
        steps = load_steps(args.steps)
        if not args.execute:
            print("Validated %d protocol steps; no connection made. Pass --execute to run." % len(steps))
            return 0
        result = execute(args.host, args.port, steps, args.timeout)
        print(result.decode("utf-8", "replace"))
        matches = sorted(set(FLAGS.findall(result)))
        for flag in matches:
            print("FLAG CANDIDATE:", flag.decode("utf-8", "replace"))
        print("STATUS: %s" % ("flag-pattern-observed" if matches else "transcript-complete; no flag observed"))
        return 0 if matches else 1
    except (OSError, ValueError, json.JSONDecodeError, socket.timeout) as exc:
        print("pwnscan-tcp: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

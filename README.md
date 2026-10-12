# pwnscan

`pwnscan` performs deterministic static triage of CTF jeopardy binaries. It
identifies exploit surfaces, explains a possible route to the flag, and gives
defensive fixes. It reads files as bytes and never executes them.

The CLI supports ELF, PE, and thin Mach-O files. Python 3.9 or newer is the
only runtime requirement.

## Install

```console
python -m pip install .
pwnscan ./challenge
```

You can run the source tree without installation:

```console
python -m pwnscan ./challenge --format json --pretty
```

Set `PYTHONPATH=src` for the second form when running from a checkout.

## Output

Text output includes binary metadata, mitigations, evidence, an attack vector,
validation steps, and a defensive patch. JSON output uses the stable
`pwnscan/v1` schema.

```console
pwnscan ./challenge --color always
pwnscan ./challenge --format json --pretty
pwnscan ./challenge --fail-on high
```

`--fail-on` returns exit code `3` when the report contains the selected
severity or a higher one. Parse and input errors return `2`.

The current rules cover:

- unbounded copies and reads that may provide a stack or heap overwrite;
- attacker-controlled format-string candidates;
- command execution sinks;
- `win`, `print_flag`, shell, and flag clues;
- missing NX, canary, PIE/ASLR, RELRO, and CFG signals.

`pwnscan` derives findings from file contents. It does not use file names,
paths, network services, an LLM, or challenge-specific signatures. Reports
sort maps, symbols, strings, evidence, and findings before serialization. The
target path appears in the report for operator context, so it is the only
path-dependent field.

Static evidence does not prove exploitability. Use each finding as a debugger
and decompiler worklist inside the authorized CTF environment.

## Ghidra

The CLI remains the primary interface. Ghidra improves call-site and data-flow
review after triage; embedding the whole scanner in Ghidra would weaken CLI
portability and complicate deterministic testing.

[`ghidra_scripts/PwnscanExport.py`](ghidra_scripts/PwnscanExport.py) exports
Ghidra symbols, functions, and imports to deterministic JSON. Run it from
Ghidra's Script Manager after analysis. Pass the JSON to your own correlation
workflow or inspect it beside `pwnscan --format json` output. See
[`docs/ghidra.md`](docs/ghidra.md).

## Tests

```console
python -m pip install -e ".[dev]"
python -m pytest
```

The tests construct minimal binary headers in memory. They do not run fixture
binaries.

## Scope and safety

Use this tool for CTF challenges, labs, and systems you may test. `pwnscan`
does not generate weaponized payloads, connect to targets, or execute code.

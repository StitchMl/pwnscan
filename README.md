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

The current engine covers:

- parsed imports, undefined ELF symbols, exported functions, and string hints as separate evidence classes;
- ELF gadgets, useful-string addresses, RWX sections, symbol addresses, PIE versus DSO, and RELRO state;
- PE import tables, ASLR, DEP, CFG, and RWX sections;
- unbounded writes, format-string targets, command sinks, ret2win paths, and mitigation gaps;
- computed `p32`/`p64` ret2win scaffolds when a symbol address exists.

An isolated API name inside arbitrary data remains a low-confidence hint. High
confidence requires structural evidence, such as an import plus a Ghidra call
reference.

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
Ghidra symbols, functions, imports, and call references to deterministic JSON.
Run it from Ghidra's Script Manager after analysis, then merge it directly:

```console
pwnscan ./challenge --ghidra ./challenge.ghidra.json
```

See
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
does not connect to targets or execute target code. Generated scaffolds contain
only addresses derived from the supplied artifact and require manual validation.

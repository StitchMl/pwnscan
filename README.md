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
an exploit-readiness state, a flag path, validation steps, and a defensive
patch. JSON output uses the stable
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
- Ghidra-backed integer allocation arithmetic, write-length conversions, repeated frees, post-free memory use, and indirect call targets;
- an exact ret2win payload when Ghidra proves the saved-return offset, input
  capacity, fixed target address, and absence of a stack canary.

An isolated API name inside arbitrary data remains a low-confidence hint. High
confidence requires structural evidence, such as an import plus a Ghidra call
reference.

`pwnscan` derives findings from file contents. It does not use file names,
paths, network services, an LLM, or challenge-specific signatures. Reports
sort maps, symbols, strings, evidence, and findings before serialization. The
target path appears in the report for operator context, so it is the only
path-dependent field.

`payload-ready` is reserved for a complete static exploit chain with exact
bytes and a flag-path function. Every incomplete hypothesis is marked
`validation-only`; the scanner does not invent offsets or addresses.

## Ghidra

The CLI remains the primary interface. Ghidra improves call-site and data-flow
review after triage; embedding the whole scanner in Ghidra would weaken CLI
portability and complicate deterministic testing.

[`ghidra_scripts/PwnscanExport.java`](ghidra_scripts/PwnscanExport.java) exports
Ghidra symbols, functions, imports, call arguments, bounded P-code expression
trees, indirect targets, and stack-buffer sizes to deterministic JSON. The Python variant is retained
for PyGhidra installations. Run either exporter after analysis, then merge it:

```console
pwnscan ./challenge --ghidra ./challenge.ghidra.json
```

If Ghidra is installed, the CLI can create an isolated temporary project,
run headless analysis, merge the result, and remove the project:

```console
pwnscan ./challenge --ghidra-auto --ghidra-home C:\Tools\ghidra_12.0_PUBLIC
```

Set `GHIDRA_HOME` instead of passing `--ghidra-home`. `--ghidra-timeout`
limits analysis time. Ghidra reads and decompiles the target; it never runs it.
Recovered P-code arguments let `pwnscan` prove constant-size stack overwrites,
compute saved-return offsets, reject constant `printf("%s", value)` calls, and
rank dynamic command arguments. Expression trees also expose arithmetic and
width conversions used by allocation and memory-write lengths. Pointer identity
facts support lifetime review without claiming that two branch-separated calls
execute on the same path.

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

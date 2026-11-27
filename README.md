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

Text output includes binary metadata, mitigations, a per-severity findings summary, evidence, an attack vector,
an exploit-readiness state, a flag path, validation steps, and a defensive
patch. JSON output uses the stable
`pwnscan/v1` schema.

```console
pwnscan ./challenge --color always
pwnscan ./challenge --format json --pretty
pwnscan ./challenge --min-severity medium --output report.txt
pwnscan ./challenge --fail-on high
pwnscan ./challenges/ --min-severity medium
```

Passing a directory runs batch triage across all supported binaries inside it, automatically pairing any adjacent `<file>.ghidra.json` export and printing a compact summary table (or a JSON array with `--format json`). `--min-severity` filters the reported findings to the selected severity or higher
(and `--fail-on` evaluates the filtered findings). `--output` (`-o`) writes the
report to a file without ANSI color sequences in `auto` mode. `--fail-on`
returns exit code `3` when the report contains the selected severity or a higher
one. Parse and input errors return `2`.

The current engine covers:

- parsed imports, undefined ELF/Mach-O symbols, exported functions (ELF, PE, Mach-O), and string hints as separate evidence classes;
- ELF gadgets, useful-string addresses, RWX sections, symbol addresses, PIE (including static-PIE via `DF_1_PIE`) versus DSO, and RELRO state;
- PE import/export tables, ASLR, DEP, CFG, and RWX sections;
- unbounded writes, format-string targets, command sinks, ret2win paths, and mitigation gaps;
- Ghidra-backed constant-length stack overwrites, integer allocation arithmetic, write-length sign/truncation conversions, repeated frees, post-free memory use, and indirect call targets;
- structural flag-output correlation: `open` of a flag-like path whose descriptor (call result) reaches `sendfile`/`write`/`fwrite`, reported as a candidate flag path on `PWN-WIN-001`;
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

When Ghidra is installed, pwnscan locates it from `PATH`, `GHIDRA_HOME`, and
common install directories, then runs headless analysis automatically for each
binary. It creates an isolated temporary project, merges the export, and
removes the project. Pass `--no-ghidra-auto` to skip this analysis:

```console
pwnscan ./challenge
pwnscan ./challenge --no-ghidra-auto
```

`--ghidra-auto` forces the analysis and reports an error if Ghidra is not
installed. `--ghidra-home` remains available for a nonstandard install;
`--ghidra-timeout` limits analysis time. Add `--ghidra-keep EXPORT.json` to save the
generated export next to the report instead of discarding it, or `--ghidra-cache`
to reuse `<target>.ghidra.json` when its `sha256` still matches the binary. Ghidra reads
and decompiles the target; it never runs it.
Recovered P-code arguments let `pwnscan` prove constant-size stack overwrites,
compute saved-return offsets, reject constant `printf("%s", value)` calls, and
rank dynamic command arguments. Expression trees also expose arithmetic and
width conversions used by allocation and memory-write lengths. Pointer identity
facts support lifetime review without claiming that two branch-separated calls
execute on the same path.

See
[`docs/ghidra.md`](docs/ghidra.md).

## Known limitations

- **Intraprocedural heap lifetime (`PWN-HEAP-001`, `PWN-HEAP-002`)**: calls within a function are ordered by address without full CFG/dominance or pointer-reassignment tracking, so mutually exclusive branches can trigger false positives.
- **Expression-tree integer checks (`PWN-INT-001`, `PWN-SIGN-001`)**: P-code expression trees identify arithmetic or width/sign conversions with dynamic operands, without proving the absence of prior bounds checks.
- **Byte-level gadget scan (`PWN-ROP-001`)**: ELF gadgets are matched as raw byte sequences in executable sections and should be verified against instruction boundaries in a disassembler.
- **Thin Mach-O only**: universal/fat Mach-O containers are rejected; extract a single architecture slice first.

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

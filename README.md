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
pwnscan ./challenge --min-severity medium --output report.txt
pwnscan ./challenge --fail-on high
```

`--min-severity` filters the reported findings to the selected severity or higher
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

## Batch analysis of arbitrary CTF binaries

Install Ghidra separately and set `GHIDRA_HOME` to its extracted installation
root (containing `support/analyzeHeadless`). The batch entry point accepts
individual files and directories. It detects ELF, PE, and thin Mach-O candidates
by magic bytes, not file extension or challenge name. Binaries are **never
executed**.

```console
pwnscan-batch ./challenges --recursive --ghidra-auto --output-dir ./reports
pwnscan-batch ./challenge1 ./challenge2 --ghidra-auto --keep-ghidra-export
```

Reports are saved as separate JSON files with SHA-256-derived suffixes to avoid
basename collisions, plus an `index.json` listing successes and failures.
An unsupported or failed target does not abort the remaining batch; the command
returns exit code 2 if any target failed. Default execution without
`--ghidra-auto` performs fast static triage. Use `--ghidra-timeout 600` for
large binaries, and `--ghidra-home /path/to/ghidra` to select a specific Ghidra
install. Ghidra headless analysis is CPU/memory intensive and processes files
sequentially to keep resource usage bounded.

When installed from a source checkout with `pip install -e .`, the bundled
Java exporter is discovered automatically. The batch command also supports
`--ghidra-script /path/to/PwnscanExport.java` when using a custom exporter.

## Experimental exploit solver (explicit opt-in)

The static scanner does not recover runtime secrets or flags. The `pwnscan-solve`
command is an experimental solver for Ghidra-evidenced dynamic format-string
calls and uppercase secrets of known or inferred length. Unsupported binaries
return a diagnostic instead of a fabricated flag. It is not a universal solver.

On Windows, Ghidra runs automatically first and a standalone Linux script is
generated. With `--execute --wsl`, the script runs inside WSL:

```powershell
pwnscan-solve "C:\Users\Matteo\Downloads\babyfmt_level1.0" `
  --ghidra-home "C:\Tools\ghidra_12.0_PUBLIC" `
  --execute --wsl `
  --output "$HOME\Desktop\babyfmt_level1.solve.py"
```

On Linux use: `pwnscan-solve ./challenge --execute`.

The generated solver probes positional `%N$s` reads in separate processes and
submits any candidate in the same process (secrets can change across launches).
It prints a candidate only when success text is observed. A local password may
unlock a subsequent `/flag` read, but is not necessarily itself the CTF flag.
Executing an untrusted challenge is opt-in and should be done only in an isolated
authorized environment. The normal static scanner never executes the target.

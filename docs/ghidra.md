# Ghidra workflow

Keep `pwnscan` outside Ghidra for batch scans, CI, and reproducible tests. If
Ghidra is installed, pwnscan discovers it and invokes the headless adapter
automatically. The CLI remains useful without Ghidra and reports its static
findings in that case.

## Automatic headless analysis

```console
pwnscan ./challenge
pwnscan ./challenge --no-ghidra-auto
```

Detection checks `PATH`, `GHIDRA_HOME`, and common install locations. Set
`--ghidra-home` only for a nonstandard install. The adapter creates a temporary
project, imports the binary, runs analysis, exports deterministic JSON, then
deletes the project. The target is never executed. Use `--ghidra-timeout
SECONDS` to bound analysis. `--ghidra-auto` forces an error if Ghidra cannot be
found; `--no-ghidra-auto` disables automatic analysis.

The launcher also derives `JAVA_HOME` from a valid existing setting or the
`java` executable on `PATH`. On Windows it gives the headless process a
per-run `APPDATA` directory and chooses a temporary project location without
characters Ghidra rejects; no machine-wide environment variables are changed.

## Manual export

1. Copy `ghidra_scripts/PwnscanExport.java` into a Ghidra script directory.
2. Import the challenge and let Ghidra analyze it.
3. Open Script Manager and run `PwnscanExport.java`.
4. Choose an output file when Ghidra asks.
5. Merge the export with `pwnscan ./challenge --ghidra ./export.json`.

The Java exporter works in standard headless and desktop Ghidra installations
and emits sorted JSON. The Python variant requires PyGhidra. Neither modifies
the program database. The CLI validates the schema and structure before using
functions, imports, bounded P-code expression trees, indirect targets,
stack-buffer sizes, saved-return offsets, and call references.

Useful review order:

- cross-reference the dangerous imports listed by `pwnscan`;
- inspect callers, destination sizes, and input limits;
- inspect `win` or flag-related functions and their guards;
- verify stack layout and indirect calls before building a proof in the CTF
  runner.

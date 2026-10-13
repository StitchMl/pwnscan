# Ghidra workflow

Keep `pwnscan` outside Ghidra for batch scans, CI, and reproducible tests. Use
Ghidra after the CLI ranks an input, or invoke it through the optional headless
adapter.

## Automatic headless analysis

```console
pwnscan ./challenge --ghidra-auto --ghidra-home C:\Tools\ghidra_12.0_PUBLIC
```

You may set `GHIDRA_HOME`. The adapter creates a temporary project, imports the
binary, runs analysis, exports deterministic JSON, then deletes the project.
The target is never executed. Use `--ghidra-timeout SECONDS` to bound analysis.

## Manual export

1. Copy `ghidra_scripts/PwnscanExport.java` into a Ghidra script directory.
2. Import the challenge and let Ghidra analyze it.
3. Open Script Manager and run `PwnscanExport.java`.
4. Choose an output file when Ghidra asks.
5. Merge the export with `pwnscan ./challenge --ghidra ./export.json`.

The Java exporter works in standard headless and desktop Ghidra installations
and emits sorted JSON. The Python variant requires PyGhidra. Neither modifies
the program database. The CLI validates the schema and structure before using
functions, imports, P-code call arguments, stack-buffer sizes, saved-return
offsets, and call references.

Useful review order:

- cross-reference the dangerous imports listed by `pwnscan`;
- inspect callers, destination sizes, and input limits;
- inspect `win` or flag-related functions and their guards;
- verify stack layout and indirect calls before building a proof in the CTF
  runner.

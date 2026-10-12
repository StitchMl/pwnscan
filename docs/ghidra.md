# Ghidra workflow

Keep `pwnscan` outside Ghidra for batch scans, CI, and reproducible tests. Use
Ghidra after the CLI ranks an input.

1. Copy `ghidra_scripts/PwnscanExport.py` into a Ghidra script directory.
2. Import the challenge and let Ghidra analyze it.
3. Open Script Manager and run `PwnscanExport.py`.
4. Choose an output file when Ghidra asks.
5. Merge the export with `pwnscan ./challenge --ghidra ./export.json`.

The exporter uses Ghidra's Python API and emits sorted JSON. It does not modify
the program database. The CLI validates the schema and structure before using
functions, imports, and call references.

Useful review order:

- cross-reference the dangerous imports listed by `pwnscan`;
- inspect callers, destination sizes, and input limits;
- inspect `win` or flag-related functions and their guards;
- verify stack layout and indirect calls before building a proof in the CTF
  runner.

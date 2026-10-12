# Ghidra workflow

Keep `pwnscan` outside Ghidra for batch scans, CI, and reproducible tests. Use
Ghidra after the CLI ranks an input.

1. Copy `ghidra_scripts/PwnscanExport.py` into a Ghidra script directory.
2. Import the challenge and let Ghidra analyze it.
3. Open Script Manager and run `PwnscanExport.py`.
4. Choose an output file when Ghidra asks.
5. Compare the export's function and import names with the CLI report.

The exporter uses Ghidra's Jython API and emits sorted JSON. It does not modify
the program database. Ghidra versions that ship Python 3 can run the same API
calls after minor import changes.

Useful review order:

- cross-reference the dangerous imports listed by `pwnscan`;
- inspect callers, destination sizes, and input limits;
- inspect `win` or flag-related functions and their guards;
- verify stack layout and indirect calls before building a proof in the CTF
  runner.

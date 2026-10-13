from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


class GhidraError(RuntimeError):
    pass


def _headless_executable(home: Optional[Path] = None) -> Path:
    candidates = []
    if home is not None:
        candidates.append(home)
    configured = os.environ.get("GHIDRA_HOME")
    if configured:
        candidates.append(Path(configured))
    located = shutil.which("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if located:
        return Path(located)
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    for candidate in candidates:
        executable = candidate / "support" / name
        if executable.is_file():
            return executable
    raise GhidraError("Ghidra headless not found; use --ghidra-home or GHIDRA_HOME")


def _export_script(explicit: Optional[Path] = None) -> Path:
    candidates = []
    if explicit is not None:
        candidates.append(explicit)
    candidates.extend([
        Path(__file__).resolve().parents[2] / "ghidra_scripts" / "PwnscanExport.java",
        Path(sys.prefix) / "share" / "pwnscan" / "ghidra_scripts" / "PwnscanExport.java",
    ])
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise GhidraError("PwnscanExport.java not found; use --ghidra-script")


def export_headless(target: Path, home: Optional[Path] = None, script: Optional[Path] = None, timeout: int = 300) -> Path:
    """Run Ghidra analysis in an isolated temporary project and return copied JSON."""
    executable = _headless_executable(home)
    export_script = _export_script(script)
    output_handle = tempfile.NamedTemporaryFile(prefix="pwnscan-ghidra-", suffix=".json", delete=False)
    output_handle.close()
    output = Path(output_handle.name)
    with tempfile.TemporaryDirectory(prefix="pwnscan-ghidra-project-") as project:
        command = [
            str(executable), project, "pwnscan", "-import", str(target.resolve()),
            "-scriptPath", str(export_script.parent), "-postScript", export_script.name,
            str(output), "-deleteProject",
        ]
        try:
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            output.unlink(missing_ok=True)
            raise GhidraError("Ghidra headless failed: %s" % exc) from exc
        if completed.returncode != 0 or not output.is_file() or output.stat().st_size == 0:
            output.unlink(missing_ok=True)
            tail = "\n".join(completed.stdout.splitlines()[-12:])
            raise GhidraError("Ghidra headless returned %d\n%s" % (completed.returncode, tail))
    return output

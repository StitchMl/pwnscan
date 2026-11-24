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
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    # An explicit home takes precedence over PATH, avoiding accidental use of
    # a different Ghidra installation on multi-version workstations.
    for candidate in candidates:
        executable = candidate / "support" / name
        if executable.is_file():
            return executable
    located = shutil.which(name)
    if located:
        return Path(located)
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
    """Run isolated Ghidra analysis without PIPE-related launcher hangs.

    A persistent diagnostic log is retained only when Ghidra fails.
    """
    executable = _headless_executable(home)
    export_script = _export_script(script)
    output_fd, output_name = tempfile.mkstemp(prefix="pwnscan-ghidra-", suffix=".json")
    os.close(output_fd)
    output = Path(output_name)
    log_fd, log_name = tempfile.mkstemp(prefix="pwnscan-ghidra-", suffix=".log")
    os.close(log_fd)
    log_path = Path(log_name)
    failure = None
    try:
        with tempfile.TemporaryDirectory(prefix="pwnscan-ghidra-project-") as project:
            command = [
                str(executable), project, "pwnscan", "-import", str(target.resolve()),
                "-scriptPath", str(export_script.parent),
                "-postScript", export_script.name, str(output),
                "-analysisTimeoutPerFile", str(max(1, timeout // 2)),
                "-deleteProject",
            ]
            with log_path.open("wb") as logfile:
                # Ghidra launchers can leave inherited PIPE handles open after
                # the JVM exits. A real file avoids that hang and preserves logs.
                process = subprocess.Popen(
                    command, stdout=logfile, stderr=subprocess.STDOUT,
                    start_new_session=(os.name != "nt"),
                )
                try:
                    returncode = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired as exc:
                    if os.name == "nt":
                        subprocess.run(
                            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            check=False, timeout=15,
                        )
                    else:
                        import signal
                        os.killpg(process.pid, signal.SIGKILL)
                    process.kill()
                    process.wait()
                    failure = "Ghidra headless timed out after %d seconds" % timeout
                    raise GhidraError(failure + "; log: " + str(log_path)) from exc
            if returncode != 0 or output.stat().st_size == 0:
                failure = "Ghidra headless exited with code %d" % returncode
                raise GhidraError(failure + "; log: " + str(log_path) +
                                  "\n" + "\n".join(
                                      log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-15:]
                                  ))
        return output
    except (OSError, subprocess.SubprocessError):
        # Preserve the diagnostic log for subprocess and filesystem errors.
        raise
    finally:
        if failure is not None:
            output.unlink(missing_ok=True)
        else:
            log_path.unlink(missing_ok=True)

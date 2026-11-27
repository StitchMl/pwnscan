from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


class GhidraError(RuntimeError):
    pass


def _headless_temp_root() -> Path | None:
    candidates = [Path(tempfile.gettempdir())]
    if os.name == "nt":
        candidates.append(Path.home() / "AppData" / "Local" / "Temp")
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if "#" not in str(candidate) and candidate.is_dir():
            return candidate
    raise GhidraError(
        "No writable temporary directory without '#' is available for Ghidra projects"
    )


def _platform_install_roots() -> list[Path]:
    user_home = Path.home()
    roots = [
        user_home,
        user_home / "tools",
        user_home / "Tools",
        user_home / "Downloads",
        user_home / "Desktop",
        user_home / "Documents",
    ]
    if os.name == "nt":
        for variable in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "APPDATA", "USERPROFILE"):
            value = os.environ.get(variable)
            if value:
                root = Path(value)
                roots.append(root)
                roots.append(root / "Programs")
        roots.extend((Path("C:/Tools"), Path("C:/ghidra")))
    elif sys.platform == "darwin":
        roots.extend((Path("/Applications"), Path("/opt/homebrew/opt"), Path("/opt")))
    else:
        roots.extend((Path("/opt"), Path("/usr/local"), Path("/usr/local/share")))
    return roots


def _directories(root: Path) -> list[Path]:
    try:
        return sorted((item for item in root.iterdir() if item.is_dir()),
                      key=lambda item: item.name.casefold())
    except OSError:
        return []


def _append_unique(path: Path, homes: list[Path], seen: set[Path]) -> None:
    if path not in seen:
        homes.append(path)
        seen.add(path)


def _common_ghidra_homes() -> list[Path]:
    """Return bounded, common Ghidra install locations for each platform."""
    homes: list[Path] = []
    seen: set[Path] = set()
    for root in _platform_install_roots():
        _append_unique(root, homes, seen)
        for child in _directories(root):
            if "ghidra" not in child.name.casefold():
                continue
            _append_unique(child, homes, seen)
            # Some installers use Program Files/Ghidra/<version>/support.
            for version in _directories(child):
                _append_unique(version, homes, seen)
    return homes


def _headless_executable(home: Optional[Path] = None) -> Path:
    candidates: list[Path] = []
    if home is not None:
        candidates.append(home)
    configured = os.environ.get("GHIDRA_HOME")
    if configured:
        candidates.append(Path(configured))
    located = shutil.which("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if located:
        return Path(located)
    candidates.extend(_common_ghidra_homes())
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    for candidate in candidates:
        executable = candidate / "support" / name
        if executable.is_file():
            return executable
    raise GhidraError("Ghidra headless was not found in PATH, GHIDRA_HOME, or common install locations")


def find_headless_executable(home: Optional[Path] = None) -> Path | None:
    """Detect Ghidra without turning an optional default into a hard failure."""
    try:
        return _headless_executable(home)
    except GhidraError:
        return None


def _java_home() -> Path | None:
    configured = os.environ.get("JAVA_HOME")
    if configured:
        candidate = Path(configured)
        java_name = "java.exe" if os.name == "nt" else "java"
        if (candidate / "bin" / java_name).is_file():
            return candidate
    java_name = "java.exe" if os.name == "nt" else "java"
    located = shutil.which(java_name) or shutil.which("java")
    if located is None:
        return None
    executable = Path(located).resolve()
    if executable.parent.name.casefold() == "bin":
        return executable.parent.parent
    return None


def _headless_environment(app_data: Path) -> dict[str, str]:
    """Give Ghidra a discovered JDK and isolated writable per-run settings."""
    environment = os.environ.copy()
    java_home = _java_home()
    if java_home is not None:
        environment["JAVA_HOME"] = str(java_home)
    if os.name == "nt":
        app_data.mkdir(parents=True, exist_ok=True)
        environment["APPDATA"] = str(app_data)
    return environment


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
    output_fd, output_name = tempfile.mkstemp(
        prefix="pwnscan-ghidra-", suffix=".json", dir=_headless_temp_root(),
    )
    os.close(output_fd)
    output = Path(output_name)
    with tempfile.TemporaryDirectory(
        prefix="pwnscan-ghidra-project-", dir=_headless_temp_root(),
    ) as project:
        environment = _headless_environment(Path(project) / "appdata")
        command = [
            str(executable), project, "pwnscan", "-import", str(target.resolve()),
            "-scriptPath", str(export_script.parent), "-postScript", export_script.name,
            str(output), "-deleteProject",
        ]
        try:
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, check=False, env=environment)
        except (OSError, subprocess.TimeoutExpired) as exc:
            output.unlink(missing_ok=True)
            raise GhidraError("Ghidra headless failed: %s" % exc) from exc
        if completed.returncode != 0 or not output.is_file() or output.stat().st_size == 0:
            output.unlink(missing_ok=True)
            tail = "\n".join(completed.stdout.splitlines()[-30:])
            raise GhidraError("Ghidra headless returned %d\n%s" % (completed.returncode, tail))
    return output


def _target_sha256(target: Path) -> str:
    return hashlib.sha256(target.read_bytes()).hexdigest()


def default_cache_path(target: Path) -> Path:
    return target.with_name(target.name + ".ghidra.json")


def is_cache_valid(target: Path, cache_path: Path) -> bool:
    if not cache_path.is_file():
        return False
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict) or payload.get("schema") != "pwnscan-ghidra/v1":
        return False
    cached_hash = payload.get("target_sha256")
    if isinstance(cached_hash, str):
        return cached_hash == _target_sha256(target)
    return cache_path.stat().st_mtime >= target.stat().st_mtime


def write_cached_export(target: Path, export_path: Path, cache_path: Path) -> None:
    try:
        payload = json.loads(export_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        shutil.copyfile(export_path, cache_path)
        return
    if not isinstance(payload, dict):
        shutil.copyfile(export_path, cache_path)
        return
    payload["target_sha256"] = _target_sha256(target)
    cache_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

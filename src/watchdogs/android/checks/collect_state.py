#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TOOLS: dict[str, dict[str, Any]] = {
    "adb": {"version": ["adb", "version"]},
    "fastboot": {"version": ["fastboot", "--version"]},
    "aapt": {"version": ["aapt", "version"]},
    "aapt2": {"version": ["aapt2", "version"]},
    "apksigner": {"version": ["apksigner", "--version"]},
    "zipalign": {"version": ["zipalign", "--version"]},
    "sdkmanager": {
        "version": ["sdkmanager", "--version"],
        "probe": ["sdkmanager", "--list"],
        "probe_timeout": 20,
    },
    "jadx": {"version": ["jadx", "--version"], "probe": ["jadx", "--version"]},
    "jadx-gui": {"version": ["jadx-gui", "--help"], "probe": ["jadx-gui", "--help"]},
    "frida": {"version": ["frida", "--version"]},
    "frida-ps": {"version": ["frida-ps", "--version"]},
    "frida-trace": {"version": ["frida-trace", "--version"]},
    "ghidra": {"version": ["ghidra", "-version"], "probe": ["ghidra", "-version"], "probe_timeout": 25},
    "java": {"version": ["java", "-version"]},
    "javac": {"version": ["javac", "-version"]},
    "python3": {"version": ["python3", "--version"]},
    "pipx": {"version": ["pipx", "--version"]},
    "apktool": {"version": ["apktool", "--version"]},
    "dex2jar": {"version": ["dex2jar", "--version"]},
}

SHELL_FILES = [
    Path.home() / ".bashrc",
    Path.home() / ".zshrc",
    Path.home() / ".profile",
    Path.home() / ".config/shell/shared/aliases.sh",
    Path.home() / ".config/shell/shared/workflows.sh",
]

SDK_CANDIDATES = [
    Path.home() / "Android/Sdk",
    Path("/usr/lib/android-sdk"),
    Path("/usr/share/android-sdk"),
    Path("/opt/android-sdk"),
]


@dataclass
class RunResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def combined(self) -> str:
        return "\n".join(part for part in [self.stdout.strip(), self.stderr.strip()] if part).strip()


def run(cmd: list[str], timeout: int = 10) -> RunResult:
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
        return RunResult(command=cmd, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except FileNotFoundError as exc:
        return RunResult(command=cmd, returncode=127, stdout="", stderr=str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace")
        return RunResult(command=cmd, returncode=124, stdout=stdout, stderr=stderr, timed_out=True)


def read_shebang(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            line = handle.readline(256)
    except OSError:
        return None
    if not line.startswith(b"#!"):
        return None
    return line[2:].decode(errors="replace").strip()


def first_lines(text: str, limit: int = 8) -> str:
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines[:limit])


def version_dirs(path: Path) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    seen: set[str] = set()
    for parent in [path] + list(path.parents[:6]):
        if not parent.name or not re.search(r"\d", parent.name):
            continue
        key = str(parent)
        if key in seen:
            continue
        seen.add(key)
        matches.append({"path": key, "exists": parent.exists()})
    return matches


def which_all(name: str) -> list[dict[str, Any]]:
    result = run(["which", "-a", name])
    paths: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        candidate = line.strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        resolved = os.path.realpath(candidate) if os.path.exists(candidate) else None
        paths.append(
            {
                "path": candidate,
                "resolved_path": resolved,
                "exists": os.path.exists(candidate),
                "executable": os.access(candidate, os.X_OK) if os.path.exists(candidate) else False,
            }
        )
    return paths


def collect_tool(name: str, spec: dict[str, Any]) -> dict[str, Any]:
    command_path = shutil.which(name)
    paths = which_all(name)
    resolved_path = os.path.realpath(command_path) if command_path else None
    exists = bool(command_path and os.path.exists(command_path))
    executable = bool(command_path and os.access(command_path, os.X_OK))
    is_symlink = bool(command_path and os.path.islink(command_path))
    symlink_target = os.readlink(command_path) if is_symlink else None
    symlink_target_valid = bool(command_path and (not is_symlink or os.path.exists(os.path.realpath(command_path))))

    version_result = run(spec["version"], timeout=spec.get("version_timeout", 10)) if command_path else None
    probe_result = run(spec["probe"], timeout=spec.get("probe_timeout", 10)) if command_path and spec.get("probe") else None

    interpreter = None
    interpreter_exists = None
    if command_path:
        shebang = read_shebang(Path(command_path))
        if shebang:
            interpreter = shebang.split()[0]
            interpreter_exists = shutil.which(Path(interpreter).name) is not None or Path(interpreter).exists()

    unique_resolved = sorted({entry["resolved_path"] for entry in paths if entry["resolved_path"]})
    shadowed = len(unique_resolved) > 1
    notes: list[str] = []
    status = "OK"
    if not command_path:
        status = "FAIL"
        notes.append(f"{name} is missing from PATH")
    elif not executable:
        status = "FAIL"
        notes.append(f"{command_path} exists but is not executable")
    elif not symlink_target_valid:
        status = "FAIL"
        notes.append(f"{command_path} is a broken symlink")
    elif version_result and not version_result.ok and name not in {"ghidra", "jadx-gui"}:
        version_text = first_lines(version_result.combined())
        if name == "zipalign" and "Zip alignment utility" in version_text:
            pass
        else:
            status = "WARN"
            notes.append(f"version command failed with exit {version_result.returncode}")

    if shadowed:
        if status == "OK":
            status = "WARN"
        notes.append(f"multiple distinct binaries found; {command_path} wins over {', '.join(unique_resolved[1:])}")

    if interpreter and interpreter_exists is False:
        status = "FAIL"
        notes.append(f"launcher interpreter is missing: {interpreter}")

    if probe_result and not probe_result.ok and name in {"ghidra", "jadx", "jadx-gui", "sdkmanager"}:
        status = "FAIL" if name in {"ghidra", "sdkmanager"} else ("WARN" if status == "OK" else status)
        notes.append(f"launcher probe failed with exit {probe_result.returncode}")

    return {
        "name": name,
        "status": status,
        "notes": notes,
        "command_path": command_path,
        "resolved_path": resolved_path,
        "exists": exists,
        "executable": executable,
        "which_all": paths,
        "shadowed": shadowed,
        "is_symlink": is_symlink,
        "symlink_target": symlink_target,
        "symlink_target_valid": symlink_target_valid,
        "version_text": first_lines(version_result.combined()) if version_result else "",
        "version_ok": version_result.ok if version_result else False,
        "version_returncode": version_result.returncode if version_result else None,
        "probe_text": first_lines(probe_result.combined()) if probe_result else "",
        "probe_ok": probe_result.ok if probe_result else None,
        "probe_returncode": probe_result.returncode if probe_result else None,
        "interpreter": interpreter,
        "interpreter_exists": interpreter_exists,
        "versioned_install_dirs": version_dirs(Path(resolved_path)) if resolved_path else [],
    }


def parse_java_major(version_text: str) -> int | None:
    match = re.search(r'version "(\d+)', version_text)
    if not match:
        match = re.search(r"(\d+)\.\d+\.\d+", version_text)
    return int(match.group(1)) if match else None


def alternatives_info(name: str) -> dict[str, Any]:
    if shutil.which("update-alternatives") is None:
        return {"available": False, "name": name}
    result = run(["update-alternatives", "--query", name], timeout=10)
    data = {"available": True, "name": name, "returncode": result.returncode, "raw": first_lines(result.combined(), limit=20)}
    value = None
    candidates: list[str] = []
    for line in result.stdout.splitlines():
        if line.startswith("Value: "):
            value = line.split(": ", 1)[1].strip()
        elif line.startswith("Alternative: "):
            candidates.append(line.split(": ", 1)[1].strip())
    data["value"] = value
    data["candidates"] = candidates
    return data


def detect_sdk_root(sdkmanager_path: str | None) -> dict[str, Any]:
    env_root = os.environ.get("ANDROID_SDK_ROOT")
    env_home = os.environ.get("ANDROID_HOME")
    candidates: list[Path] = []
    for raw in [env_root, env_home]:
        if raw:
            candidates.append(Path(raw).expanduser())
    if sdkmanager_path:
        path = Path(os.path.realpath(sdkmanager_path))
        for parent in [path.parent] + list(path.parents):
            if (parent / "platform-tools").exists() or (parent / "build-tools").exists() or (parent / "cmdline-tools").exists():
                candidates.append(parent)
    candidates.extend(SDK_CANDIDATES)

    seen: set[str] = set()
    inspected: list[dict[str, Any]] = []
    selected = None
    for candidate in candidates:
        resolved = str(candidate.expanduser())
        if resolved in seen:
            continue
        seen.add(resolved)
        entry = {
            "path": resolved,
            "exists": candidate.exists(),
            "platform_tools": (candidate / "platform-tools").exists(),
            "build_tools": (candidate / "build-tools").exists(),
            "cmdline_tools": (candidate / "cmdline-tools").exists(),
            "platforms": (candidate / "platforms").exists(),
        }
        inspected.append(entry)
        if entry["exists"] and (entry["platform_tools"] or entry["build_tools"] or entry["cmdline_tools"]):
            selected = resolved
            break

    status = "OK" if selected else "FAIL"
    notes = [] if selected else ["could not find a valid Android SDK root"]
    return {
        "status": status,
        "notes": notes,
        "env": {"ANDROID_SDK_ROOT": env_root, "ANDROID_HOME": env_home},
        "selected_root": selected,
        "candidates": inspected,
    }


def collect_path_state() -> dict[str, Any]:
    path_entries = os.environ.get("PATH", "").split(":")
    raw_duplicates = sorted({entry for entry in path_entries if entry and path_entries.count(entry) > 1})
    resolved_map: dict[str, list[str]] = {}
    missing_entries: list[str] = []
    for entry in path_entries:
        if not entry:
            continue
        path = Path(entry)
        if not path.exists():
            missing_entries.append(entry)
            continue
        resolved_map.setdefault(str(path.resolve()), []).append(entry)
    resolved_duplicates = {key: value for key, value in resolved_map.items() if len(value) > 1}
    status = "OK"
    notes: list[str] = []
    if raw_duplicates:
        status = "WARN"
        notes.append("PATH contains duplicate entries")
    if missing_entries:
        status = "WARN"
        notes.append("PATH contains non-existent directories")
    return {
        "status": status,
        "notes": notes,
        "entries": path_entries,
        "raw_duplicates": raw_duplicates,
        "resolved_duplicates": resolved_duplicates,
        "missing_entries": missing_entries,
    }


def collect_shell_state() -> dict[str, Any]:
    exports: dict[str, list[dict[str, Any]]] = {"ANDROID_HOME": [], "ANDROID_SDK_ROOT": []}
    path_lines: list[dict[str, Any]] = []
    for file_path in SHELL_FILES:
        if not file_path.exists():
            continue
        for idx, line in enumerate(file_path.read_text(errors="replace").splitlines(), start=1):
            for var in exports:
                match = re.search(rf"(?:export\s+)?{var}=([^\s#;]+)", line)
                if match:
                    value = match.group(1).strip('"').strip("'")
                    exports[var].append({"file": str(file_path), "line": idx, "value": value})
            if any(token in line for token in ["platform-tools", "cmdline-tools", "build-tools", "ANDROID_HOME", "ANDROID_SDK_ROOT"]):
                path_lines.append({"file": str(file_path), "line": idx, "text": line.strip()})
    notes: list[str] = []
    status = "OK"
    for var, entries in exports.items():
        values = {entry["value"] for entry in entries}
        if len(values) > 1:
            status = "WARN"
            notes.append(f"{var} is assigned multiple different values in shell config")
        for entry in entries:
            value = entry["value"].replace("$HOME", str(Path.home()))
            candidate = Path(os.path.expandvars(value)).expanduser()
            if not candidate.exists():
                status = "WARN"
                notes.append(f"{var} points to a missing path in {entry['file']}:{entry['line']}")
    return {"status": status, "notes": notes, "exports": exports, "path_lines": path_lines[:20], "managed_block_found": bool(path_lines)}


def collect_frida_python_state(tools: dict[str, dict[str, Any]]) -> dict[str, Any]:
    notes: list[str] = []
    status = "OK"
    python_path = tools["python3"]["command_path"]
    import_result = run([python_path, "-c", "import frida,sys; print(frida.__version__)"], timeout=10) if python_path else None
    pipx_result = run(["pipx", "list"], timeout=20) if tools["pipx"]["command_path"] else None
    frida_tool_paths = [tools[name]["command_path"] for name in ["frida", "frida-ps", "frida-trace"] if tools[name]["command_path"]]
    if any(not tools[name]["command_path"] for name in ["frida", "frida-ps", "frida-trace"]):
        status = "FAIL"
        notes.append("one or more Frida CLI tools are missing")
    if import_result and not import_result.ok:
        if pipx_result and "frida-tools" in pipx_result.combined() and frida_tool_paths:
            notes.append("system python3 cannot import frida, but pipx-managed Frida tools are present")
        else:
            status = "FAIL"
            notes.append("python3 cannot import frida")
    if pipx_result and "frida-tools" not in pipx_result.combined():
        if status == "OK":
            status = "WARN"
        notes.append("pipx does not list frida-tools")
    interpreters = {tools[name]["interpreter"] for name in ["frida", "frida-ps", "frida-trace"] if tools[name]["interpreter"]}
    if len(interpreters) > 1:
        if status == "OK":
            status = "WARN"
        notes.append("Frida tools use different launch interpreters")
    return {
        "status": status,
        "notes": notes,
        "python_import": first_lines(import_result.combined()) if import_result else "",
        "python_import_ok": import_result.ok if import_result else False,
        "pipx_list": first_lines(pipx_result.combined(), limit=20) if pipx_result else "",
        "tool_paths": frida_tool_paths,
    }


def collect_java_state(tools: dict[str, dict[str, Any]]) -> dict[str, Any]:
    java_text = tools["java"]["version_text"]
    javac_text = tools["javac"]["version_text"]
    java_major = parse_java_major(java_text)
    javac_major = parse_java_major(javac_text)
    ghidra_probe = tools["ghidra"]["probe_text"].lower()
    status = "OK"
    notes: list[str] = []
    if java_major and javac_major and java_major != javac_major:
        status = "FAIL"
        notes.append(f"java reports {java_major} while javac reports {javac_major}")
    if "requires java" in ghidra_probe or "requires at least" in ghidra_probe or "unsupported java" in ghidra_probe:
        status = "FAIL"
        notes.append("Ghidra reported a Java compatibility problem")
    if tools["ghidra"]["command_path"] and not tools["ghidra"]["probe_ok"]:
        status = "FAIL"
        notes.append("Ghidra launcher probe failed")
    return {
        "status": status,
        "notes": notes,
        "java_major": java_major,
        "javac_major": javac_major,
        "alternatives": {"java": alternatives_info("java"), "javac": alternatives_info("javac")},
    }


def overall_status(sections: list[str]) -> str:
    if "FAIL" in sections:
        return "FAIL"
    if "WARN" in sections:
        return "WARN"
    return "OK"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    tools = {name: collect_tool(name, spec) for name, spec in TOOLS.items()}
    sdk_state = detect_sdk_root(tools["sdkmanager"]["resolved_path"])
    path_state = collect_path_state()
    shell_state = collect_shell_state()
    frida_python = collect_frida_python_state(tools)
    java_state = collect_java_state(tools)

    state = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hostname": os.uname().nodename,
        "cwd": os.getcwd(),
        "tools": tools,
        "sdk": sdk_state,
        "path_state": path_state,
        "shell_state": shell_state,
        "frida_python": frida_python,
        "java_state": java_state,
    }
    state["overall_status"] = overall_status(
        [tool["status"] for tool in tools.values()]
        + [sdk_state["status"], path_state["status"], shell_state["status"], frida_python["status"], java_state["status"]]
    )

    Path(args.output).write_text(json.dumps(state, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

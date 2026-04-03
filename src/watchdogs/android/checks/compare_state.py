#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


TOOL_ORDER = [
    "adb",
    "fastboot",
    "aapt",
    "aapt2",
    "apksigner",
    "zipalign",
    "sdkmanager",
    "jadx",
    "jadx-gui",
    "frida",
    "frida-ps",
    "frida-trace",
    "ghidra",
    "java",
    "javac",
    "python3",
    "pipx",
    "apktool",
    "dex2jar",
]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def normalize_version(text: str) -> str:
    return " ".join(text.split())


def add_issue(issues: list[str], message: str) -> None:
    if message not in issues:
        issues.append(message)


def tool_diff(name: str, current: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    status = current.get("status", "OK")
    issues = list(current.get("notes", []))

    if baseline:
        old_path = baseline.get("resolved_path") or baseline.get("command_path")
        new_path = current.get("resolved_path") or current.get("command_path")
        if old_path and new_path and old_path != new_path:
            if status == "OK":
                status = "WARN"
            add_issue(issues, f"active path changed: {old_path} -> {new_path}")
        if baseline.get("command_path") and not current.get("command_path"):
            status = "FAIL"
            add_issue(issues, f"tool disappeared from PATH; baseline path was {baseline.get('command_path')}")
        old_version = normalize_version(baseline.get("version_text", ""))
        new_version = normalize_version(current.get("version_text", ""))
        if old_version and new_version and old_version != new_version:
            if status == "OK":
                status = "WARN"
            add_issue(issues, f"version drift: {old_version} -> {new_version}")
        if current.get("shadowed") and not baseline.get("shadowed", False):
            if status == "OK":
                status = "WARN"
            add_issue(issues, "new duplicate PATH conflict detected")

    return {
        "name": name,
        "status": status,
        "current_path": current.get("command_path"),
        "current_resolved_path": current.get("resolved_path"),
        "current_version": current.get("version_text", ""),
        "baseline_path": baseline.get("command_path") if baseline else None,
        "baseline_resolved_path": baseline.get("resolved_path") if baseline else None,
        "baseline_version": baseline.get("version_text", "") if baseline else "",
        "issues": issues,
    }


def section_diff(name: str, current: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    status = current.get("status", "OK")
    issues = list(current.get("notes", [])) if status != "OK" else []
    if baseline:
        if name == "sdk":
            if baseline.get("selected_root") and current.get("selected_root") != baseline.get("selected_root"):
                if status == "OK":
                    status = "WARN"
                add_issue(issues, f"SDK root changed: {baseline.get('selected_root')} -> {current.get('selected_root')}")
            if baseline.get("selected_root") and not current.get("selected_root"):
                status = "FAIL"
                add_issue(issues, "SDK root is now broken or missing")
        elif name == "path_state":
            old_dupes = set(baseline.get("raw_duplicates", []))
            new_dupes = set(current.get("raw_duplicates", []))
            if new_dupes - old_dupes:
                if status == "OK":
                    status = "WARN"
                add_issue(issues, f"new PATH duplicates: {', '.join(sorted(new_dupes - old_dupes))}")
        elif name == "shell_state":
            old_notes = set(baseline.get("notes", []))
            for note in sorted(set(current.get("notes", [])) - old_notes):
                if status == "OK":
                    status = "WARN"
                add_issue(issues, note)
        elif name == "frida_python" and baseline.get("status") == "OK" and current.get("status") != "OK":
            status = "FAIL" if current.get("status") == "FAIL" else "WARN"
            add_issue(issues, "Frida/Python environment regressed from the baseline")
        elif name == "java_state" and baseline.get("status") == "OK" and current.get("status") != "OK":
            status = "FAIL"
            add_issue(issues, "Java/Ghidra compatibility regressed from the baseline")
    return {"name": name, "status": status, "issues": issues}


def overall_status(items: list[dict[str, Any]]) -> str:
    states = [item["status"] for item in items]
    if "FAIL" in states:
        return "FAIL"
    if "WARN" in states:
        return "WARN"
    return "OK"


def remediation_hints(items: list[dict[str, Any]], sections: dict[str, dict[str, Any]]) -> list[str]:
    hints: list[str] = []
    if any(item["name"] == "dex2jar" and item["status"] == "FAIL" for item in items):
        hints.append("Install or restore dex2jar, then re-run: sudo apt install dex2jar  # or restore your preferred local wrapper")
    if any(item["name"] == "sdkmanager" and item["status"] == "FAIL" for item in items):
        hints.append("Inspect the SDK install and root detection: sdkmanager --version ; ls -la /usr/lib/android-sdk ~/Android/Sdk")
    if any(item["name"] in {"ghidra", "jadx", "jadx-gui"} and item["status"] != "OK" for item in items):
        hints.append("Probe the launchers directly: ghidra -version ; jadx --version ; jadx-gui --help")
    if sections["java_state"]["status"] != "OK":
        hints.append("Check Java alternatives and Ghidra compatibility: update-alternatives --query java ; java -version ; javac -version")
    if sections["frida_python"]["status"] != "OK":
        hints.append("Check Frida tooling and the Python environment: pipx list ; python3 -c 'import frida; print(frida.__version__)'")
    if sections["path_state"]["status"] != "OK":
        hints.append("Review PATH ordering and duplicate directories in your shell startup files before changing anything")
    return hints


def render_summary(
    baseline_present: bool,
    overall: str,
    tool_items: list[dict[str, Any]],
    section_items: list[dict[str, Any]],
    remediation: list[str],
) -> str:
    lines = [
        f"Android Tooling Watchdog: {overall}",
        f"Baseline: {'present' if baseline_present else 'not initialized'}",
        "",
        "Dashboard",
    ]
    for item in tool_items:
        lines.append(f"{item['status']:<4} {item['name']:<12} {item.get('current_path') or 'missing'}")
    lines.append(f"{section_items[0]['status']:<4} sdk-env      {', '.join(section_items[0]['issues']) or 'SDK root and sdkmanager look usable'}")
    lines.append(f"{section_items[1]['status']:<4} path-env     {', '.join(section_items[1]['issues']) or 'PATH duplication check clean'}")
    lines.append(f"{section_items[2]['status']:<4} shell-env    {', '.join(section_items[2]['issues']) or 'Shell Android exports look consistent'}")
    lines.append(f"{section_items[3]['status']:<4} frida-python {', '.join(section_items[3]['issues']) or 'Frida and Python look consistent'}")
    lines.append(f"{section_items[4]['status']:<4} java-ghidra  {', '.join(section_items[4]['issues']) or 'Java and Ghidra look compatible'}")
    lines.extend(["", "Findings"])
    findings = [item for item in tool_items if item["issues"]]
    findings.extend([item for item in section_items if item["issues"]])
    if not findings and baseline_present:
        lines.append("No drift or breakage detected.")
    elif not baseline_present:
        lines.append("No last-good baseline exists yet; this run can be promoted only after the environment is healthy.")
    for item in findings:
        for issue in item["issues"]:
            lines.append(f"- {item['name']}: {issue}")
    lines.extend(["", "Recommended Remediation"])
    if remediation:
        for hint in remediation:
            lines.append(f"- {hint}")
    else:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--current", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--diff", required=True)
    args = parser.parse_args()

    baseline_data = load_json(Path(args.baseline))
    current_data = load_json(Path(args.current))
    baseline_present = bool(baseline_data.get("tools")) and baseline_data.get("baseline_status") != "uninitialized"

    tool_items = []
    for name in TOOL_ORDER:
        baseline_tool = baseline_data.get("tools", {}).get(name) if baseline_present else None
        tool_items.append(tool_diff(name, current_data["tools"][name], baseline_tool))

    sections = {
        "sdk": section_diff("sdk", current_data["sdk"], baseline_data.get("sdk") if baseline_present else None),
        "path_state": section_diff("path_state", current_data["path_state"], baseline_data.get("path_state") if baseline_present else None),
        "shell_state": section_diff("shell_state", current_data["shell_state"], baseline_data.get("shell_state") if baseline_present else None),
        "frida_python": section_diff("frida_python", current_data["frida_python"], baseline_data.get("frida_python") if baseline_present else None),
        "java_state": section_diff("java_state", current_data["java_state"], baseline_data.get("java_state") if baseline_present else None),
    }
    section_items = [sections["sdk"], sections["path_state"], sections["shell_state"], sections["frida_python"], sections["java_state"]]

    overall = overall_status(tool_items + section_items)
    remediation = remediation_hints(tool_items, sections)
    summary_text = render_summary(baseline_present, overall, tool_items, section_items, remediation)

    diff_data = {
        "overall_status": overall,
        "baseline_present": baseline_present,
        "tools": tool_items,
        "sections": sections,
        "recommended_remediation": remediation,
    }

    Path(args.summary).write_text(summary_text)
    Path(args.diff).write_text(json.dumps(diff_data, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

parser = argparse.ArgumentParser(description="Scan every staged Rift artifact component without assigning a safety verdict.")
parser.add_argument("--artifact-dir", required=True, type=Path)
parser.add_argument("--runtime-report", type=Path)
parser.add_argument("--out", required=True, type=Path)
parser.add_argument("--yara-rules", type=Path)
parser.add_argument("--clamav", action="store_true")
args = parser.parse_args()

signals = {
    "managed.dynamic-load": ("Assembly.Load", "Assembly.LoadFrom", "LoadFromAssemblyPath"),
    "process.execution": ("Process.Start", "cmd.exe", "powershell", "/bin/sh"),
    "native.memory": ("VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory"),
    "network.client": ("HttpClient", "WebClient", "HttpWebRequest", "Socket.Connect"),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def strings(path: Path) -> set[str]:
    with path.open("rb") as stream:
        data = stream.read(8 * 1024 * 1024)
    return {match.decode("ascii", "ignore") for match in re.findall(rb"[\x20-\x7e]{4,}", data)}


def kind(path: Path, content: bytes) -> str:
    if content[:2] == b"MZ":
        return "managed-pe" if b"BSJB" in content else "native-pe"
    return {".zip": "archive", ".dll": "unknown-dll", ".exe": "unknown-executable"}.get(path.suffix.lower(), "data")


def external(command: list[str], path: Path, found_exit: int) -> dict:
    try:
        result = subprocess.run([*command, str(path)], capture_output=True, text=True, timeout=30)
        return {"status": "finding" if result.returncode == found_exit else "clean" if result.returncode == 0 else "error", "output": (result.stdout + result.stderr)[-8192:] or None}
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}


def yara_scan(path: Path) -> dict:
    try:
        result = subprocess.run([yara, "-r", str(args.yara_rules), str(path)], capture_output=True, text=True, timeout=30)
        output = (result.stdout + result.stderr)[-8192:] or None
        return {"status": "finding" if result.returncode == 0 and result.stdout.strip() else "clean" if result.returncode == 0 else "error", "output": output}
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}


loaded_hashes: set[str] = set()
if args.runtime_report:
    runtime = json.loads(args.runtime_report.read_text(encoding="utf-8"))
    loaded_hashes = {
        item.get("parameters", {}).get("artifact_sha256")
        for item in runtime.get("observations", [])
        if item.get("kind") in {"assembly_load", "native_library"}
    }

yara = shutil.which("yara") if args.yara_rules else None
clamav = shutil.which("clamscan") if args.clamav else None
components = []
for path in sorted(item for item in args.artifact_dir.rglob("*") if item.is_file()):
    with path.open("rb") as stream:
        content = stream.read(1024 * 1024)
    component_kind = kind(path, content)
    inspectable = component_kind in {"managed-pe", "native-pe", "unknown-dll", "unknown-executable"} or path.suffix.lower() in {".ps1", ".sh", ".bat", ".cmd"}
    text = strings(path) if inspectable else set()
    findings = [name for name, terms in signals.items() if any(term in candidate for term in terms for candidate in text)]
    digest = sha256(path)
    item = {
        "path": path.relative_to(args.artifact_dir).as_posix(),
        "sha256": digest,
        "bytes": path.stat().st_size,
        "kind": component_kind,
        "observed_loaded": digest in loaded_hashes,
        "static_signals": findings,
    }
    if yara:
        item["yara"] = yara_scan(path)
    if clamav:
        item["clamav"] = external([clamav, "--no-summary"], path, 1)
    components.append(item)

report = {
    "schema_version": "rift.component-security.v1",
    "producer": "interdimensional-rift-component-scanner",
    "artifact_tree_sha256": (json.loads(args.runtime_report.read_text(encoding="utf-8")).get("execution", {}).get("artifact_tree_sha256") if args.runtime_report else None),
    "engines": {
        "deterministic_static": "active",
        "yara": "active" if yara else "not_requested" if not args.yara_rules else "unavailable",
        "clamav": "active" if clamav else "not_requested" if not args.clamav else "unavailable",
    },
    "components": components,
}
args.out.parent.mkdir(parents=True, exist_ok=True)
args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

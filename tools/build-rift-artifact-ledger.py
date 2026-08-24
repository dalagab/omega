#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description="Produce a merge-ready ledger of every component in a Rift artifact.")
parser.add_argument("report", type=Path)
parser.add_argument("--observer", type=Path)
parser.add_argument("--component-security", type=Path)
parser.add_argument("--out", required=True, type=Path)
args = parser.parse_args()

runtime = json.loads(args.report.read_text(encoding="utf-8"))
inventory = runtime.get("artifact_inventory") or {}
execution = runtime.get("execution") or {}
loaded_hashes = {
    observation.get("parameters", {}).get("artifact_sha256")
    for observation in runtime.get("observations", [])
    if observation.get("kind") in {"assembly_load", "native_library"}
}
components = []
for item in inventory.get("files") or []:
    item = dict(item)
    item["observed_loaded"] = item.get("sha256") in loaded_hashes
    components.append(item)
observer = json.loads(args.observer.read_text(encoding="utf-8")) if args.observer else None
component_security = json.loads(args.component_security.read_text(encoding="utf-8")) if args.component_security else None
ledger = {
    "schema_version": "rift.artifact-ledger.v1",
    "artifact_tree_sha256": execution.get("artifact_tree_sha256"),
    "entry_sha256": execution.get("entry_sha256"),
    "plugin": runtime.get("plugin", {}),
    "components": components,
    "outer_observer": observer.get("summary") if observer else None,
    "component_security": component_security,
}
args.out.parent.mkdir(parents=True, exist_ok=True)
args.out.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")

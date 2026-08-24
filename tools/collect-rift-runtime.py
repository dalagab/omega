#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


parser = argparse.ArgumentParser(description="Project Rift evidence into Omega's runtime collector contract.")
parser.add_argument("--report", required=True, type=Path)
parser.add_argument("--observer", type=Path)
parser.add_argument("--component-security", type=Path)
parser.add_argument("--out", required=True, type=Path)
args = parser.parse_args()


def read_json(path: Path | None) -> dict | None:
    return json.loads(path.read_text(encoding="utf-8")) if path and path.is_file() else None


report = read_json(args.report)
if report is None:
    raise SystemExit("Rift report is required")
observer = read_json(args.observer)
component_security = read_json(args.component_security)
runtime = report.get("schema_version") == "rift.runtime-observation.v2"
supervisor = report.get("schema_version") == "rift.supervisor.v3"
if not (runtime or supervisor):
    raise SystemExit(f"unsupported Rift report schema: {report.get('schema_version')!r}")

execution = report.get("execution") or {}
plugin = report.get("plugin") or {}
collection = {
    "schema_version": "omega.collector.rift.runtime.v1",
    "collector": "omega.collector.rift.runtime",
    "subject": {
        "artifact_tree_sha256": execution.get("artifact_tree_sha256") or report.get("artifact_sha256"),
        "entry_sha256": execution.get("entry_sha256"),
        "plugin": {
            "internal_name": plugin.get("internal_name"),
            "assembly_name": plugin.get("assembly_name"),
            "path": plugin.get("path"),
        },
    },
    "execution": {
        "outcome": plugin.get("load_outcome") if runtime else execution.get("outcome"),
        "runtime_reported": runtime,
        "network": execution.get("network"),
        "network_profile": execution.get("network_profile"),
        "seccomp": execution.get("seccomp"),
        "boundary_profile": execution.get("boundary_profile"),
        "exercise_profile": execution.get("exercise_profile"),
        "ui_profile": execution.get("ui_profile"),
        "game_data_fixture_tree_sha256": execution.get("game_data_fixture_tree_sha256"),
    },
    "runtime_observations": report.get("observations") if runtime else [],
    "exercise": report.get("exercise") if runtime else None,
    "outer_observer": observer,
    "component_security": component_security,
}

args.out.parent.mkdir(parents=True, exist_ok=True)
args.out.write_text(json.dumps(collection, indent=2) + "\n", encoding="utf-8")

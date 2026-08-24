#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("report", type=Path)
parser.add_argument("--require-active", action="store_true")
args = parser.parse_args()

data = json.loads(args.report.read_text(encoding="utf-8"))
if data.get("schema_version") != "rift.outer-observer.v1":
    raise SystemExit("unsupported Rift outer observer schema")
if not isinstance(data.get("artifact_tree_sha256"), str) or len(data["artifact_tree_sha256"]) != 64:
    raise SystemExit("observer report lacks artifact tree SHA-256")
if args.require_active and data.get("observer", {}).get("status") != "active":
    raise SystemExit("required outer observer did not capture any trace files")
for event in data.get("events", []):
    if event.get("kind") not in {"filesystem", "network", "process"}:
        raise SystemExit("observer report contains unknown event kind")
    if event.get("origin", "plugin") not in {"plugin", "trusted-loopback-probe"}:
        raise SystemExit("observer report contains unknown event origin")
    if not isinstance(event.get("count"), int) or event["count"] < 1:
        raise SystemExit("observer report contains invalid event count")
probe = data.get("dynamic_loopback_probe", {})
if probe.get("status") not in {"active", "not_observed"}:
    raise SystemExit("observer report contains unknown loopback probe status")
if probe.get("status") == "active" and probe.get("network_scope") != "sandbox-loopback-only":
    raise SystemExit("active loopback probe is not confined to sandbox loopback")
print(f"Rift outer observer validation PASS: status={data.get('observer', {}).get('status')}")

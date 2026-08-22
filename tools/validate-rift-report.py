#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

parser = argparse.ArgumentParser()
parser.add_argument("report", type=Path)
parser.add_argument("--mode", required=True, choices=["runtime-ok", "alpha", "canary", "memory", "tasks", "tmpfs", "hangtree"])
args = parser.parse_args()

try:
    data = json.loads(args.report.read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"invalid Rift JSON report: {exc}")

schema = data.get("schema_version")
text = json.dumps(data, sort_keys=True)
runtime = schema == "rift.runtime-observation.v1"
supervisor = schema == "rift.supervisor.v3"

if not (runtime or supervisor):
    raise SystemExit(f"unsupported Rift report schema: {schema!r}")

def require_runtime_marker(marker: str):
    if not runtime:
        raise SystemExit(f"expected runtime report containing {marker!r}, got {schema}")
    if marker not in text:
        raise SystemExit(f"runtime report missing marker: {marker}")

if args.mode == "runtime-ok":
    if not runtime or data.get("plugin", {}).get("load_outcome") != "ok":
        raise SystemExit("expected successful runtime plugin report")

elif args.mode == "alpha":
    if not runtime or data.get("plugin", {}).get("load_outcome") != "ok":
        raise SystemExit("Alpha did not complete normally")
    for marker in (
        "RIFT_ALPHA armed inside Rift",
        "runtime.filesystem.tmpfs",
        "runtime.network.loopback",
        "runtime.http.loopback",
        "runtime.process.missing",
        "runtime.assembly.missing",
        "runtime.native-load.missing",
        "runtime.registry.readonly",
        "runtime.pinvoke.getpid",
        "runtime.framework.tick",
    ):
        require_runtime_marker(marker)

elif args.mode == "canary":
    if not runtime or data.get("plugin", {}).get("load_outcome") != "ok":
        raise SystemExit("Canary did not complete normally")
    for marker in (
        "boundary.artifact_readonly PASS",
        "boundary.runtime_readonly PASS",
        "boundary.contracts_readonly PASS",
        "boundary.host_secrets_absent PASS",
        "boundary.no_new_privileges PASS",
        "boundary.capabilities_dropped PASS",
        "boundary.network_isolated PASS",
        "boundary.nested_userns_denied PASS",
        "boundary.ptrace_denied PASS",
        "boundary.raw_packet_socket_denied PASS",
        "boundary.tmpfs_tmp_bounded PASS",
        "boundary.tmpfs_home_bounded PASS",
        "boundary.tmpfs_work_bounded PASS",
        "boundary.hostname_isolated PASS",
        "RIFT_CANARY completed",
    ):
        require_runtime_marker(marker)
    if " FAILED" in text:
        raise SystemExit("Canary emitted a FAILED boundary marker")

elif args.mode == "memory":
    if runtime:
        if "stress.memory_pressure bounded:OutOfMemoryException" not in text:
            raise SystemExit("memory fixture returned a runtime report without a bounded OOM marker")
    elif supervisor:
        outcome = data.get("execution", {}).get("outcome")
        if outcome not in {"memory_limit", "process_killed"}:
            raise SystemExit(f"memory fixture expected memory_limit/process_killed supervisor outcome, got {outcome}")
    else:
        raise SystemExit("memory fixture produced unknown outcome")

elif args.mode == "tasks":
    if runtime:
        if "stress.task_pressure bounded:" not in text:
            raise SystemExit("task fixture did not observe the task/thread bound")
        if "stress.task_pressure FAILED" in text:
            raise SystemExit("task fixture exceeded its self-test ceiling without a resource bound")
    elif supervisor:
        if data.get("execution", {}).get("outcome") not in {"tasks_limit", "process_killed"}:
            raise SystemExit("task fixture supervisor outcome was not tasks_limit/process_killed")
    else:
        raise SystemExit("task fixture produced unknown outcome")

elif args.mode == "tmpfs":
    if not runtime:
        raise SystemExit("tmpfs fixture should observe ENOSPC/IOException and return a runtime report")
    if "stress.tmpfs_pressure bounded:IOException" not in text:
        raise SystemExit("tmpfs fixture did not observe its bounded tmpfs")

elif args.mode == "hangtree":
    if runtime:
        outcome = data.get("plugin", {}).get("load_outcome")
        if outcome != "init_timeout":
            raise SystemExit(f"hang-tree fixture expected init_timeout, got {outcome}")
        if "stress.hangtree child_started" not in text:
            raise SystemExit("hang-tree fixture did not start its child before timeout")
    elif supervisor:
        if data.get("execution", {}).get("outcome") != "wall_timeout":
            raise SystemExit("hang-tree fixture expected init_timeout or wall_timeout")
    else:
        raise SystemExit("hang-tree fixture produced unknown outcome")

print(f"Rift report validation PASS: mode={args.mode} schema={schema}")

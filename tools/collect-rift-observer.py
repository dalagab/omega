#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser(description="Normalise bounded Rift strace output into neutral execution evidence.")
parser.add_argument("--trace-dir", required=True, type=Path)
parser.add_argument("--out", required=True, type=Path)
parser.add_argument("--artifact-tree-sha256", required=True)
args = parser.parse_args()

line_re = re.compile(r"^(?:\[pid\s+(?P<pid>\d+)\]\s+)?(?P<call>[a-zA-Z0-9_]+)\((?P<body>.*)\)\s+=\s+(?P<result>.*)$")
quoted_re = re.compile(r'"((?:\\.|[^"\\])*)"')
ip_re = re.compile(r'(?:inet_addr\("(?P<ipv4>[^"]+)"\)|inet_pton\([^,]+,\s*"(?P<ip>[^"]+)"|sin6_addr=inet_pton\([^,]+,\s*"(?P<ip6>[^"]+)")')
port_re = re.compile(r'(?:sin6?_port=htons\((?P<port>\d+)\))')
tcp_endpoint_re = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+):\d+$")


def outcome(result: str) -> str:
    if result.startswith("-1 "):
        errno = result.split()[1]
        return "blocked" if errno in {"EACCES", "EPERM"} else "failed"
    return "succeeded"


def event_kind(call: str) -> str | None:
    if call in {"accept", "accept4", "bind", "connect", "getpeername", "getsockname", "listen", "recv", "recvfrom", "recvmsg", "send", "sendmsg", "sendto", "shutdown", "socket"}:
        return "network"
    if call in {"execve", "clone", "clone3", "fork", "vfork"}:
        return "process"
    if call in {"open", "openat", "openat2", "access", "stat", "statx", "lstat", "readlink", "readlinkat", "unlink", "unlinkat", "rename", "renameat", "mkdir", "mkdirat"}:
        return "filesystem"
    return None


def subject(kind: str, body: str) -> str | None:
    quoted = quoted_re.findall(body)
    if kind == "network":
        match = ip_re.search(body)
        host = next((match.group(key) for key in ("ipv4", "ip", "ip6") if match and match.group(key)), None)
        port = port_re.search(body)
        if host:
            return f"{host}:{port.group('port')}" if port else host
        return quoted[0] if quoted else None
    return quoted[0] if quoted else None


trace_files = sorted(path for path in args.trace_dir.glob("*") if path.is_file())
records: list[tuple[int | None, str, str, str]] = []
records_by_pid: dict[int, list[tuple[str, str, str]]] = {}
root_pids: set[int] = set()
root_starts: dict[int, int] = {}
probe_pids: set[int] = set()


def trace_pid(path: Path) -> int | None:
    match = re.search(r"\.(\d+)$", path.name)
    return int(match.group(1)) if match else None


for trace in trace_files:
    pid = trace_pid(trace)
    for raw in trace.read_text(encoding="utf-8", errors="replace").splitlines():
        match = line_re.match(raw)
        if not match:
            continue
        call = match.group("call")
        body = match.group("body")
        result = match.group("result")
        records.append((pid, call, body, result))
        if pid is not None:
            process_records = records_by_pid.setdefault(pid, [])
            process_records.append((call, body, result))
        if pid is not None and call == "execve" and subject("process", body) == "/rift/interdimensional-rift":
            root_pids.add(pid)
            root_starts[pid] = len(records_by_pid[pid]) - 1
        if pid is not None and call == "execve" and subject("process", body) == "/rift-tools/rift-loopback-probe" and '"--probe-worker"' in body:
            probe_pids.add(pid)

selected_pids = set(root_pids)
pending = list(root_pids)
while pending:
    parent = pending.pop()
    for call, _, result in records_by_pid.get(parent, [])[root_starts.get(parent, 0):]:
        if call not in {"clone", "clone3", "fork", "vfork"}:
            continue
        child = re.match(r"^(\d+)", result)
        if child and int(child.group(1)) not in selected_pids:
            selected_pids.add(int(child.group(1)))
            pending.append(int(child.group(1)))

if not selected_pids:
    selected_pids = {pid for pid, _, _, _ in records if pid is not None}

probe_pids.difference_update(selected_pids)


def diagnostic_event(call: str, body: str, result: str) -> dict:
    kind = event_kind(call)
    return {
        "kind": kind or "other",
        "operation": call,
        "subject": subject(kind, body) if kind else None,
        "outcome": outcome(result),
    }


diagnostic_tail = []
for origin, pids, start_indexes in (
    ("plugin", selected_pids, root_starts),
    ("trusted-loopback-probe", probe_pids, {}),
):
    for pid in sorted(pids):
        tail = records_by_pid.get(pid, [])[start_indexes.get(pid, 0):][-12:]
        if tail:
            diagnostic_tail.append({
                "origin": origin,
                "pid": pid,
                "events": [diagnostic_event(call, body, result) for call, body, result in tail],
            })

events: dict[tuple[str, str, str, str | None, str], dict] = {}
if root_pids:
    event_records = [
        ("plugin", record)
        for pid in selected_pids
        for record in records_by_pid.get(pid, [])[root_starts.get(pid, 0):]
    ]
else:
    event_records = [("plugin", (call, body, result)) for _, call, body, result in records]

event_records.extend(
    ("trusted-loopback-probe", record)
    for pid in probe_pids
    for record in records_by_pid.get(pid, [])
)

for origin, (call, body, result) in event_records:
    kind = event_kind(call)
    if kind is None:
        continue
    key = (origin, kind, call, subject(kind, body), outcome(result))
    event = events.setdefault(key, {"origin": key[0], "kind": key[1], "operation": key[2], "subject": key[3], "outcome": key[4], "count": 0})
    event["count"] += 1

ordered = sorted(events.values(), key=lambda event: (event["origin"], event["kind"], event["operation"], event["subject"] or "", event["outcome"]))
summary = {kind: sum(event["count"] for event in ordered if event["kind"] == kind) for kind in ("filesystem", "network", "process")}
probe_connections = [
    event for event in ordered
    if event["origin"] == "trusted-loopback-probe" and event["kind"] == "network" and event["operation"] == "connect"
]
listener_events = [
    event for event in ordered
    if event["origin"] == "plugin" and event["kind"] == "network" and event["operation"] in {"bind", "listen", "accept", "accept4"}
]
tcp_listener_bind_events = [
    event for event in listener_events
    if event["operation"] == "bind" and isinstance(event["subject"], str) and tcp_endpoint_re.match(event["subject"])
]
report = {
    "schema_version": "rift.outer-observer.v1",
    "producer": "interdimensional-rift-outer-observer",
    "artifact_tree_sha256": args.artifact_tree_sha256,
    "observer": {
        "engine": "strace",
        "trace_files": len(trace_files),
        "status": "active" if trace_files else "missing",
        "scope": "rift-host-process-tree" if root_pids else "all-traced-processes-no-rift-root",
        "rift_host_pids": sorted(root_pids),
        "observed_process_pids": len(selected_pids),
        "trusted_loopback_probe_pids": sorted(probe_pids),
    },
    "events": ordered,
    "dynamic_loopback_probe": {
        "schema_version": "rift.dynamic-loopback-probe.v1",
        "status": "active" if probe_pids else "not_observed",
        "network_scope": "sandbox-loopback-only",
        "protocol": "tcp",
        "payload": "none",
        "listener_events": listener_events,
        "tcp_listener_bind_events": tcp_listener_bind_events,
        "connection_attempts": probe_connections,
    },
    "diagnostics": {
        "schema_version": "rift.outer-observer-diagnostics.v1",
        "per_process_tail": diagnostic_tail,
    },
    "summary": {
        "event_count": sum(summary.values()),
        "by_kind": summary,
        "by_origin": {origin: sum(event["count"] for event in ordered if event["origin"] == origin) for origin in ("plugin", "trusted-loopback-probe")},
    },
}
args.out.parent.mkdir(parents=True, exist_ok=True)
args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

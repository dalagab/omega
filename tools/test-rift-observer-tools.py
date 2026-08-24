#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
collector = root / "tools/collect-rift-observer.py"
validator = root / "tools/validate-rift-observer.py"

with tempfile.TemporaryDirectory() as raw:
    directory = Path(raw)
    trace_dir = directory / "trace"
    trace_dir.mkdir()
    (trace_dir / "trace.123").write_text(
        'execve("/rift-tools/rift-loopback-probe", ["/rift-tools/rift-loopback-probe", "--"], 0x1) = 0\n'
        'clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD, stack=NULL, stack_size=0}, 88) = 124\n'
        'execve("/rift/interdimensional-rift", ["/rift/interdimensional-rift"], 0x1) = 0\n'
        'openat(AT_FDCWD, "/input/Plugin.dll", O_RDONLY) = 3\n'
        'bind(5, {sa_family=AF_INET, sin_port=htons(43123), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
        'listen(5, 512) = 0\n'
        'accept4(5, NULL, NULL, SOCK_CLOEXEC) = 6\n'
        'connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.8")}, 16) = -1 ENETUNREACH (Network is unreachable)\n'
        'execve("/input/helper.bin", ["helper.bin"], 0x1) = -1 EACCES (Permission denied)\n',
        encoding="utf-8",
    )
    (trace_dir / "trace.124").write_text(
        'execve("/rift-tools/rift-loopback-probe", ["/rift-tools/rift-loopback-probe", "--probe-worker"], 0x1) = 0\n'
        'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3\n'
        'connect(3, {sa_family=AF_INET, sin_port=htons(43123), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n',
        encoding="utf-8",
    )
    output = directory / "observer.json"
    subprocess.run([sys.executable, str(collector), "--trace-dir", str(trace_dir), "--out", str(output), "--artifact-tree-sha256", "a" * 64], check=True)
    subprocess.run([sys.executable, str(validator), str(output), "--require-active"], check=True)
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"]["by_kind"] == {"filesystem": 1, "network": 6, "process": 3}
    assert any(event["subject"] == "203.0.113.8:443" and event["outcome"] == "failed" for event in data["events"])
    assert any(event["subject"] == "/input/helper.bin" and event["outcome"] == "blocked" for event in data["events"])
    assert data["dynamic_loopback_probe"]["status"] == "active"
    assert data["dynamic_loopback_probe"]["network_scope"] == "sandbox-loopback-only"
    assert any(event["operation"] == "bind" and event["subject"] == "127.0.0.1:43123" for event in data["dynamic_loopback_probe"]["listener_events"])
    assert data["dynamic_loopback_probe"]["tcp_listener_bind_events"][0]["subject"] == "127.0.0.1:43123"
    assert any(event["subject"] == "127.0.0.1:43123" and event["outcome"] == "succeeded" for event in data["dynamic_loopback_probe"]["connection_attempts"])
    assert any(tail["origin"] == "plugin" and tail["events"][-1]["operation"] == "execve" for tail in data["diagnostics"]["per_process_tail"])

print("Rift observer tool self-test: PASS")

#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile


root = Path(__file__).resolve().parents[1]
collector = root / "tools/collect-rift-runtime.py"
with tempfile.TemporaryDirectory() as raw:
    directory = Path(raw)
    report = directory / "report.json"
    observer = directory / "observer.json"
    report.write_text(json.dumps({
        "schema_version": "rift.runtime-observation.v2",
        "plugin": {"internal_name": "Fixture", "assembly_name": "Fixture", "load_outcome": "ok"},
        "execution": {"artifact_tree_sha256": "a" * 64, "entry_sha256": "b" * 64, "network": "isolated", "seccomp": "enforced"},
        "observations": [{"kind": "network", "operation": "connect"}],
        "exercise": {"schema_version": "rift.exercise.v1"},
    }), encoding="utf-8")
    observer.write_text(json.dumps({"schema_version": "rift.outer-observer.v1"}), encoding="utf-8")
    output = directory / "omega-rift-runtime.json"
    subprocess.run([sys.executable, str(collector), "--report", str(report), "--observer", str(observer), "--out", str(output)], check=True)
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["collector"] == "omega.collector.rift.runtime"
    assert data["execution"]["runtime_reported"] is True
    assert data["outer_observer"]["schema_version"] == "rift.outer-observer.v1"

print("Rift runtime collector self-test: PASS")

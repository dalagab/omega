#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
scanner = root / "tools/scan-rift-components.py"
with tempfile.TemporaryDirectory() as raw:
    directory = Path(raw)
    artifact = directory / "artifact"
    artifact.mkdir()
    (artifact / "Probe.dll").write_bytes(b"MZ....BSJB....Assembly.Load....Process.Start")
    output = directory / "report.json"
    subprocess.run([sys.executable, str(scanner), "--artifact-dir", str(artifact), "--out", str(output)], check=True)
    report = json.loads(output.read_text())
    assert report["schema"] == "omega.rift.component-security.v1"
    component = report["components"][0]
    assert component["kind"] == "managed-pe"
    assert set(component["static_signals"]) == {"managed.dynamic-load", "process.execution"}
    record = report["records"][0]
    assert record["component"] == "Probe.dll"
    assert record["status"] == "observed"
    assert set(record["staticSignals"]) == {"managed.dynamic-load", "process.execution"}
print("Rift component scanner self-test: PASS")

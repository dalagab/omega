#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
names = ["RiftMemoryPressure", "RiftTaskPressure", "RiftTmpfsPressure", "RiftHangTree"]

errors = []
for name in names:
    fixture = root / "tests/fixtures" / name
    source = fixture / "Plugin.cs"
    if not source.is_file():
        errors.append(f"{name}: Plugin.cs missing")
        continue
    if any(p for p in fixture.rglob("*.json") if not {"bin", "obj"} & set(p.relative_to(fixture).parts)):
        errors.append(f"{name}: authored JSON is forbidden")
    text = source.read_text(encoding="utf-8")
    for required in ("RIFT_EXECUTOR", "bubblewrap-v2", "RIFT_STRESS"):
        if required not in text:
            errors.append(f"{name}: missing {required}")
    for forbidden in ("https://", "http://", "GITHUB_TOKEN", "ACTIONS_ID_TOKEN", "/home/runner", "/github/workspace"):
        if forbidden in text:
            errors.append(f"{name}: forbidden external/runner material {forbidden}")

expected = {
    "RiftMemoryPressure": "stress.memory_pressure",
    "RiftTaskPressure": "stress.task_pressure",
    "RiftTmpfsPressure": "stress.tmpfs_pressure",
    "RiftHangTree": "stress.hangtree",
}
for name, marker in expected.items():
    text = (root / "tests/fixtures" / name / "Plugin.cs").read_text(encoding="utf-8")
    if marker not in text:
        errors.append(f"{name}: missing marker {marker}")

helper = root / "tests/fixtures/RiftHangTree/rift-hang-child.c"
if "SIG_IGN" not in helper.read_text(encoding="utf-8"):
    errors.append("RiftHangTree helper must ignore SIGTERM so SIGKILL cleanup is exercised")

if errors:
    for e in errors:
        print("FAIL:", e, file=sys.stderr)
    raise SystemExit(1)

print("Rift containment stress fixture contract: PASS")
print("- all fixtures inert outside Rift")
print("- no authored JSON/install manifests")
print("- no routable network or runner-secret targets")
print("- memory, tasks, tmpfs, and stubborn-child scenarios present")

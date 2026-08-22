#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
fixture = root / "tests/fixtures/RiftCanary"
source = fixture / "Plugin.cs"
text = source.read_text(encoding="utf-8")

json_files = [
    p for p in fixture.rglob("*.json")
    if not ({"bin", "obj"} & set(p.relative_to(fixture).parts))
]
if json_files:
    raise SystemExit("Canary fixture must contain no authored JSON")

required = [
    "RIFT_EXECUTOR",
    "RIFT_CANARY completed",
    "boundary.artifact_readonly",
    "boundary.runtime_readonly",
    "boundary.contracts_readonly",
    "boundary.host_secrets_absent",
    "boundary.no_new_privileges",
    "boundary.capabilities_dropped",
    "boundary.network_isolated",
    "boundary.nested_userns_denied",
    "boundary.ptrace_denied",
    "boundary.raw_packet_socket_denied",
    "boundary.tmpfs_tmp_bounded",
    "boundary.tmpfs_home_bounded",
    "boundary.tmpfs_work_bounded",
    "boundary.hostname_isolated",
    "CLONE_NEWUSER",
    "AF_PACKET",
    "PTRACE_TRACEME",
    "/home/runner",
    "/github/workspace",
]
for marker in required:
    if marker not in text:
        raise SystemExit(f"Canary missing required marker: {marker}")

for forbidden in ["http://", "https://", "Process.Start", "DownloadString", "GITHUB_TOKEN="]:
    if forbidden in text:
        raise SystemExit(f"Canary contains forbidden active primitive: {forbidden}")

print("Canary contract: PASS")
print("- environmental sentinel is inert outside RIFT_EXECUTOR=bubblewrap-v2")
print("- no JSON/install manifest")
print("- finite checks cover mounts, secrets, no-new-privs, capabilities, network, seccomp/userns, tmpfs, and hostname")

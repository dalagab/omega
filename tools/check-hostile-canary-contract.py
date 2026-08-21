#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "RiftHostileCanary"
SOURCE = FIXTURE / "Plugin.cs"

errors: list[str] = []

if not SOURCE.is_file():
    errors.append(f"missing canary source: {SOURCE}")
    text = ""
else:
    text = SOURCE.read_text(encoding="utf-8")

# This fixture is deliberately not a discoverable/installable Dalamud package.
json_files = sorted(FIXTURE.rglob("*.json"))
if json_files:
    errors.append("hostile canary fixture must contain zero .json files: " + ", ".join(str(p.relative_to(ROOT)) for p in json_files))

for forbidden in (
    "DalamudApiLevel",
    "DownloadLinkInstall",
    "DownloadLinkUpdate",
    "InternalName",
    "RepoUrl",
    "Punchline",
):
    if forbidden in text:
        errors.append(f"canary source must not embed Dalamud manifest/feed key {forbidden!r}")

required_markers = (
    "HttpClient",
    "TcpClient",
    "Process.Start",
    "powershell.exe",
    "-EncodedCommand",
    "CredRead",
    "ProtectedData.Unprotect",
    "discord.com/api/webhooks/",
    "OpenProcess",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "Add-MpPreference",
    "DisableRealtimeMonitoring",
    "TVqQAAMAAAAEAAAA",
    "AmsiScanBuffer",
    "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
    "schtasks.exe",
    "OpenSCManager",
    "IsDebuggerPresent",
    "VBoxGuest",
)
for marker in required_markers:
    if marker not in text:
        errors.append(f"missing reviewed alarm marker: {marker}")

required_safety = (
    'Environment.GetEnvironmentVariable("RIFT_EXECUTOR")',
    '"bubblewrap-v2"',
    'IPAddress.Loopback, 9',
    '"/tmp/rift-hostile-canary"',
    '"/rift/RIFT_CANARY_DOES_NOT_EXIST"',
    'writable: false',
    'DllImport("libc", EntryPoint = "getpid")',
)
for marker in required_safety:
    if marker not in text:
        errors.append(f"missing canary safety invariant: {marker}")

# Hard guard: no obviously real credential path or routable exfil target may be added.
for pattern, label in (
    (r"https?://(?!127\.0\.0\.1|localhost)[A-Za-z0-9.-]+", "routable URL"),
    (r"(?:/home/runner|/root/|\.ssh|GITHUB_TOKEN|ACTIONS_ID_TOKEN)", "runner/credential material"),
):
    hits = re.findall(pattern, text, flags=re.IGNORECASE)
    if hits:
        errors.append(f"canary contains forbidden {label}: {hits[:3]}")

if errors:
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    raise SystemExit(1)

print("Hostile canary contract: PASS")
print("- no JSON / Dalamud manifest")
print("- reviewed alarm vocabulary present")
print("- active probes restricted to Rift-local harmless sentinels")

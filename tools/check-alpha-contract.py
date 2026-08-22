#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/RiftAlpha"
SOURCE = FIXTURE / "Plugin.cs"
errors: list[str] = []

if not SOURCE.is_file():
    errors.append(f"missing Alpha source: {SOURCE}")
    text = ""
else:
    text = SOURCE.read_text(encoding="utf-8")

json_files = sorted(
    p for p in FIXTURE.rglob("*.json")
    if not ({"bin", "obj"} & set(p.relative_to(FIXTURE).parts))
)
if json_files:
    errors.append("Alpha source fixture must contain zero authored .json files: " +
                  ", ".join(str(p.relative_to(ROOT)) for p in json_files))

for forbidden in ("DalamudApiLevel", "DownloadLinkInstall", "DownloadLinkUpdate", "InternalName", "RepoUrl", "Punchline"):
    if forbidden in text:
        errors.append(f"Alpha must not embed Dalamud manifest/feed key {forbidden!r}")

for marker in (
    "HttpClient", "TcpClient", "Process.Start", "powershell.exe", "-EncodedCommand",
    "CredRead", "ProtectedData.Unprotect", "discord.com/api/webhooks/",
    "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "Add-MpPreference", "DisableRealtimeMonitoring",
    "TVqQAAMAAAAEAAAA", "AmsiScanBuffer",
    "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
    "schtasks.exe", "OpenSCManager", "IsDebuggerPresent", "VBoxGuest",
):
    if marker not in text:
        errors.append(f"missing reviewed Alpha alarm marker: {marker}")

for marker in (
    'Environment.GetEnvironmentVariable("RIFT_EXECUTOR")',
    '"bubblewrap-v2"',
    'IPAddress.Loopback, 9',
    '"/tmp/rift-alpha"',
    '"/rift/RIFT_ALPHA_DOES_NOT_EXIST"',
    '"http://127.0.0.1:9/rift-alpha"',
    'writable: false',
    'DllImport("libc", EntryPoint = "getpid")',
    'RIFT_ALPHA armed inside Rift',
):
    if marker not in text:
        errors.append(f"missing Alpha safety invariant: {marker}")

for pattern, label in (
    (r"https?://(?!127\.0\.0\.1|localhost)[A-Za-z0-9.-]+", "routable URL"),
    (r"(?:/home/runner|/root/|\.ssh|GITHUB_TOKEN|ACTIONS_ID_TOKEN)", "runner/credential material"),
):
    hits = re.findall(pattern, text, flags=re.IGNORECASE)
    if hits:
        errors.append(f"Alpha contains forbidden {label}: {hits[:3]}")

if errors:
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    raise SystemExit(1)

print("Alpha contract: PASS")
print("- DLL-only/non-installable fixture; no authored JSON manifest")
print("- reviewed suspicious static vocabulary present")
print("- active probes are harmless and Rift-local")

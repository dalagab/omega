#!/usr/bin/env python3
from __future__ import annotations
import re, sys
from pathlib import Path
from alpha_registry import load

ROOT=Path(__file__).resolve().parents[1]
REG=ROOT/"registry/registry.json"
FORBIDDEN_KEYS=("DalamudApiLevel","DownloadLinkInstall","DownloadLinkUpdate","RepoUrl","Punchline")
ROUTABLE_URL=re.compile(r"https?://(?!127\.0\.0\.1(?::\d+)?(?:/|$)|localhost(?::\d+)?(?:/|$))[A-Za-z0-9.-]+",re.I)
RUNNER_MATERIAL=re.compile(r"(?:/home/runner|/root/|\.ssh|GITHUB_TOKEN|ACTIONS_ID_TOKEN)",re.I)

def main()->int:
    doc=load(REG); errors=[]
    for row in doc["entries"]:
        project=(ROOT/row["projectPath"]).resolve(); folder=project.parent
        if ROOT not in project.parents: errors.append(f"{row['id']}: project escaped corpus"); continue
        authored_json=[p for p in folder.rglob("*.json") if not ({"bin","obj"}&set(p.relative_to(folder).parts)) and p.name!="alpha.json"]
        if authored_json: errors.append(f"{row['id']}: only alpha.json metadata is permitted in a fixture folder")
        text="\n".join(p.read_text(encoding="utf-8",errors="replace") for p in folder.rglob("*.cs") if not ({"bin","obj"}&set(p.relative_to(folder).parts)))
        for key in FORBIDDEN_KEYS:
            if key in text: errors.append(f"{row['id']}: manifest/feed key {key} is forbidden")
        if ROUTABLE_URL.search(text): errors.append(f"{row['id']}: routable URL found")
        if RUNNER_MATERIAL.search(text): errors.append(f"{row['id']}: runner/credential material found")
        project_text=project.read_text(encoding="utf-8",errors="replace")
        if row["mode"]=="static-only":
            for active in ("new HttpClient(","new TcpClient(","Process.Start(","File.WriteAll", "Registry.CurrentUser.CreateSubKey"):
                if active in text: errors.append(f"{row['id']}: static-only fixture contains active call {active}")
        else:
            if "Omega.Alpha.Sdk" not in project_text: errors.append(f"{row['id']}: runtime fixture must use Omega.Alpha.Sdk")
            if "IAlphaScenario" not in text: errors.append(f"{row['id']}: runtime fixture must implement IAlphaScenario")
            if "Dalamud" in project_text or "Dalamud" in text: errors.append(f"{row['id']}: runtime Alpha may not reference Dalamud")
    sdk=(ROOT/"sdk/Omega.Alpha.Sdk/AlphaSafeProbes.cs").read_text(encoding="utf-8")
    contracts=(ROOT/"sdk/Omega.Alpha.Sdk/AlphaContracts.cs").read_text(encoding="utf-8")
    for required in ('"/tmp/omega-alpha"','IPAddress.Loopback, 9','"http://127.0.0.1:9/omega-alpha"','"/rift/OMEGA_ALPHA_DOES_NOT_EXIST"','writable: false','DllImport("libc", EntryPoint = "getpid")'):
        if required not in sdk: errors.append(f"SDK missing safety invariant {required}")
    for required in ('interface IAlphaScenario','RIFT_ALPHA_EXECUTOR','rift-alpha-bubblewrap-v1'):
        if required not in contracts: errors.append(f"SDK missing runtime contract {required}")
    if ROUTABLE_URL.search(sdk): errors.append("SDK contains a routable URL")
    if errors:
        for e in errors: print("FAIL:",e,file=sys.stderr)
        return 1
    print(f"Alpha source contract: PASS ({len(doc['entries'])} registered tests)")
    return 0
if __name__=="__main__": raise SystemExit(main())

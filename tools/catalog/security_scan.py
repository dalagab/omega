#!/usr/bin/env python3
"""Incrementally enrich an Omega catalog with static plugin security intelligence.

The scanner treats plugin packages and source archives as hostile input. It never
executes plugin code, never loads managed assemblies, and never extracts plugin
archives into the runner workspace. Results are evidence-based capabilities and
risk indicators, not a claim that a plugin is safe or malicious.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import PurePosixPath, Path
from typing import Iterable

SCANNER_VERSION = "1.0.0"
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 1024
MAX_ARCHIVE_UNCOMPRESSED = 256 * 1024 * 1024
MAX_ENTRY_SCAN_BYTES = 16 * 1024 * 1024
MAX_TEXT_SOURCE_BYTES = 1024 * 1024
MAX_SOURCE_TEXT_TOTAL = 24 * 1024 * 1024
USER_AGENT = f"Omega-Security-Scanner/{SCANNER_VERSION}"
SEVERITY_RANK = {"none": 0, "informational": 1, "caution": 2, "high": 3, "critical": 4}


@dataclasses.dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    category: str
    title: str
    description: str
    capability: str
    patterns: tuple[str, ...]


RULES = (
    Rule("network.http", "informational", "network", "Network access", "References HTTP/network client APIs.", "Network access", ("System.Net.Http.HttpClient", "WebRequest", "HttpWebRequest", "DownloadString", "DownloadData", "DownloadFile")),
    Rule("network.socket", "caution", "network", "Raw socket access", "References TCP/UDP/socket APIs that can open arbitrary network connections.", "Raw sockets", ("System.Net.Sockets", "TcpClient", "UdpClient", "Socket.Connect", "SocketAsyncEventArgs")),
    Rule("filesystem.write", "informational", "filesystem", "Filesystem write access", "References APIs commonly used to create, modify, move, or delete files.", "Filesystem write", ("WriteAllText", "WriteAllBytes", "FileStream", "FileMode.Create", "File.Delete", "File.Move", "Directory.CreateDirectory", "Directory.Delete")),
    Rule("process.launch", "caution", "process", "Process execution", "References APIs that can launch external programs or shell commands.", "Process execution", ("System.Diagnostics.Process", "Process.Start", "ProcessStartInfo", "CreateProcess", "ShellExecute")),
    Rule("shell.powershell", "high", "process", "Shell or PowerShell invocation", "Contains indicators for invoking command shells or PowerShell.", "Shell/PowerShell", ("powershell.exe", "pwsh.exe", "cmd.exe", "-EncodedCommand", "System.Management.Automation")),
    Rule("registry.access", "caution", "system", "Windows Registry access", "References Windows Registry APIs.", "Registry access", ("Microsoft.Win32.Registry", "RegistryKey", "RegOpenKey", "RegSetValue")),
    Rule("native.pinvoke", "caution", "native", "Unmanaged/native API access", "References P/Invoke or dynamic native library loading.", "Native/PInvoke", ("DllImportAttribute", "System.Runtime.InteropServices.DllImport", "NativeLibrary.Load", "LoadLibrary", "GetProcAddress")),
    Rule("dynamic.assembly", "caution", "dynamic-code", "Dynamic assembly loading", "References APIs that can load code dynamically at runtime.", "Dynamic code loading", ("Assembly.Load", "Assembly.LoadFrom", "Assembly.LoadFile", "AssemblyLoadContext", "Reflection.Emit")),
    Rule("memory.process", "high", "memory", "Cross-process memory access", "References APIs used to open another process or read/write its memory.", "Process memory access", ("OpenProcess", "ReadProcessMemory", "WriteProcessMemory", "VirtualAllocEx", "VirtualProtectEx")),
    Rule("memory.remote-thread", "high", "memory", "Remote thread creation", "References APIs commonly used to start execution in another process.", "Remote thread creation", ("CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC")),
    Rule("game.hooking", "caution", "game-memory", "Game memory/signature hooking", "References Dalamud/game hooking or signature-scanning facilities that can alter behavior inside the game process.", "Game memory/hooks", ("Dalamud.Hooking", "SignatureScanner", "SigScanner", "Hook<", "HookFromAddress", "CreateHook")),
    Rule("local.listener", "caution", "network", "Local server/listener", "References APIs that can listen for inbound local/network connections.", "Local server/listener", ("HttpListener", "TcpListener", "Kestrel", "WebApplication.CreateBuilder")),
    Rule("clipboard", "informational", "privacy", "Clipboard access", "References APIs that can read or modify clipboard contents.", "Clipboard access", ("System.Windows.Forms.Clipboard", "TextCopy.ClipboardService", "SDL_GetClipboardText", "SDL_SetClipboardText")),
    Rule("credential.api", "high", "privacy", "Credential or protected-data access", "References credential-manager, protected-data, or password-vault APIs. This is capability evidence, not proof of credential collection.", "Credential/protected-data access", ("CredentialManager", "PasswordVault", "Windows.Security.Credentials", "ProtectedData.Unprotect", "CryptUnprotectData", "CredRead")),
)

SOURCE_SUFFIXES = {".cs", ".csproj", ".props", ".targets", ".json", ".yml", ".yaml", ".ps1", ".cmd", ".bat"}
BINARY_SUFFIXES = {".dll", ".exe", ".so", ".dylib"}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return not path.is_absolute() and ".." not in path.parts and not re.match(r"^[A-Za-z]:", normalized)


def validate_public_https_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS downloads are scanned")
    host = (parsed.hostname or "").strip().lower()
    if not host or host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("Artifact URL must use a public Internet host")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ValueError(f"Artifact host could not be resolved: {host}") from exc
    if not addresses:
        raise ValueError(f"Artifact host could not be resolved: {host}")
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError(f"Artifact URL resolves to a non-public address: {address}")
    return parsed


def request_bytes(url: str, max_bytes: int, token: str = "") -> tuple[bytes, str]:
    parsed = validate_public_https_url(url)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/octet-stream"}
    if token and parsed.hostname and parsed.hostname.lower() in {"api.github.com", "github.com"}:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        validate_public_https_url(response.geturl())
        length = response.headers.get("Content-Length")
        if length and int(length) > max_bytes:
            raise ValueError(f"Download exceeds {max_bytes} byte limit")
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"Download exceeds {max_bytes} byte limit")
        return data, response.geturl()


def decoded_views(data: bytes) -> str:
    chunks: list[str] = []
    ascii_strings = re.findall(rb"[\x20-\x7e]{5,}", data)
    chunks.extend(x.decode("ascii", "ignore") for x in ascii_strings)
    utf16_strings = re.findall(rb"(?:[\x20-\x7e]\x00){5,}", data)
    chunks.extend(x.decode("utf-16le", "ignore") for x in utf16_strings)
    return "\n".join(chunks)


def add_rule_hits(text: str, evidence_label: str, hits: dict[str, list[str]]) -> None:
    lowered = text.lower()
    for rule in RULES:
        matched = [p for p in rule.patterns if p.lower() in lowered]
        if not matched:
            continue
        existing = hits[rule.rule_id]
        for pattern in matched[:3]:
            evidence = f"{evidence_label}: {pattern}"
            if evidence not in existing and len(existing) < 8:
                existing.append(evidence)


def scan_archive(data: bytes, hits: dict[str, list[str]]) -> dict:
    metadata = {"archive": False, "files": 1, "uncompressedBytes": len(data), "bundledExecutables": [], "bundledNativeLibraries": []}
    if not data.startswith(b"PK"):
        add_rule_hits(decoded_views(data[:MAX_ENTRY_SCAN_BYTES]), "artifact", hits)
        if data.startswith(b"MZ"):
            metadata["bundledExecutables"].append("artifact")
        return metadata

    metadata["archive"] = True
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ValueError(f"Archive has {len(infos)} entries; limit is {MAX_ARCHIVE_ENTRIES}")
        total = sum(max(0, info.file_size) for info in infos)
        if total > MAX_ARCHIVE_UNCOMPRESSED:
            raise ValueError("Archive exceeds uncompressed size limit")
        metadata["files"] = len(infos)
        metadata["uncompressedBytes"] = total
        for info in infos:
            if not safe_member_name(info.filename):
                raise ValueError(f"Unsafe archive path: {info.filename}")
            if info.file_size <= 0 or info.is_dir():
                continue
            if info.compress_size > 0 and info.file_size / info.compress_size > 500:
                raise ValueError(f"Suspicious compression ratio: {info.filename}")
            suffix = Path(info.filename).suffix.lower()
            if suffix not in BINARY_SUFFIXES | SOURCE_SUFFIXES:
                continue
            with archive.open(info) as stream:
                sample = stream.read(min(info.file_size, MAX_ENTRY_SCAN_BYTES))
            if suffix == ".exe":
                metadata["bundledExecutables"].append(info.filename)
            elif suffix in {".so", ".dylib"} or (suffix == ".dll" and b"BSJB" not in sample and not info.filename.lower().endswith(".resources.dll")):
                metadata["bundledNativeLibraries"].append(info.filename)
            if suffix in SOURCE_SUFFIXES:
                text = sample.decode("utf-8", "ignore")
            else:
                text = decoded_views(sample)
            add_rule_hits(text, f"artifact:{info.filename}", hits)
    return metadata


def github_repo_parts(url: str) -> tuple[str, str] | None:
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return None
    if parsed.hostname not in {"github.com", "www.github.com"}:
        return None
    parts = [x for x in parsed.path.split("/") if x]
    if len(parts) < 2:
        return None
    repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    return parts[0], repo


def fetch_source(repo_url: str, token: str, hits: dict[str, list[str]]) -> dict:
    parts = github_repo_parts(repo_url)
    if parts is None:
        return {"available": False, "repository": repo_url, "commit": "", "filesScanned": 0, "error": "No supported GitHub repository URL"}
    owner, repo = parts
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(api_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            meta = json.load(response)
        branch = str(meta.get("default_branch") or "main")
        commit_req = urllib.request.Request(f"{api_url}/commits/{urllib.parse.quote(branch)}", headers=headers)
        with urllib.request.urlopen(commit_req, timeout=20) as response:
            commit = json.load(response)
        sha = str(commit.get("sha") or "")
        archive_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{sha or branch}"
        source_bytes, _ = request_bytes(archive_url, MAX_SOURCE_BYTES, token)
        files_scanned = 0
        total_text = 0
        with zipfile.ZipFile(io.BytesIO(source_bytes)) as archive:
            for info in archive.infolist():
                if files_scanned >= 500 or total_text >= MAX_SOURCE_TEXT_TOTAL:
                    break
                if info.is_dir() or not safe_member_name(info.filename):
                    continue
                suffix = Path(info.filename).suffix.lower()
                if suffix not in SOURCE_SUFFIXES or info.file_size <= 0 or info.file_size > MAX_TEXT_SOURCE_BYTES:
                    continue
                with archive.open(info) as stream:
                    raw = stream.read(MAX_TEXT_SOURCE_BYTES)
                text = raw.decode("utf-8", "ignore")
                add_rule_hits(text, f"source:{info.filename}", hits)
                files_scanned += 1
                total_text += len(raw)
        return {"available": True, "repository": f"https://github.com/{owner}/{repo}", "commit": sha, "filesScanned": files_scanned, "error": ""}
    except Exception as exc:
        return {"available": False, "repository": repo_url, "commit": "", "filesScanned": 0, "error": str(exc)[:500]}


def finding_payload(hits: dict[str, list[str]], archive_meta: dict) -> tuple[list[dict], list[str]]:
    by_id = {r.rule_id: r for r in RULES}
    findings: list[dict] = []
    capabilities: set[str] = set()
    for rule_id, evidence in hits.items():
        rule = by_id[rule_id]
        capabilities.add(rule.capability)
        findings.append({
            "ruleId": rule.rule_id,
            "severity": rule.severity,
            "category": rule.category,
            "title": rule.title,
            "description": rule.description,
            "evidence": evidence,
        })

    if archive_meta.get("bundledExecutables"):
        capabilities.add("Bundled executable")
        findings.append({"ruleId": "package.executable", "severity": "caution", "category": "package", "title": "Bundled executable", "description": "The plugin package contains one or more executable files.", "evidence": archive_meta["bundledExecutables"][:8]})
    native = archive_meta.get("bundledNativeLibraries") or []
    if native:
        capabilities.add("Bundled native libraries")
        findings.append({"ruleId": "package.native-library", "severity": "informational", "category": "package", "title": "Bundled native libraries", "description": "The plugin package contains native-library payloads in addition to managed plugin files.", "evidence": native[:8]})

    rule_ids = {f["ruleId"] for f in findings}
    if "network.http" in rule_ids and ("process.launch" in rule_ids or "shell.powershell" in rule_ids):
        capabilities.add("Download/execute potential")
        findings.append({"ruleId": "compound.network-execute", "severity": "high", "category": "compound", "title": "Network plus process execution", "description": "The artifact references both network access and process/shell execution. This combination can download and execute external content; manual review is recommended.", "evidence": []})
    if "credential.api" in rule_ids and ("network.http" in rule_ids or "network.socket" in rule_ids):
        findings.append({"ruleId": "compound.credential-network", "severity": "high", "category": "compound", "title": "Credential APIs plus network access", "description": "The artifact references credential/protected-data APIs and network APIs. This is not proof of credential collection, but it warrants manual review.", "evidence": []})

    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f["ruleId"]))
    return findings, sorted(capabilities, key=str.lower)


def ensure_schema(db: sqlite3.Connection) -> None:
    db.executescript("""
    CREATE TABLE IF NOT EXISTS plugin_security_scans (
        scan_id INTEGER PRIMARY KEY,
        plugin_id INTEGER NOT NULL REFERENCES plugins(plugin_id) ON DELETE CASCADE,
        variant_id INTEGER NOT NULL REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
        source_id INTEGER NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
        assembly_version TEXT NOT NULL DEFAULT '',
        artifact_channel TEXT NOT NULL DEFAULT 'stable',
        artifact_url TEXT NOT NULL DEFAULT '',
        artifact_sha256 TEXT NOT NULL DEFAULT '',
        scanner_version TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT '',
        scanned_at_utc TEXT NOT NULL DEFAULT '',
        highest_severity TEXT NOT NULL DEFAULT 'none',
        informational_count INTEGER NOT NULL DEFAULT 0,
        caution_count INTEGER NOT NULL DEFAULT 0,
        high_count INTEGER NOT NULL DEFAULT 0,
        critical_count INTEGER NOT NULL DEFAULT 0,
        capabilities_json TEXT NOT NULL DEFAULT '[]',
        source_available INTEGER NOT NULL DEFAULT 0,
        source_repository TEXT NOT NULL DEFAULT '',
        source_commit TEXT NOT NULL DEFAULT '',
        source_to_binary_verified INTEGER NOT NULL DEFAULT 0,
        report_json TEXT NOT NULL DEFAULT '{}',
        error TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_security_scans_variant ON plugin_security_scans(variant_id, scanned_at_utc DESC);
    CREATE INDEX IF NOT EXISTS ix_security_scans_hash ON plugin_security_scans(artifact_sha256);

    CREATE TABLE IF NOT EXISTS plugin_security_findings (
        finding_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        rule_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS ix_security_findings_scan ON plugin_security_findings(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_findings_severity ON plugin_security_findings(severity);

    CREATE TABLE IF NOT EXISTS plugin_security_current (
        variant_id INTEGER PRIMARY KEY REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        assembly_version TEXT NOT NULL DEFAULT '',
        artifact_channel TEXT NOT NULL DEFAULT 'stable',
        artifact_url TEXT NOT NULL DEFAULT '',
        artifact_sha256 TEXT NOT NULL DEFAULT '',
        scanner_version TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT '',
        scanned_at_utc TEXT NOT NULL DEFAULT '',
        highest_severity TEXT NOT NULL DEFAULT 'none',
        informational_count INTEGER NOT NULL DEFAULT 0,
        caution_count INTEGER NOT NULL DEFAULT 0,
        high_count INTEGER NOT NULL DEFAULT 0,
        critical_count INTEGER NOT NULL DEFAULT 0,
        capabilities_json TEXT NOT NULL DEFAULT '[]',
        findings_json TEXT NOT NULL DEFAULT '[]',
        source_available INTEGER NOT NULL DEFAULT 0,
        source_repository TEXT NOT NULL DEFAULT '',
        source_commit TEXT NOT NULL DEFAULT '',
        source_to_binary_verified INTEGER NOT NULL DEFAULT 0,
        report_json TEXT NOT NULL DEFAULT '{}',
        error TEXT NOT NULL DEFAULT ''
    );
    """)


def recreate_runtime_view(db: sqlite3.Connection) -> None:
    # Keep the runtime projection owned by the authoritative catalog builder so
    # scanner and catalog workflows cannot drift into incompatible views.
    from build_sqlite_catalog import create_runtime_view
    create_runtime_view(db)


def choose_artifact(row: sqlite3.Row) -> tuple[str, str, str]:
    stable = str(row["download_link_install"] or "").strip()
    testing = str(row["download_link_testing"] or "").strip()
    if stable:
        return "stable", str(row["assembly_version"] or ""), stable
    return "testing", str(row["testing_assembly_version"] or row["assembly_version"] or ""), testing


def due_rows(db: sqlite3.Connection, max_scans: int, rescan_hours: int, names: set[str]) -> list[sqlite3.Row]:
    if max_scans <= 0:
        return []
    now = dt.datetime.now(dt.timezone.utc)
    rows = db.execute("""
        SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,v.author,v.assembly_version,
               v.testing_assembly_version,v.download_link_install,v.download_link_testing,v.repo_url,
               s.name AS source_name,sc.status AS current_status,sc.scanned_at_utc AS current_scanned_at_utc,
               sc.scanner_version AS current_scanner_version,sc.artifact_url AS current_artifact_url,
               sc.assembly_version AS current_assembly_version
          FROM plugin_variants v
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
          LEFT JOIN plugin_security_current sc ON sc.variant_id=v.variant_id
         WHERE v.active=1 AND p.active=1 AND (v.download_link_install<>'' OR v.download_link_testing<>'')
         ORDER BY CASE WHEN sc.scan_id IS NULL THEN 0 WHEN sc.status<>'complete' THEN 1 ELSE 2 END,
                  COALESCE(sc.scanned_at_utc,''), p.internal_name COLLATE NOCASE, s.name COLLATE NOCASE
    """).fetchall()
    result = []
    for row in rows:
        if names and str(row["internal_name"]).lower() not in names:
            continue
        _channel, version, url = choose_artifact(row)
        if not url:
            continue
        last = parse_utc(row["current_scanned_at_utc"])
        stale = last is None or (now - last).total_seconds() >= rescan_hours * 3600
        due = (
            row["current_status"] is None or
            str(row["current_status"]) != "complete" or
            str(row["current_scanner_version"] or "") != SCANNER_VERSION or
            str(row["current_artifact_url"] or "") != url or
            str(row["current_assembly_version"] or "") != version or
            stale
        )
        if due:
            result.append(row)
        if len(result) >= max_scans:
            break
    return result


def save_scan(db: sqlite3.Connection, row: sqlite3.Row, result: dict) -> int:
    counts = result["counts"]
    cur = db.execute("""
        INSERT INTO plugin_security_scans(
            plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,
            scanner_version,status,scanned_at_utc,highest_severity,informational_count,caution_count,high_count,
            critical_count,capabilities_json,source_available,source_repository,source_commit,source_to_binary_verified,
            report_json,error)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        row["plugin_id"], row["variant_id"], row["source_id"], result["assemblyVersion"], result["artifactChannel"],
        result["artifactUrl"], result["artifactSha256"], SCANNER_VERSION, result["status"], result["scannedAtUtc"],
        result["highestSeverity"], counts["informational"], counts["caution"], counts["high"], counts["critical"],
        json.dumps(result["capabilities"], separators=(",", ":")), int(result["source"]["available"]),
        result["source"]["repository"], result["source"]["commit"], 0, json.dumps(result, separators=(",", ":")),
        result.get("error", ""),
    ))
    scan_id = int(cur.lastrowid)
    for finding in result["findings"]:
        db.execute("""INSERT INTO plugin_security_findings(scan_id,rule_id,severity,category,title,description,evidence_json)
                      VALUES(?,?,?,?,?,?,?)""", (scan_id, finding["ruleId"], finding["severity"], finding["category"], finding["title"], finding["description"], json.dumps(finding["evidence"], separators=(",", ":"))))

    existing = db.execute("SELECT status FROM plugin_security_current WHERE variant_id=?", (row["variant_id"],)).fetchone()
    if result["status"] != "complete" and existing is not None and str(existing[0]) == "complete":
        # Preserve last-known-good intelligence when a periodic revalidation fails transiently.
        return scan_id

    db.execute("""
        INSERT INTO plugin_security_current(
            variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,
            scanned_at_utc,highest_severity,informational_count,caution_count,high_count,critical_count,capabilities_json,
            findings_json,source_available,source_repository,source_commit,source_to_binary_verified,report_json,error)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(variant_id) DO UPDATE SET
            scan_id=excluded.scan_id,assembly_version=excluded.assembly_version,artifact_channel=excluded.artifact_channel,
            artifact_url=excluded.artifact_url,artifact_sha256=excluded.artifact_sha256,scanner_version=excluded.scanner_version,
            status=excluded.status,scanned_at_utc=excluded.scanned_at_utc,highest_severity=excluded.highest_severity,
            informational_count=excluded.informational_count,caution_count=excluded.caution_count,high_count=excluded.high_count,
            critical_count=excluded.critical_count,capabilities_json=excluded.capabilities_json,findings_json=excluded.findings_json,
            source_available=excluded.source_available,source_repository=excluded.source_repository,source_commit=excluded.source_commit,
            source_to_binary_verified=excluded.source_to_binary_verified,report_json=excluded.report_json,error=excluded.error
    """, (
        row["variant_id"], scan_id, result["assemblyVersion"], result["artifactChannel"], result["artifactUrl"],
        result["artifactSha256"], SCANNER_VERSION, result["status"], result["scannedAtUtc"], result["highestSeverity"],
        counts["informational"], counts["caution"], counts["high"], counts["critical"],
        json.dumps(result["capabilities"], separators=(",", ":")), json.dumps(result["findings"], separators=(",", ":")),
        int(result["source"]["available"]), result["source"]["repository"], result["source"]["commit"], 0,
        json.dumps(result, separators=(",", ":")), result.get("error", ""),
    ))
    return scan_id


def scan_row(row: sqlite3.Row, token: str, scan_source: bool) -> dict:
    channel, version, url = choose_artifact(row)
    scanned_at = utc_now()
    base = {
        "schema": "omega.plugin-security.scan.v1",
        "scannerVersion": SCANNER_VERSION,
        "scannedAtUtc": scanned_at,
        "plugin": {"internalName": row["internal_name"], "name": row["name"], "author": row["author"], "sourceName": row["source_name"]},
        "assemblyVersion": version,
        "artifactChannel": channel,
        "artifactUrl": url,
        "artifactSha256": "",
        "status": "failed",
        "highestSeverity": "none",
        "counts": {"informational": 0, "caution": 0, "high": 0, "critical": 0},
        "capabilities": [],
        "findings": [],
        "source": {"available": False, "repository": str(row["repo_url"] or ""), "commit": "", "filesScanned": 0, "sourceToBinaryVerified": False, "error": ""},
        "package": {},
        "error": "",
    }
    try:
        artifact, final_url = request_bytes(url, MAX_ARTIFACT_BYTES)
        base["resolvedArtifactUrl"] = final_url
        base["artifactSha256"] = sha256_bytes(artifact)
        artifact_hits: dict[str, list[str]] = defaultdict(list)
        package_meta = scan_archive(artifact, artifact_hits)
        base["package"] = package_meta
        findings, capabilities = finding_payload(artifact_hits, package_meta)
        if scan_source and str(row["repo_url"] or ""):
            source_hits: dict[str, list[str]] = defaultdict(list)
            base["source"] = fetch_source(str(row["repo_url"]), token, source_hits)
            base["source"]["sourceToBinaryVerified"] = False
            source_findings, source_capabilities = finding_payload(source_hits, {})
            base["source"]["findings"] = source_findings
            base["source"]["capabilities"] = source_capabilities
        counts = {severity: sum(1 for f in findings if f["severity"] == severity) for severity in ("informational", "caution", "high", "critical")}
        highest = "none"
        for severity in ("critical", "high", "caution", "informational"):
            if counts[severity]:
                highest = severity
                break
        base.update({"status": "complete", "findings": findings, "capabilities": capabilities, "counts": counts, "highestSeverity": highest})
    except Exception as exc:
        base["error"] = str(exc)[:1000]
    return base


def update_descriptor(database_path: Path, bundle_path: Path, descriptor_path: Path) -> dict:
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.write(database_path, "omega-catalog.sqlite")
    catalog_sha = hashlib.sha256(database_path.read_bytes()).hexdigest()
    bundle_sha = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    descriptor["catalogSha256"] = catalog_sha
    descriptor["bundleSha256"] = bundle_sha
    descriptor["size"] = bundle_path.stat().st_size
    descriptor["databaseBytes"] = database_path.stat().st_size
    descriptor["securityGeneratedAtUtc"] = utc_now()
    descriptor_path.write_text(json.dumps(descriptor, indent=2) + "\n", encoding="utf-8")
    (bundle_path.parent / f"{bundle_path.name}.sha256").write_text(f"{bundle_sha}  {bundle_path.name}\n", encoding="ascii")
    return descriptor


def run(args: argparse.Namespace) -> dict:
    db_path = Path(args.database)
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    token = os.environ.get("GITHUB_TOKEN", "")
    names = {x.strip().lower() for x in args.internal_names.split(",") if x.strip()}
    summary = {"schema": "omega.plugin-security.batch.v1", "scannerVersion": SCANNER_VERSION, "startedAtUtc": utc_now(), "selected": 0, "completed": 0, "failed": 0, "plugins": []}
    try:
        ensure_schema(db)
        rows = due_rows(db, args.max_scans, args.rescan_after_hours, names)
        summary["selected"] = len(rows)
        for index, row in enumerate(rows, start=1):
            print(f"[{index}/{len(rows)}] scanning {row['internal_name']} from {row['source_name']}", flush=True)
            result = scan_row(row, token, not args.skip_source)
            save_scan(db, row, result)
            db.commit()
            summary["completed" if result["status"] == "complete" else "failed"] += 1
            summary["plugins"].append({"internalName": row["internal_name"], "sourceName": row["source_name"], "status": result["status"], "highestSeverity": result["highestSeverity"], "artifactSha256": result["artifactSha256"], "error": result["error"]})
        recreate_runtime_view(db)
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_scanner_version',?)", (SCANNER_VERSION,))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_scanned_at_utc',?)", (utc_now(),))
        db.commit()
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        if str(integrity).lower() != "ok":
            raise RuntimeError(f"SQLite integrity_check failed: {integrity}")
        summary["currentScanCount"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_current WHERE status='complete'").fetchone()[0])
        summary["currentHighOrCritical"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_current WHERE status='complete' AND highest_severity IN ('high','critical')").fetchone()[0])
    finally:
        db.close()
    summary["finishedAtUtc"] = utc_now()
    Path(args.report).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if args.bundle and args.descriptor:
        update_descriptor(db_path, Path(args.bundle), Path(args.descriptor))
    return summary


def self_test() -> None:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("TestPlugin.dll", b"MZ" + b"x" * 32 + b"System.Net.Http.HttpClient\x00System.Diagnostics.Process\x00DllImportAttribute\x00")
    hits: dict[str, list[str]] = defaultdict(list)
    meta = scan_archive(payload.getvalue(), hits)
    findings, capabilities = finding_payload(hits, meta)
    ids = {x["ruleId"] for x in findings}
    assert "network.http" in ids
    assert "process.launch" in ids
    assert "native.pinvoke" in ids
    assert "compound.network-execute" in ids
    assert "Network access" in capabilities
    try:
        bad = io.BytesIO()
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("../escape.dll", b"MZ")
        scan_archive(bad.getvalue(), defaultdict(list))
        raise AssertionError("path traversal was accepted")
    except ValueError:
        pass
    try:
        validate_public_https_url("https://localhost/plugin.zip")
        raise AssertionError("localhost SSRF target was accepted")
    except ValueError:
        pass
    print("Omega security scanner self-test passed.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Incrementally scan Omega plugin artifacts without executing them")
    parser.add_argument("--database", default="catalog/dist/omega-catalog.sqlite")
    parser.add_argument("--bundle", default="")
    parser.add_argument("--descriptor", default="")
    parser.add_argument("--report", default="catalog/security-report.json")
    parser.add_argument("--max-scans", type=int, default=60)
    parser.add_argument("--rescan-after-hours", type=int, default=168)
    parser.add_argument("--internal-names", default="")
    parser.add_argument("--skip-source", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    report = run(args)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

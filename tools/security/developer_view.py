#!/usr/bin/env python3
"""Omega Security Developer View.

Read-only developer tooling for inspecting the published Omega security evidence database.

Typical use:
    python tools/security/developer_view.py

That command opens the latest published Security Evidence v2 directly from GitHub. It
fetches only the root/plugin indexes initially and downloads individual variant/evidence
shards lazily as the operator opens them. A bounded local HTTP cache avoids repeat fetches.

Other useful modes:
    python tools/security/developer_view.py serve-online
    python tools/security/developer_view.py serve --evidence-v2 path/to/security-evidence-v2
    python tools/security/developer_view.py serve --database path/to/omega-security-evidence.sqlite
    python tools/security/developer_view.py audit --database path/to/omega-security-evidence.sqlite --json

Local SQLite databases are always opened read-only. The SQL console only accepts SELECT/PRAGMA/WITH/EXPLAIN.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import datetime as dt
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile
from typing import Any, Iterable

from evidence_v2_inspector import DEFAULT_ONLINE_BASE_URL, DEFAULT_REMOTE_CACHE_BYTES, V2SigmascopeInspector

REPOSITORY = "dalagab/omega"
EVIDENCE_TAG = "security-evidence-latest"
MARKETPLACE_TAG = "catalog-latest"
EVIDENCE_ASSET = "omega-security-evidence.sqlite.zip"
MARKETPLACE_ASSET = "omega-marketplace.sqlite.zip"
GITHUB_API = "https://api.github.com"
USER_AGENT = "Omega-Security-Developer-View/1.0"
DEFAULT_PORT = 8765
MAX_SQL_ROWS = 1000
MAX_TABLE_ROWS = 250
OSV_QUERY_LIMIT = 2_000
SEVERITY_RANK = {"none": 0, "informational": 1, "low": 1, "caution": 2, "moderate": 2, "medium": 2, "high": 3, "critical": 4}
RANK_SEVERITY = {0: "none", 1: "informational", 2: "caution", 3: "high", 4: "critical"}
ADVISORY_POINTS = {4: 40, 3: 25, 2: 12, 1: 5, 0: 8}
EXPECTED_EVIDENCE_TABLES = {
    "plugins", "plugin_variants", "sources", "plugin_security_scans", "plugin_security_current",
    "plugin_security_findings", "plugin_security_dependencies", "plugin_security_dependency_resolutions",
    "plugin_security_dependency_issues", "plugin_security_dependency_advisory_matches",
    "plugin_security_ipc_endpoints", "plugin_security_ipc_registry",
    "plugin_security_permission_candidates", "plugin_security_automation_capabilities",
    "plugin_security_source_artifact_comparisons", "plugin_security_scan_lineage",
    "plugin_security_dependency_drift",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_cache_dir() -> Path:
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "Omega" / "SecurityDeveloperView"
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "omega-security-developer-view"
    return Path.home() / ".cache" / "omega-security-developer-view"


def github_headers() -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def http_json(url: str) -> Any:
    req = urllib.request.Request(url, headers=github_headers())
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def release_asset(tag: str, asset_name: str) -> dict[str, Any]:
    release = http_json(f"{GITHUB_API}/repos/{REPOSITORY}/releases/tags/{urllib.parse.quote(tag)}")
    for asset in release.get("assets") or []:
        if str(asset.get("name") or "") == asset_name:
            return asset
    raise RuntimeError(f"Release {tag!r} does not contain {asset_name!r}")


def _progress(done: int, total: int, label: str, started: float) -> None:
    if total > 0:
        pct = min(100.0, done * 100.0 / total)
        width = 24
        filled = int(width * pct / 100.0)
        bar = "#" * filled + "-" * (width - filled)
        rate = done / max(0.1, time.monotonic() - started)
        print(f"\r{label}: [{bar}] {pct:5.1f}%  {done/1024/1024:,.1f}/{total/1024/1024:,.1f} MiB  {rate/1024/1024:,.1f} MiB/s", end="", file=sys.stderr, flush=True)
    else:
        print(f"\r{label}: {done/1024/1024:,.1f} MiB", end="", file=sys.stderr, flush=True)


def download_file(url: str, destination: Path, expected_size: int = 0, label: str = "download") -> Path:
    """Download a large release asset with resumable .part support.

    GitHub release assets are large enough that a transient connection failure should not
    force a complete restart. A partial file is kept on failure and resumed with HTTP Range
    when the server supports it.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_suffix(destination.suffix + ".part")
    resume_at = part.stat().st_size if part.exists() else 0
    headers = {**github_headers(), "Accept": "application/octet-stream"}
    if resume_at > 0:
        headers["Range"] = f"bytes={resume_at}-"
    req = urllib.request.Request(url, headers=headers)
    started = time.monotonic()
    with urllib.request.urlopen(req, timeout=60) as response:
        status_value = getattr(response, "status", None)
        status = int(status_value if status_value is not None else response.getcode() or 200)
        append = resume_at > 0 and status == 206
        if append:
            content_range = str(response.headers.get("Content-Range") or "")
            match = re.match(r"bytes\s+(\d+)-\d+/(\d+|\*)", content_range, re.I)
            if not match or int(match.group(1)) != resume_at:
                raise RuntimeError(f"Server returned an invalid resume range for {label}: {content_range or 'missing Content-Range'}")
            total = expected_size or (int(match.group(2)) if match.group(2).isdigit() else 0)
            mode = "ab"
            done = resume_at
            print(f"Resuming {label} at {resume_at/1024/1024:,.1f} MiB", file=sys.stderr)
        else:
            # Server ignored Range (common behind redirects/CDNs): restart safely.
            mode = "wb"
            done = 0
            total = expected_size or int(response.headers.get("Content-Length") or 0)
        with part.open(mode) as out:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                done += len(chunk)
                if done == len(chunk) or done % (8 * 1024 * 1024) < len(chunk):
                    _progress(done, total, label, started)
    print(file=sys.stderr)
    actual_size = part.stat().st_size
    if expected_size and actual_size != expected_size:
        # Keep a short partial file so a later invocation can resume it. An oversized file
        # cannot be resumed correctly and is discarded.
        if actual_size > expected_size:
            part.unlink(missing_ok=True)
        raise RuntimeError(f"Incomplete download for {label}: expected {expected_size} bytes, got {actual_size}")
    part.replace(destination)
    return destination


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_sidecar(text: str) -> str:
    match = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    if not match:
        raise RuntimeError("SHA-256 sidecar does not contain a 64-character digest")
    return match.group(1).lower()


def download_text(url: str) -> str:
    req = urllib.request.Request(url, headers=github_headers())
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read(1024 * 1024).decode("utf-8", "replace")


def safe_extract_sqlite(bundle: Path, destination_dir: Path) -> Path:
    destination_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(bundle) as archive:
        candidates = []
        for info in archive.infolist():
            if info.is_dir():
                continue
            pure = PurePosixPath(info.filename)
            if pure.is_absolute() or ".." in pure.parts:
                raise RuntimeError(f"Unsafe ZIP member {info.filename!r}")
            if pure.suffix.lower() in {".sqlite", ".db"}:
                candidates.append(info)
        if len(candidates) != 1:
            raise RuntimeError(f"Expected exactly one SQLite database in {bundle.name}; found {len(candidates)}")
        info = candidates[0]
        output = destination_dir / Path(info.filename).name
        temp = output.with_suffix(output.suffix + ".part")
        with archive.open(info) as source, temp.open("wb") as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
        temp.replace(output)
        return output


def fetch_bundle(tag: str, asset_name: str, cache: Path) -> Path:
    asset = release_asset(tag, asset_name)
    url = str(asset.get("browser_download_url") or "")
    size = int(asset.get("size") or 0)
    digest = str(asset.get("digest") or "")
    api_digest = digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else ""
    sidecar_asset = release_asset(tag, asset_name + ".sha256")
    sidecar_digest = parse_sidecar(download_text(str(sidecar_asset.get("browser_download_url") or "")))
    expected = api_digest or sidecar_digest
    if api_digest and sidecar_digest and api_digest != sidecar_digest:
        raise RuntimeError(f"GitHub asset digest and {asset_name}.sha256 disagree")

    release_dir = cache / tag
    archive = release_dir / asset_name
    state_path = release_dir / (asset_name + ".state.json")
    if archive.exists():
        size_matches = not size or archive.stat().st_size == size
        if not size_matches:
            print(
                f"Discarding stale cached {archive.name}: published size changed "
                f"from {archive.stat().st_size:,} to {size:,} bytes",
                file=sys.stderr,
            )
            archive.unlink(missing_ok=True)
            state_path.unlink(missing_ok=True)
        else:
            actual = sha256_file(archive)
            if actual == expected:
                print(f"Using cached {archive} ({archive.stat().st_size/1024/1024:,.1f} MiB)", file=sys.stderr)
            else:
                print(f"Discarding stale cached {archive.name}: SHA-256 changed", file=sys.stderr)
                archive.unlink(missing_ok=True)
                state_path.unlink(missing_ok=True)
    if not archive.exists():
        print(f"Downloading {asset_name} ({size/1024/1024:,.1f} MiB)...", file=sys.stderr)
        download_file(url, archive, size, asset_name)
        actual = sha256_file(archive)
        if actual != expected:
            archive.unlink(missing_ok=True)
            raise RuntimeError(f"SHA-256 verification failed for {asset_name}: expected {expected}, got {actual}")
    extracted_dir = release_dir / "extracted"
    extracted: Path | None = None
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            candidate = extracted_dir / Path(str(state.get("extractedFile") or "")).name
            if state.get("archiveSha256") == expected and candidate.is_file():
                extracted = candidate
        except Exception:
            extracted = None
    if extracted is None:
        extracted = safe_extract_sqlite(archive, extracted_dir)
        state_path.write_text(json.dumps({
            "archiveSha256": expected, "asset": asset_name, "extractedFile": extracted.name, "fetchedAtUtc": utc_now()
        }, indent=2), encoding="utf-8")
    return extracted


def fetch_latest(cache: Path, include_marketplace: bool = True) -> tuple[Path, Path | None]:
    evidence = fetch_bundle(EVIDENCE_TAG, EVIDENCE_ASSET, cache)
    marketplace = fetch_bundle(MARKETPLACE_TAG, MARKETPLACE_ASSET, cache) if include_marketplace else None
    return evidence, marketplace


def open_ro(path: Path) -> sqlite3.Connection:
    path = path.resolve()
    if not path.exists():
        raise FileNotFoundError(path)
    uri = "file:" + urllib.parse.quote(str(path).replace("\\", "/"), safe="/:_") + "?mode=ro"
    db = sqlite3.connect(uri, uri=True, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


def json_value(value: Any, fallback: Any = None) -> Any:
    if value is None:
        return fallback
    if isinstance(value, (dict, list, int, float, bool)):
        return value
    text = str(value)
    try:
        return json.loads(text)
    except Exception:
        return fallback if fallback is not None else text


def row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def severity_max(values: Iterable[str]) -> str:
    rank = 0
    for value in values:
        rank = max(rank, SEVERITY_RANK.get(str(value or "").strip().casefold(), 0))
    return RANK_SEVERITY.get(rank, "none")


def security_risk_score(informational: int, caution: int, high: int, critical: int, advisory_points: int = 0) -> int:
    return min(100, max(0, informational) + max(0, caution) * 6 + max(0, high) * 15 + max(0, critical) * 30 + max(0, advisory_points))


@dataclass
class AuditItem:
    status: str
    code: str
    title: str
    detail: str
    plugin: str = ""
    variant_id: int | None = None


class SecurityInspector:
    def __init__(self, evidence_path: Path, marketplace_path: Path | None = None):
        self.evidence_path = evidence_path.resolve()
        self.marketplace_path = marketplace_path.resolve() if marketplace_path else None
        self.db = open_ro(self.evidence_path)
        self.marketplace = open_ro(self.marketplace_path) if self.marketplace_path and self.marketplace_path.exists() else None
        self.tables = {str(r[0]) for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.marketplace_tables = {str(r[0]) for r in self.marketplace.execute("SELECT name FROM sqlite_master WHERE type='table'")} if self.marketplace else set()
        self.lock = threading.RLock()

    def close(self) -> None:
        with self.lock:
            self.db.close()
            if self.marketplace:
                self.marketplace.close()

    def meta(self) -> dict[str, str]:
        if "catalog_meta" not in self.tables:
            return {}
        return {str(r[0]): str(r[1]) for r in self.db.execute("SELECT key,value FROM catalog_meta ORDER BY key")}

    def summary(self) -> dict[str, Any]:
        with self.lock:
            meta = self.meta()
            def scalar(sql: str, args: tuple[Any, ...] = ()) -> Any:
                row = self.db.execute(sql, args).fetchone()
                return row[0] if row else 0
            counts = {
                "plugins": scalar("SELECT COUNT(*) FROM plugins WHERE active=1") if "plugins" in self.tables else 0,
                "variants": scalar("SELECT COUNT(*) FROM plugin_variants WHERE active=1") if "plugin_variants" in self.tables else 0,
                "currentScans": scalar("SELECT COUNT(*) FROM plugin_security_current") if "plugin_security_current" in self.tables else 0,
                "completeScans": scalar("SELECT COUNT(*) FROM plugin_security_current WHERE status='complete'") if "plugin_security_current" in self.tables else 0,
                "failedScans": scalar("SELECT COUNT(*) FROM plugin_security_current WHERE status<>'complete'") if "plugin_security_current" in self.tables else 0,
                "findings": scalar("SELECT COUNT(*) FROM plugin_security_findings") if "plugin_security_findings" in self.tables else 0,
                "criticalFindings": scalar("SELECT COUNT(*) FROM plugin_security_findings WHERE lower(severity)='critical'") if "plugin_security_findings" in self.tables else 0,
                "highFindings": scalar("SELECT COUNT(*) FROM plugin_security_findings WHERE lower(severity)='high'") if "plugin_security_findings" in self.tables else 0,
                "advisories": scalar("SELECT COUNT(*) FROM plugin_security_dependency_advisory_matches") if "plugin_security_dependency_advisory_matches" in self.tables else 0,
                "ipcProviders": scalar("SELECT COUNT(*) FROM plugin_security_ipc_registry") if "plugin_security_ipc_registry" in self.tables else 0,
                "dependencyIssues": scalar("SELECT COUNT(*) FROM plugin_security_dependency_issues") if "plugin_security_dependency_issues" in self.tables else 0,
            }
            sigmascope_row = self.db.execute("SELECT scanner_version,MAX(scanned_at_utc) FROM plugin_security_scans GROUP BY scanner_version ORDER BY MAX(scan_id) DESC LIMIT 1").fetchone() if "plugin_security_scans" in self.tables else None
            scanner_version = str(sigmascope_row[0]) if sigmascope_row else ""
            current_at_scanner = scalar(
                "SELECT COUNT(*) FROM plugin_security_current WHERE scanner_version=?", (scanner_version,)
            ) if scanner_version and "plugin_security_current" in self.tables else 0
            counts["currentAtSigmascope"] = current_at_scanner
            counts["currentAtScanner"] = current_at_scanner
            counts["legacyCurrent"] = max(0, int(counts["currentScans"]) - int(current_at_scanner))
            counts["observedNugetVersions"] = scalar(
                """SELECT COUNT(*) FROM (
                       SELECT lower(TRIM(d.name)),COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))
                         FROM plugin_security_dependencies d
                         JOIN plugin_security_current c ON c.scan_id=d.scan_id
                        WHERE c.status='complete' AND lower(d.kind) IN ('nuget','nuget-lock','nuget-resolved')
                          AND TRIM(d.name)<>''
                          AND COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))<>''
                        GROUP BY 1,2
                   )"""
            ) if {"plugin_security_dependencies", "plugin_security_current"}.issubset(self.tables) else 0
            try:
                counts["osvQueriedPackages"] = max(0, int(meta.get("public_advisory_queried_packages", "0") or 0))
                counts["osvMatchedPackages"] = max(0, int(meta.get("public_advisory_matched_packages", "0") or 0))
            except ValueError:
                counts["osvQueriedPackages"] = 0
                counts["osvMatchedPackages"] = 0
            return {
                "evidencePath": str(self.evidence_path),
                "marketplacePath": str(self.marketplace_path) if self.marketplace_path else "",
                "databaseBytes": self.evidence_path.stat().st_size,
                "meta": meta,
                "counts": counts,
                "sigmascopeVersion": scanner_version,
                "scannerVersion": scanner_version,
                "latestScanUtc": sigmascope_row[1] if sigmascope_row else "",
                "hasMarketplaceComparison": bool(self.marketplace),
                "generatedAtUtc": utc_now(),
            }

    def list_plugins(self, q: str = "", severity: str = "", status: str = "", known_risk: bool = False, limit: int = 300, offset: int = 0) -> list[dict[str, Any]]:
        limit = min(max(1, limit), 1000)
        offset = max(0, offset)
        where = ["v.active=1"]
        args: list[Any] = []
        if q.strip():
            token = f"%{q.strip()}%"
            where.append("(p.internal_name LIKE ? COLLATE NOCASE OR p.canonical_name LIKE ? COLLATE NOCASE OR v.name LIKE ? COLLATE NOCASE OR v.author LIKE ? COLLATE NOCASE OR s.name LIKE ? COLLATE NOCASE OR s.url LIKE ? COLLATE NOCASE)")
            args.extend([token] * 6)
        if severity:
            where.append("lower(COALESCE(sc.highest_severity,'none'))=?")
            args.append(severity.casefold())
        if status:
            where.append("lower(COALESCE(sc.status,'unscanned'))=?")
            args.append(status.casefold())
        sql = f"""
            SELECT p.plugin_id,p.internal_name,p.canonical_name,v.variant_id,v.name,v.author,v.assembly_version,
                   s.name AS source_name,s.url AS source_url,
                   sc.scan_id,COALESCE(sc.status,'unscanned') AS scan_status,COALESCE(sc.highest_severity,'none') AS highest_severity,
                   COALESCE(sc.informational_count,0) AS informational_count,COALESCE(sc.caution_count,0) AS caution_count,
                   COALESCE(sc.high_count,0) AS high_count,COALESCE(sc.critical_count,0) AS critical_count,
                   COALESCE(sc.scanner_version,'') AS scanner_version,COALESCE(sc.scanned_at_utc,'') AS scanned_at_utc,
                   COALESCE(sc.automation_level,'none') AS automation_level,COALESCE(sc.source_available,0) AS source_available,
                   COALESCE(sc.source_to_binary_verified,0) AS source_verified,COALESCE(sc.artifact_sha256,'') AS artifact_sha256
              FROM plugin_variants v
              JOIN plugins p ON p.plugin_id=v.plugin_id
              JOIN sources s ON s.source_id=v.source_id
              LEFT JOIN plugin_security_current sc ON sc.variant_id=v.variant_id
             WHERE {' AND '.join(where)}
             ORDER BY CASE lower(COALESCE(sc.highest_severity,'none')) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'caution' THEN 2 WHEN 'informational' THEN 1 ELSE 0 END DESC,
                      p.canonical_name COLLATE NOCASE,v.name COLLATE NOCASE,s.name COLLATE NOCASE
             LIMIT ? OFFSET ?
        """
        args.extend([limit, offset])
        with self.lock:
            rows = [dict(r) for r in self.db.execute(sql, tuple(args)).fetchall()]
            if known_risk:
                rows = [r for r in rows if self.advisory_summary(int(r["variant_id"]))["count"] > 0]
            for row in rows:
                adv = self.advisory_summary(int(row["variant_id"]))
                row["knownAdvisoryCount"] = adv["count"]
                row["knownAdvisoryHighestSeverity"] = adv["highestSeverity"]
                row["riskScore"] = security_risk_score(row["informational_count"], row["caution_count"], row["high_count"], row["critical_count"], adv["points"])
            return rows

    def advisory_rows(self, variant_id: int) -> list[dict[str, Any]]:
        if not {"plugin_security_current", "plugin_security_dependencies", "plugin_security_dependency_resolutions", "plugin_security_dependency_advisory_matches"}.issubset(self.tables):
            return []
        sql = """
            SELECT DISTINCT adv.advisory_id,adv.component_key,adv.component_kind,adv.component_name,
                   adv.affected_version,adv.affected_range,adv.fixed_version,adv.severity,adv.title,
                   adv.advisory_url,adv.advisory_source,adv.refreshed_at_utc,
                   d.name AS dependency_name,d.version AS dependency_version,d.resolved_version,
                   d.kind AS dependency_kind,r.requirement,r.resolution_status,r.version_status
              FROM plugin_security_current sc
              JOIN plugin_security_dependencies d ON d.scan_id=sc.scan_id
              JOIN plugin_security_dependency_resolutions r ON r.dependency_id=d.dependency_id
              JOIN plugin_security_dependency_advisory_matches adv
                ON adv.component_key=r.component_key
               AND (TRIM(adv.affected_version)='' OR lower(TRIM(adv.affected_version))=lower(COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))))
             WHERE sc.variant_id=? AND sc.status='complete' AND TRIM(adv.advisory_id)<>''
             ORDER BY CASE lower(adv.severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'moderate' THEN 2 WHEN 'caution' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
                      adv.advisory_id,adv.component_name
        """
        return [dict(r) for r in self.db.execute(sql, (variant_id,)).fetchall()]

    def advisory_summary(self, variant_id: int) -> dict[str, Any]:
        rows = self.advisory_rows(variant_id)
        unique: dict[tuple[str, str, str], int] = {}
        for row in rows:
            key = (str(row["advisory_id"]).casefold(), str(row["component_key"]).casefold(), str(row["affected_version"]).casefold())
            unique[key] = max(unique.get(key, -1), SEVERITY_RANK.get(str(row["severity"] or "").casefold(), 0))
        ranks = list(unique.values())
        rank = max(ranks, default=0)
        return {"count": len(unique), "highestSeverity": RANK_SEVERITY.get(rank, "unknown" if unique else "none"), "points": sum(ADVISORY_POINTS.get(r, 8) for r in ranks)}

    def _dependency_detail(self, scan_id: int) -> list[dict[str, Any]]:
        rows = [dict(r) for r in self.db.execute("SELECT * FROM plugin_security_dependencies WHERE scan_id=? ORDER BY kind,name,version", (scan_id,)).fetchall()]
        for dep in rows:
            dep_id = int(dep["dependency_id"])
            resolution = self.db.execute("SELECT * FROM plugin_security_dependency_resolutions WHERE dependency_id=?", (dep_id,)).fetchone() if "plugin_security_dependency_resolutions" in self.tables else None
            dep["resolution"] = row_dict(resolution)
            dep["issues"] = [dict(r) for r in self.db.execute("SELECT * FROM plugin_security_dependency_issues WHERE dependency_id=? ORDER BY issue_id", (dep_id,)).fetchall()] if "plugin_security_dependency_issues" in self.tables else []
            for key in ("evidence_json", "relationship_evidence_json"):
                dep[key] = json_value(dep.get(key), [])
            if dep["resolution"]:
                for key in ("evidence_json", "relationship_evidence_json"):
                    dep["resolution"][key] = json_value(dep["resolution"].get(key), [])
        return rows

    def plugin_detail(self, variant_id: int) -> dict[str, Any]:
        with self.lock:
            identity = self.db.execute("""
                SELECT p.plugin_id,p.internal_name,p.canonical_name,p.active AS plugin_active,
                       v.*,s.name AS source_name,s.url AS source_url,s.provider AS source_provider,s.kind AS source_kind,
                       sc.scan_id,sc.artifact_channel,sc.artifact_url,sc.artifact_sha256,sc.scanner_version,sc.status AS scan_status,
                       sc.scanned_at_utc,sc.highest_severity,sc.informational_count,sc.caution_count,sc.high_count,sc.critical_count,
                       sc.capabilities_json,sc.automation_level,sc.automation_capabilities_json,sc.source_available,
                       sc.source_repository,sc.source_commit,sc.source_to_binary_verified,sc.report_json,sc.error AS scan_error
                  FROM plugin_variants v
                  JOIN plugins p ON p.plugin_id=v.plugin_id
                  JOIN sources s ON s.source_id=v.source_id
                  LEFT JOIN plugin_security_current sc ON sc.variant_id=v.variant_id
                 WHERE v.variant_id=?
            """, (variant_id,)).fetchone()
            if not identity:
                raise KeyError(f"Unknown variant_id {variant_id}")
            item = dict(identity)
            scan_id = int(item["scan_id"] or 0)
            item["authors_json"] = json_value(item.get("authors_json"), [])
            item["capabilities_json"] = json_value(item.get("capabilities_json"), [])
            item["automation_capabilities_json"] = json_value(item.get("automation_capabilities_json"), [])
            report = json_value(item.get("report_json"), {})
            source_scope = (((report or {}).get("source") or {}).get("scope") or {}) if isinstance(report, dict) else {}
            package = ((report or {}).get("package") or {}) if isinstance(report, dict) else {}
            findings = [dict(r) for r in self.db.execute("SELECT * FROM plugin_security_findings WHERE scan_id=? ORDER BY CASE lower(severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'caution' THEN 2 ELSE 1 END DESC,finding_id", (scan_id,)).fetchall()] if scan_id else []
            for row in findings:
                row["evidence_json"] = json_value(row.get("evidence_json"), [])
            permissions = [dict(r) for r in self.db.execute("SELECT * FROM plugin_security_permission_candidates WHERE scan_id=? ORDER BY risk DESC,permission_id", (scan_id,)).fetchall()] if scan_id and "plugin_security_permission_candidates" in self.tables else []
            for row in permissions:
                row["evidence_json"] = json_value(row.get("evidence_json"), [])
            automation = [dict(r) for r in self.db.execute("SELECT * FROM plugin_security_automation_capabilities WHERE scan_id=? ORDER BY automation_level DESC,capability_id", (scan_id,)).fetchall()] if scan_id and "plugin_security_automation_capabilities" in self.tables else []
            for row in automation:
                row["evidence_json"] = json_value(row.get("evidence_json"), [])
            ipc = [dict(r) for r in self.db.execute("SELECT * FROM plugin_security_ipc_endpoints WHERE scan_id=? ORDER BY role,channel", (scan_id,)).fetchall()] if scan_id and "plugin_security_ipc_endpoints" in self.tables else []
            for row in ipc:
                row["relationship_evidence_json"] = json_value(row.get("relationship_evidence_json"), [])
                row["providers"] = [dict(r) for r in self.db.execute("SELECT * FROM plugin_security_ipc_registry WHERE channel=? ORDER BY provider_internal_name", (row["channel"],)).fetchall()] if row.get("role") == "consumer" else []
            comparison = row_dict(self.db.execute("SELECT * FROM plugin_security_source_artifact_comparisons WHERE scan_id=?", (scan_id,)).fetchone()) if scan_id and "plugin_security_source_artifact_comparisons" in self.tables else None
            if comparison:
                for key in ("source_only_json", "artifact_only_json", "version_mismatches_json", "requirement_mismatches_json"):
                    comparison[key] = json_value(comparison.get(key), [])
            lineage = row_dict(self.db.execute("SELECT * FROM plugin_security_scan_lineage WHERE current_scan_id=?", (scan_id,)).fetchone()) if scan_id and "plugin_security_scan_lineage" in self.tables else None
            drift = [dict(r) for r in self.db.execute("SELECT * FROM plugin_security_dependency_drift WHERE current_scan_id=? ORDER BY drift_id", (scan_id,)).fetchall()] if scan_id and "plugin_security_dependency_drift" in self.tables else []
            advisories = self.advisory_rows(variant_id)
            adv_summary = self.advisory_summary(variant_id)
            expected_risk = security_risk_score(int(item.get("informational_count") or 0), int(item.get("caution_count") or 0), int(item.get("high_count") or 0), int(item.get("critical_count") or 0), adv_summary["points"])
            marketplace = self.marketplace_security(variant_id)
            audit = [asdict(x) for x in self.audit_variant(variant_id)]
            return {
                "identity": item,
                "sourceScope": source_scope,
                "package": package,
                "findings": findings,
                "dependencies": self._dependency_detail(scan_id) if scan_id else [],
                "advisories": advisories,
                "advisorySummary": adv_summary,
                "permissions": permissions,
                "automation": automation,
                "ipc": ipc,
                "sourceArtifactComparison": comparison,
                "lineage": lineage,
                "drift": drift,
                "riskScore": expected_risk,
                "marketplaceSecurity": marketplace,
                "audit": audit,
            }

    def marketplace_security(self, variant_id: int) -> dict[str, Any] | None:
        if not self.marketplace or "marketplace_security_current" not in self.marketplace_tables:
            return None
        row = self.marketplace.execute("SELECT * FROM marketplace_security_current WHERE variant_id=?", (variant_id,)).fetchone()
        return dict(row) if row else None

    def audit_variant(self, variant_id: int) -> list[AuditItem]:
        row = self.db.execute("""
            SELECT p.internal_name,v.variant_id,sc.* FROM plugin_variants v
            JOIN plugins p ON p.plugin_id=v.plugin_id
            LEFT JOIN plugin_security_current sc ON sc.variant_id=v.variant_id
            WHERE v.variant_id=?
        """, (variant_id,)).fetchone()
        if not row:
            return [AuditItem("fail", "variant.missing", "Variant missing", f"variant_id={variant_id}", variant_id=variant_id)]
        plugin = str(row["internal_name"] or "")
        if not row["scan_id"]:
            return [AuditItem("warn", "scan.missing", "No current Sigmascope analysis", "This active variant has no current Sigmascope analysis pointer.", plugin, variant_id)]
        scan_id = int(row["scan_id"])
        scan = self.db.execute("SELECT * FROM plugin_security_scans WHERE scan_id=?", (scan_id,)).fetchone()
        if scan is None:
            return [AuditItem("fail", "scan.pointer", "Current Sigmascope pointer has no immutable scan row", f"scan_id={scan_id}", plugin, variant_id)]

        items: list[AuditItem] = []
        finding_rows = self.db.execute("SELECT severity,COUNT(*) FROM plugin_security_findings WHERE scan_id=? GROUP BY lower(severity)", (scan_id,)).fetchall()
        actual_static = {str(r[0]).casefold(): int(r[1]) for r in finding_rows}
        scan_counts = {
            "informational": int(scan["informational_count"] or 0),
            "caution": int(scan["caution_count"] or 0),
            "high": int(scan["high_count"] or 0),
            "critical": int(scan["critical_count"] or 0),
        }
        mismatches = {k: (scan_counts[k], actual_static.get(k, 0)) for k in scan_counts if scan_counts[k] != actual_static.get(k, 0)}
        if mismatches:
            items.append(AuditItem("fail", "conclusion.finding_counts", "Immutable scan finding counts disagree with evidence rows", json.dumps(mismatches, sort_keys=True), plugin, variant_id))
        else:
            items.append(AuditItem("pass", "conclusion.finding_counts", "Immutable scan finding counts reproduce", f"{sum(scan_counts.values())} finding rows match the recorded scan counters.", plugin, variant_id))
        actual_static_highest = severity_max([str(r[0]) for r in finding_rows for _ in range(int(r[1]))])
        scan_highest = str(scan["highest_severity"] or "none").casefold()
        if actual_static_highest != scan_highest:
            items.append(AuditItem("fail", "conclusion.highest_severity", "Immutable scan highest severity does not reproduce", f"recorded={scan_highest}, evidence={actual_static_highest}", plugin, variant_id))
        else:
            items.append(AuditItem("pass", "conclusion.highest_severity", "Immutable scan highest severity reproduces", scan_highest, plugin, variant_id))

        # Current rows are a derived user-facing projection: artifact canonicalization
        # and cross-source provenance can intentionally add/copy findings without
        # mutating immutable scan evidence. Audit that projection against its own
        # explicit findings_json, then compare that reproducible projection to the
        # small marketplace database.
        current_findings = json_value(row["findings_json"], [])
        if not isinstance(current_findings, list):
            current_findings = []
        current_counts_actual = {"informational": 0, "caution": 0, "high": 0, "critical": 0}
        current_severities: list[str] = []
        for finding in current_findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "none").casefold()
            if severity in current_counts_actual:
                current_counts_actual[severity] += 1
            current_severities.append(severity)
        current_counts = {
            "informational": int(row["informational_count"] or 0),
            "caution": int(row["caution_count"] or 0),
            "high": int(row["high_count"] or 0),
            "critical": int(row["critical_count"] or 0),
        }
        current_mismatches = {k: (current_counts[k], current_counts_actual[k]) for k in current_counts if current_counts[k] != current_counts_actual[k]}
        if current_mismatches:
            items.append(AuditItem("fail", "projection.current_finding_counts", "Current projection counters disagree with current findings", json.dumps(current_mismatches, sort_keys=True), plugin, variant_id))
        current_highest = str(row["highest_severity"] or "none").casefold()
        projected_highest = severity_max(current_severities)
        if current_highest != projected_highest:
            items.append(AuditItem("fail", "projection.current_highest_severity", "Current projection highest severity does not reproduce", f"recorded={current_highest}, findings={projected_highest}", plugin, variant_id))

        if str(row["status"] or "") != "complete":
            items.append(AuditItem("warn", "scan.status", "Current scan is not complete", f"status={row['status']!r}; error={row['error']!r}", plugin, variant_id))
        else:
            items.append(AuditItem("pass", "scan.status", "Current scan completed", str(row["scanned_at_utc"] or ""), plugin, variant_id))

        adv = self.advisory_summary(variant_id)
        risk = security_risk_score(current_counts["informational"], current_counts["caution"], current_counts["high"], current_counts["critical"], adv["points"])
        market = self.marketplace_security(variant_id)
        if market:
            comparisons = {
                "highest_severity": (current_highest, str(market.get("highest_severity") or "none").casefold()),
                "known_advisory_count": (adv["count"], int(market.get("known_advisory_count") or 0)),
                "known_advisory_highest_severity": (adv["highestSeverity"], str(market.get("known_advisory_highest_severity") or "none")),
                "risk_score": (risk, int(market.get("risk_score") or 0)),
            }
            bad = {k: v for k, v in comparisons.items() if v[0] != v[1]}
            if bad:
                items.append(AuditItem("fail", "projection.security_summary", "Marketplace conclusion disagrees with evidence", json.dumps(bad, sort_keys=True), plugin, variant_id))
            else:
                items.append(AuditItem("pass", "projection.security_summary", "Marketplace security projection reproduces", f"risk={risk}, advisories={adv['count']}", plugin, variant_id))
        else:
            items.append(AuditItem("info", "projection.unavailable", "Marketplace comparison not loaded", "Load omega-marketplace.sqlite to compare the client conclusion against detailed evidence.", plugin, variant_id))

        if "plugin_security_source_artifact_comparisons" in self.tables:
            comp = self.db.execute("SELECT * FROM plugin_security_source_artifact_comparisons WHERE scan_id=?", (scan_id,)).fetchone()
            if comp:
                for count_field, json_field in (
                    ("source_only_count", "source_only_json"), ("artifact_only_count", "artifact_only_json"),
                    ("version_mismatch_count", "version_mismatches_json"), ("requirement_mismatch_count", "requirement_mismatches_json"),
                ):
                    parsed = json_value(comp[json_field], [])
                    actual_len = len(parsed) if isinstance(parsed, list) else -1
                    if int(comp[count_field] or 0) != actual_len:
                        items.append(AuditItem("fail", "source_artifact.count", "Source/package comparison count disagrees with JSON", f"{count_field}={comp[count_field]}, {json_field} items={actual_len}", plugin, variant_id))
        return items

    def global_audit(self, max_plugin_issues: int = 500) -> dict[str, Any]:
        with self.lock:
            items: list[AuditItem] = []
            integrity = self.db.execute("PRAGMA integrity_check").fetchone()
            if integrity and str(integrity[0]).casefold() == "ok":
                items.append(AuditItem("pass", "database.integrity", "SQLite integrity check passes", "PRAGMA integrity_check = ok"))
            else:
                items.append(AuditItem("fail", "database.integrity", "SQLite integrity check failed", str(integrity[0] if integrity else "no result")))
            missing = sorted(EXPECTED_EVIDENCE_TABLES - self.tables)
            if missing:
                items.append(AuditItem("fail", "database.schema", "Expected security tables are missing", ", ".join(missing)))
            else:
                items.append(AuditItem("pass", "database.schema", "Expected security tables are present", f"{len(EXPECTED_EVIDENCE_TABLES)} core evidence tables"))
            try:
                fks = self.db.execute("PRAGMA foreign_key_check").fetchmany(100)
            except sqlite3.DatabaseError as exc:
                fks = [("error", str(exc))]
            if fks:
                items.append(AuditItem("fail", "database.foreign_keys", "Foreign-key consistency issues found", json.dumps([list(r) for r in fks[:20]])))
            else:
                items.append(AuditItem("pass", "database.foreign_keys", "Foreign-key consistency passes", "No orphan rows reported."))

            summary = self.summary()
            observed_nuget = int(summary["counts"].get("observedNugetVersions") or 0)
            queried_nuget = int(summary["counts"].get("osvQueriedPackages") or 0)
            coverage_present = "public_advisory_queried_packages" in summary.get("meta", {})
            expected_queries = min(observed_nuget, OSV_QUERY_LIMIT)
            if observed_nuget and not coverage_present:
                items.append(AuditItem(
                    "warn", "osv.coverage.metadata", "OSV collector coverage metadata is unavailable",
                    f"observedNugetVersions={observed_nuget}; this evidence predates the coverage marker or was not processed by the current advisory collector.",
                ))
            elif expected_queries and queried_nuget < expected_queries:
                items.append(AuditItem(
                    "fail", "osv.coverage.queries", "OSV collector did not query the expected package set",
                    f"observedNugetVersions={observed_nuget}, expectedQueries={expected_queries}, queriedPackages={queried_nuget}",
                ))
            else:
                items.append(AuditItem(
                    "pass", "osv.coverage.queries", "OSV collector coverage matches observed NuGet versions",
                    f"observedNugetVersions={observed_nuget}, queriedPackages={queried_nuget}, queryLimit={OSV_QUERY_LIMIT}",
                ))

            orphan_current = self.db.execute("""
                SELECT COUNT(*) FROM plugin_security_current c
                LEFT JOIN plugin_security_scans s ON s.scan_id=c.scan_id
                WHERE s.scan_id IS NULL
            """).fetchone()[0]
            items.append(AuditItem("fail" if orphan_current else "pass", "current.pointer", "Current scan pointers resolve" if not orphan_current else "Current scan pointers are orphaned", f"orphanCurrentScans={orphan_current}"))

            # IPC registry must correspond to a current provider endpoint observation.
            if {"plugin_security_ipc_registry", "plugin_security_ipc_endpoints", "plugin_security_current"}.issubset(self.tables):
                bad_ipc = self.db.execute("""
                    SELECT r.channel,r.provider_internal_name,r.provider_scan_id
                      FROM plugin_security_ipc_registry r
                      LEFT JOIN plugin_security_ipc_endpoints e
                        ON e.scan_id=r.provider_scan_id AND e.channel=r.channel AND e.role='provider'
                     WHERE e.ipc_endpoint_id IS NULL
                     LIMIT 100
                """).fetchall()
                items.append(AuditItem("fail" if bad_ipc else "pass", "ipc.registry", "IPC provider registry resolves to provider evidence" if not bad_ipc else "IPC registry contains provider rows without provider evidence", json.dumps([dict(r) for r in bad_ipc[:20]], default=str)))

            # Same artifact + Sigmascope version should not produce contradictory static conclusions.
            conflicting = self.db.execute("""
                SELECT p.internal_name,c.assembly_version,c.artifact_sha256,c.scanner_version,
                       COUNT(DISTINCT c.highest_severity || ':' || c.informational_count || ':' || c.caution_count || ':' || c.high_count || ':' || c.critical_count) AS conclusions,
                       COUNT(*) AS variants
                  FROM plugin_security_current c
                  JOIN plugin_variants v ON v.variant_id=c.variant_id
                  JOIN plugins p ON p.plugin_id=v.plugin_id
                 WHERE c.status='complete' AND length(c.artifact_sha256)=64 AND v.active=1 AND p.active=1
                 GROUP BY lower(p.internal_name),lower(c.assembly_version),lower(c.artifact_sha256),c.scanner_version
                HAVING conclusions>1
                 LIMIT 100
            """).fetchall()
            items.append(AuditItem("fail" if conflicting else "pass", "artifact.canonical_conclusion", "Identical artifacts have canonical static conclusions" if not conflicting else "Identical artifacts disagree on static conclusion", json.dumps([dict(r) for r in conflicting[:20]], default=str)))

            # Reproduce each current variant's conclusion.
            variant_rows = self.db.execute("SELECT variant_id FROM plugin_security_current ORDER BY variant_id").fetchall()
            plugin_items: list[AuditItem] = []
            for row in variant_rows:
                for issue in self.audit_variant(int(row[0])):
                    if issue.status in {"fail", "warn"}:
                        plugin_items.append(issue)
                        if len(plugin_items) >= max_plugin_issues:
                            break
                if len(plugin_items) >= max_plugin_issues:
                    break
            items.extend(plugin_items)
            counts: dict[str, int] = {"pass": 0, "info": 0, "warn": 0, "fail": 0}
            for item in items:
                counts[item.status] = counts.get(item.status, 0) + 1
            return {"generatedAtUtc": utc_now(), "counts": counts, "items": [asdict(x) for x in items], "truncated": len(plugin_items) >= max_plugin_issues}

    def managed_calls(self, variant_id: int, query: str = "", limit: int = 250) -> list[dict[str, Any]]:
        limit = min(max(limit, 1), 1000)
        scan = self.db.execute("SELECT scan_id FROM plugin_security_current WHERE variant_id=?", (variant_id,)).fetchone()
        if not scan or "plugin_security_managed_calls" not in self.tables:
            return []
        sql = "SELECT * FROM plugin_security_managed_calls WHERE scan_id=?"
        args: list[Any] = [int(scan[0])]
        if query.strip():
            token = f"%{query.strip()}%"
            sql += " AND (target_declaring_type LIKE ? COLLATE NOCASE OR target_name LIKE ? COLLATE NOCASE OR target_native_library LIKE ? COLLATE NOCASE OR source_method_name LIKE ? COLLATE NOCASE)"
            args.extend([token] * 4)
        sql += " ORDER BY managed_call_id LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.db.execute(sql, tuple(args)).fetchall()]

    @staticmethod
    def _quote_identifier(name: str) -> str:
        return '"' + str(name).replace('"', '""') + '"'

    @staticmethod
    def _table_category(name: str) -> str:
        if name.startswith("plugin_security_"):
            if "ipc" in name:
                return "IPC"
            if "dependency" in name:
                return "Dependencies"
            if "permission" in name or "automation" in name:
                return "Capabilities"
            if "managed_" in name or "source_artifact" in name or "lineage" in name:
                return "Forensics"
            return "Security"
        if name in {"plugins", "plugin_variants", "sources", "websites", "presentation", "runtime_plugin_variants", "plugin_search"}:
            return "Marketplace"
        if name.startswith("catalog_") or name in {"base_revision_changelog", "security_revision_changelog"}:
            return "Metadata"
        return "Other"

    @staticmethod
    def _friendly_table_name(name: str) -> str:
        overrides = {
            "plugins": "Plugins",
            "plugin_variants": "Plugin variants",
            "sources": "Repository sources",
            "websites": "Project-page scrapes",
            "plugin_security_current": "Current security conclusions",
            "plugin_security_scans": "Sigmascope analysis history",
            "plugin_security_findings": "Static findings",
            "plugin_security_dependencies": "Observed dependencies",
            "plugin_security_dependency_resolutions": "Dependency resolutions",
            "plugin_security_dependency_issues": "Dependency issues",
            "plugin_security_dependency_advisory_matches": "Known vulnerability matches",
            "plugin_security_dependency_components": "Dependency components",
            "plugin_security_dependency_drift": "Dependency drift",
            "plugin_security_ipc_endpoints": "IPC endpoints",
            "plugin_security_ipc_registry": "IPC provider registry",
            "plugin_security_permission_candidates": "Permission candidates",
            "plugin_security_automation_capabilities": "Automation capabilities",
            "plugin_security_source_artifact_comparisons": "Source / package comparisons",
            "plugin_security_scan_lineage": "Scan lineage",
            "plugin_security_managed_assemblies": "Managed assemblies",
            "plugin_security_managed_symbols": "Managed symbols",
            "plugin_security_managed_calls": "Managed calls",
            "plugin_security_managed_reachability": "Managed reachability",
            "catalog_meta": "Catalog metadata",
        }
        return overrides.get(name, name.replace("_", " ").strip().title())

    def table_catalog(self) -> list[dict[str, Any]]:
        hidden_suffixes = ("_data", "_idx", "_content", "_docsize", "_config")
        preferred = [
            "plugins", "plugin_variants", "sources", "websites",
            "plugin_security_current", "plugin_security_scans", "plugin_security_findings",
            "plugin_security_dependencies", "plugin_security_dependency_resolutions",
            "plugin_security_dependency_issues", "plugin_security_dependency_advisory_matches",
            "plugin_security_dependency_components", "plugin_security_dependency_drift",
            "plugin_security_ipc_endpoints", "plugin_security_ipc_registry",
            "plugin_security_permission_candidates", "plugin_security_automation_capabilities",
            "plugin_security_source_artifact_comparisons", "plugin_security_scan_lineage",
            "plugin_security_managed_assemblies", "plugin_security_managed_symbols",
            "plugin_security_managed_calls", "plugin_security_managed_reachability",
            "catalog_meta",
        ]
        rank = {name: index for index, name in enumerate(preferred)}
        rows: list[dict[str, Any]] = []
        with self.lock:
            for name in self.tables:
                if name.startswith("sqlite_"):
                    continue
                if name != "plugin_search" and name.endswith(hidden_suffixes):
                    continue
                columns = [dict(r) for r in self.db.execute(f"PRAGMA table_info({self._quote_identifier(name)})").fetchall()]
                rows.append({
                    "name": name,
                    "label": self._friendly_table_name(name),
                    "category": self._table_category(name),
                    "columnCount": len(columns),
                    "primaryKeys": [str(c.get("name") or "") for c in columns if int(c.get("pk") or 0) > 0],
                })
        return sorted(rows, key=lambda r: (rank.get(r["name"], 10_000), r["category"], r["label"].casefold()))

    def browse_table(
        self,
        name: str,
        *,
        limit: int = 100,
        offset: int = 0,
        filter_column: str = "",
        filter_value: str = "",
    ) -> dict[str, Any]:
        if name not in self.tables or name.startswith("sqlite_"):
            raise ValueError(f"Unknown table: {name}")
        limit = min(max(1, int(limit)), MAX_TABLE_ROWS)
        offset = max(0, int(offset))
        with self.lock:
            columns = [dict(r) for r in self.db.execute(f"PRAGMA table_info({self._quote_identifier(name)})").fetchall()]
            column_names = {str(c.get("name") or "") for c in columns}
            if filter_column and filter_column not in column_names:
                raise ValueError(f"Unknown column {filter_column!r} for table {name!r}")
            foreign_keys = [dict(r) for r in self.db.execute(f"PRAGMA foreign_key_list({self._quote_identifier(name)})").fetchall()]
            # The evidence schema intentionally avoids expensive cross-table FK enforcement on
            # the very large forensic tables. Add read-only semantic relationships so the
            # developer browser can still traverse the database without requiring raw SQL.
            relationship_targets = {
                "variant_id": ("plugin_variants", "variant_id"),
                "source_variant_id": ("plugin_variants", "variant_id"),
                "plugin_id": ("plugins", "plugin_id"),
                "source_plugin_id": ("plugins", "plugin_id"),
                "provider_plugin_id": ("plugins", "plugin_id"),
                "source_id": ("sources", "source_id"),
                "scan_id": ("plugin_security_scans", "scan_id"),
                "provider_scan_id": ("plugin_security_scans", "scan_id"),
                "dependency_id": ("plugin_security_dependencies", "dependency_id"),
                "component_key": ("plugin_security_dependency_components", "component_key"),
                "ipc_endpoint_id": ("plugin_security_ipc_endpoints", "ipc_endpoint_id"),
                "managed_assembly_id": ("plugin_security_managed_assemblies", "managed_assembly_id"),
                "managed_symbol_id": ("plugin_security_managed_symbols", "managed_symbol_id"),
                "source_symbol_id": ("plugin_security_managed_symbols", "managed_symbol_id"),
                "target_symbol_id": ("plugin_security_managed_symbols", "managed_symbol_id"),
                "provider_internal_name": ("plugins", "internal_name"),
            }
            linked_columns = {str(fk.get("from") or "") for fk in foreign_keys}
            for column in columns:
                column_name = str(column.get("name") or "")
                target = relationship_targets.get(column_name)
                if not target or column_name in linked_columns or target[0] not in self.tables:
                    continue
                target_columns = {str(r[1]) for r in self.db.execute(f"PRAGMA table_info({self._quote_identifier(target[0])})").fetchall()}
                if target[1] not in target_columns:
                    continue
                foreign_keys.append({
                    "id": -1, "seq": 0, "table": target[0], "from": column_name, "to": target[1],
                    "on_update": "", "on_delete": "", "match": "", "inferred": 1,
                })
            sql = f"SELECT * FROM {self._quote_identifier(name)}"
            args: list[Any] = []
            if filter_column:
                sql += f" WHERE {self._quote_identifier(filter_column)} = ?"
                args.append(filter_value)
            order_columns = [str(c.get("name") or "") for c in columns if int(c.get("pk") or 0) > 0]
            if order_columns:
                sql += " ORDER BY " + ",".join(self._quote_identifier(c) for c in order_columns)
            sql += " LIMIT ? OFFSET ?"
            args.extend([limit + 1, offset])
            fetched = self.db.execute(sql, tuple(args)).fetchall()
            has_more = len(fetched) > limit
            fetched = fetched[:limit]
            rows = [dict(r) for r in fetched]
            return {
                "name": name,
                "label": self._friendly_table_name(name),
                "category": self._table_category(name),
                "columns": columns,
                "foreignKeys": foreign_keys,
                "rows": rows,
                "limit": limit,
                "offset": offset,
                "hasMore": has_more,
                "filter": {"column": filter_column, "value": filter_value} if filter_column else None,
            }

    def read_sql(self, query: str) -> dict[str, Any]:
        text = query.strip()
        if not text:
            return {"columns": [], "rows": []}
        normalized = re.sub(r"--.*?$|/\*.*?\*/", " ", text, flags=re.M | re.S).strip().casefold()
        if ";" in normalized.rstrip(";"):
            raise ValueError("Only one read-only SQL statement is allowed")
        if not re.match(r"^(select|pragma|with|explain)\b", normalized):
            raise ValueError("Read-only console accepts SELECT, PRAGMA, WITH, or EXPLAIN only")
        forbidden = re.search(r"\b(insert|update|delete|replace|create|drop|alter|attach|detach|vacuum|reindex|analyze|begin|commit|rollback)\b", normalized)
        if forbidden:
            raise ValueError(f"Forbidden SQL keyword: {forbidden.group(1)}")
        cursor = self.db.execute(text)
        columns = [d[0] for d in (cursor.description or [])]
        rows = [list(r) for r in cursor.fetchmany(MAX_SQL_ROWS)]
        return {"columns": columns, "rows": rows, "maxRows": MAX_SQL_ROWS}


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Omega Security Developer View</title>
<style>
:root{color-scheme:dark;--bg:#090c0f;--panel:#0f1419;--panel2:#141b22;--line:#27323c;--text:#eef4f7;--muted:#8fa1ad;--cyan:#36d5d0;--red:#ff5e62;--amber:#ffbf4d;--green:#55d98d;--blue:#68a7ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 Inter,Segoe UI,Arial,sans-serif}button,input,select,textarea{font:inherit;color:inherit;background:#111820;border:1px solid var(--line);border-radius:7px;padding:8px 10px}button{cursor:pointer}button:hover{border-color:var(--cyan)}a{color:var(--cyan)}
header{position:sticky;top:0;z-index:10;background:rgba(9,12,15,.96);border-bottom:1px solid var(--line);padding:14px 18px;display:flex;align-items:center;gap:12px}.logo{font-weight:800;letter-spacing:.08em}.badge{padding:3px 7px;border-radius:999px;background:#162028;color:var(--muted);font-size:12px}.badge.ro{color:var(--green)}main{padding:18px;max-width:1900px;margin:auto}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px}.card{padding:12px}.card.clickable{cursor:pointer}.card.clickable:hover{border-color:var(--cyan);background:#111a20}.card .n{font-size:24px;font-weight:700}.muted{color:var(--muted)}.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:14px 0}.toolbar input{min-width:280px;flex:1}.split{display:grid;grid-template-columns:minmax(500px,1.05fr) minmax(520px,1.4fr);gap:14px;align-items:start}.panel{overflow:hidden}.panel h2,.panel h3{margin:0}.panelhead{padding:11px 13px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:10px}.scroll{overflow:auto;max-height:68vh}table{width:100%;border-collapse:collapse}th,td{padding:8px 9px;border-bottom:1px solid #1c252d;text-align:left;vertical-align:top}th{position:sticky;top:0;background:#131a20;color:#aebbc3;font-size:12px;z-index:1}tr.click:hover{background:#142028;cursor:pointer}.sev-critical{color:var(--red);font-weight:700}.sev-high{color:#ff866b;font-weight:700}.sev-caution,.sev-medium{color:var(--amber)}.sev-informational{color:var(--blue)}.sev-none{color:var(--muted)}.pass{color:var(--green)}.warn{color:var(--amber)}.fail{color:var(--red)}.info{color:var(--blue)}
.detail{padding:13px}.kv{display:grid;grid-template-columns:190px minmax(0,1fr);gap:5px 10px;margin:8px 0}.kv b{color:#aebbc3}.kv span{word-break:break-word}.section{border-top:1px solid var(--line);padding:12px 0}.section:first-child{border-top:0;padding-top:0}details{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:#0c1116}summary{cursor:pointer;padding:9px 11px;font-weight:600}details>div{padding:0 11px 11px}.finding{padding:9px;border:1px solid #28333c;border-radius:7px;margin:7px 0;background:#11171c}.finding h4{margin:0 0 4px}.pill{display:inline-block;padding:2px 7px;border:1px solid var(--line);border-radius:999px;margin:2px;font-size:12px}.code{font:12px/1.4 Consolas,monospace;white-space:pre-wrap;word-break:break-word;background:#080b0e;padding:8px;border-radius:6px;max-height:320px;overflow:auto}.auditrow{padding:7px 0;border-bottom:1px solid #1b242b}.auditrow:last-child{border:0}.small{font-size:12px}
.db-browser{display:grid;grid-template-columns:270px minmax(520px,1fr) minmax(300px,.55fr);min-height:520px}.db-sidebar{border-right:1px solid var(--line);padding:10px;max-height:70vh;overflow:auto}.db-main{min-width:0;border-right:1px solid var(--line)}.db-row{padding:12px;max-height:70vh;overflow:auto}.table-group{margin:10px 0 4px;color:var(--muted);font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.08em}.table-button{display:block;width:100%;text-align:left;border:0;background:transparent;padding:7px 9px;margin:1px 0}.table-button:hover,.table-button.active{background:#142028;color:var(--cyan)}.table-grid{overflow:auto;max-height:58vh}.table-grid td{max-width:260px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.table-filter{display:inline-flex;align-items:center;gap:7px}.linkbutton{border:0;padding:0;background:transparent;color:var(--cyan);text-align:left}.linkbutton:hover{text-decoration:underline}.empty{padding:28px;color:var(--muted);text-align:center}.advanced{margin-top:14px}.advanced>summary{background:var(--panel);border-radius:8px}.advanced[open]>summary{border-bottom:1px solid var(--line);border-radius:8px 8px 0 0}textarea{width:100%;min-height:90px;font-family:Consolas,monospace}.sqlout{max-height:340px;overflow:auto}
@media(max-width:1250px){.split{grid-template-columns:1fr}.scroll{max-height:48vh}.db-browser{grid-template-columns:230px 1fr}.db-row{grid-column:1/-1;border-top:1px solid var(--line);max-height:none}.db-main{border-right:0}}
@media(max-width:760px){main{padding:10px}.db-browser{grid-template-columns:1fr}.db-sidebar{border-right:0;border-bottom:1px solid var(--line);max-height:220px}.db-row{grid-column:auto}.toolbar input{min-width:100%}.kv{grid-template-columns:1fr}}
</style></head>
<body><header><div class="logo">Ω OMEGA · SIGMASCOPE DEVELOPER VIEW</div><span class="badge ro">READ ONLY</span><span id="sourceBadge" class="badge"></span><span id="scannerBadge" class="badge"></span><span id="revisionBadge" class="badge"></span><span id="latestBadge" class="badge"></span><button id="refreshEvidence" style="display:none;margin-left:auto">New evidence · Refresh</button><button id="auditButton">Run consistency audit</button></header>
<main>
<div id="summaryCards" class="cards"></div>
<section class="panel" style="margin-top:14px"><div class="panelhead"><h2>Plugin explorer</h2><span class="muted">Search conclusions first; inspect raw evidence on the right.</span></div><div style="padding:0 12px 12px"><div class="toolbar"><input id="pluginQuery" placeholder="Search plugin, internal name, author, source…"><select id="severityFilter"><option value="">Any severity</option><option>critical</option><option>high</option><option>caution</option><option>informational</option><option>none</option></select><select id="scanStatusFilter"><option value="">Any scan status</option><option>complete</option><option>failed</option><option>unscanned</option></select><label><input id="knownRiskFilter" type="checkbox"> Known OSV risk</label><button id="refreshPlugins">Refresh</button></div>
<div class="split"><section class="panel"><div class="panelhead"><h3>Plugin variants</h3><span id="pluginRowCount" class="muted"></span></div><div class="scroll"><table><thead><tr><th>Plugin</th><th>Source</th><th>Version</th><th>Severity</th><th>Risk</th><th>Scan</th></tr></thead><tbody id="pluginRows"></tbody></table></div></section><section class="panel"><div class="panelhead"><h3 id="detailTitle">Select a plugin</h3><span id="detailMeta" class="muted"></span></div><div id="pluginDetail" class="detail"><span class="muted">Choose a plugin variant to inspect its conclusion and raw evidence.</span></div></section></div></div></section>
<section class="panel" style="margin-top:14px"><div class="panelhead"><h2>Evidence browser</h2><span class="muted">Click tables, rows, and foreign-key links. No SQL required.</span></div><div class="db-browser"><aside class="db-sidebar"><input id="tableSearch" style="width:100%" placeholder="Find a table…"><div id="tableList"></div></aside><section class="db-main"><div class="panelhead"><div><h3 id="tableTitle">Choose a table</h3><div id="tableSubtitle" class="muted small"></div></div><div><button id="tablePrev" disabled>← Previous</button> <button id="tableNext" disabled>Next →</button></div></div><div id="tableFilterBar" class="detail" style="display:none"></div><div id="tableGrid" class="table-grid"><div class="empty">Choose a table from the left, or click one of the summary cards above.</div></div></section><aside class="db-row"><h3 id="rowTitle">Row inspector</h3><div id="rowDetail" class="muted" style="margin-top:10px">Click any row to inspect every field and follow database relationships.</div></aside></div></section>
<details id="advancedSql" class="advanced"><summary>Advanced · read-only SQL console</summary><div><div class="muted small" style="margin:8px 0">Optional escape hatch: SELECT / PRAGMA / WITH / EXPLAIN only · max 1000 rows.</div><textarea id="sqlText">SELECT severity, category, rule_id, COUNT(*) AS n
FROM plugin_security_findings
GROUP BY severity, category, rule_id
ORDER BY n DESC
LIMIT 100</textarea><div style="margin:7px 0"><button id="runSqlButton">Run query</button></div><div id="sqlOutput" class="sqlout"></div></div></details>
</main><script>
const $=id=>document.getElementById(id);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sev=s=>`sev-${String(s||'none').toLowerCase()}`;const fmt=n=>Number(n||0).toLocaleString();let timer;let tables=[];let currentTable=null;let currentRows=[];let currentFkLinks=[];
async function api(path,opts){const r=await fetch(path,opts);const j=await r.json();if(!r.ok)throw new Error(j.error||r.statusText);return j}
function evidence(v){if(v==null)return'';return `<div class=code>${esc(typeof v==='string'?v:JSON.stringify(v,null,2))}</div>`}
function kv(obj,keys){return `<div class=kv>`+keys.map(([k,l])=>`<b>${esc(l)}</b><span>${esc(obj?.[k]??'')}</span>`).join('')+`</div>`}
function card(label,value,table){return `<div class="card ${table?'clickable':''}" ${table?`data-table="${esc(table)}"`:''}><div class=n>${fmt(value)}</div><div class=muted>${esc(label)}</div></div>`}
async function init(){const [s,t,source]=await Promise.all([api('/api/summary'),api('/api/tables'),api('/api/source')]);tables=t;applySourceStatus(source);$('scannerBadge').textContent=`Sigmascope ${s.sigmascopeVersion||s.scannerVersion||'?'}`;$('latestBadge').textContent=s.latestScanUtc?`latest ${s.latestScanUtc}`:'';const c=s.counts;$('summaryCards').innerHTML=[['Plugins',c.plugins,'plugins'],['Variants',c.variants,'plugin_variants'],['Current analyses',c.currentScans,'plugin_security_current'],[`Current @ Sigmascope ${s.sigmascopeVersion||s.scannerVersion||'?'}`,(c.currentAtSigmascope??c.currentAtScanner),'plugin_security_current'],['Legacy current',c.legacyCurrent,'plugin_security_current'],['Failed analyses',c.failedScans,'plugin_security_current'],['Findings',c.findings,'plugin_security_findings'],['Critical',c.criticalFindings,'plugin_security_findings'],['High',c.highFindings,'plugin_security_findings'],['NuGet versions',c.observedNugetVersions,'plugin_security_dependencies'],['OSV packages queried',c.osvQueriedPackages,'plugin_security_dependencies'],['OSV matched packages',c.osvMatchedPackages,'plugin_security_dependency_advisory_matches'],['OSV matches',c.advisories,'plugin_security_dependency_advisory_matches'],['IPC providers observed',c.ipcProviders,'plugin_security_ipc_registry'],['Dependency issues',c.dependencyIssues,'plugin_security_dependency_issues']].map(x=>card(...x)).join('');$('summaryCards').querySelectorAll('[data-table]').forEach(x=>x.addEventListener('click',()=>openTable(x.dataset.table)));if(source.mode==='online'||s.format==='security-evidence-v2')$('advancedSql').style.display='none';renderTableList();await loadPlugins()}
function applySourceStatus(s){$('sourceBadge').textContent=s.mode==='online'?'ONLINE · RAW GITHUB':String(s.mode||'LOCAL').toUpperCase();$('sourceBadge').title=s.baseUrl||s.cacheDirectory||'';$('revisionBadge').textContent=s.currentRevision?`evidence ${s.currentRevision}`:'';const b=$('refreshEvidence');b.style.display=s.updateAvailable?'inline-block':'none';if(s.updateAvailable)b.textContent=`New evidence ${s.remoteRevision} · Refresh`;if(s.error)$('sourceBadge').title=(($('sourceBadge').title||'')+' '+s.error).trim()}
async function checkEvidenceRevision(){try{const s=await api('/api/source?check=1');applySourceStatus(s)}catch(e){console.warn('Evidence revision check failed',e)}}
async function refreshEvidence(){const b=$('refreshEvidence');b.disabled=true;try{const s=await api('/api/refresh',{method:'POST'});applySourceStatus(s);await init()}finally{b.disabled=false}}
function debouncedLoad(){clearTimeout(timer);timer=setTimeout(loadPlugins,220)}
async function loadPlugins(){const u='/api/plugins?limit=500&q='+encodeURIComponent($('pluginQuery').value)+'&severity='+encodeURIComponent($('severityFilter').value)+'&status='+encodeURIComponent($('scanStatusFilter').value)+($('knownRiskFilter').checked?'&known_risk=1':'');const rows=await api(u);$('pluginRowCount').textContent=`${rows.length} shown`;$('pluginRows').innerHTML=rows.map(r=>`<tr class=click data-variant="${r.variant_id}"><td><b>${esc(r.canonical_name||r.name||r.internal_name)}</b><div class="muted small">${esc(r.internal_name)} · ${esc(r.author)}</div></td><td>${esc(r.source_name||r.source_url)}<div class="muted small">${esc(r.source_url)}</div></td><td>${esc(r.assembly_version)}</td><td class="${sev(r.highest_severity)}">${esc(r.highest_severity)}</td><td>${r.knownAdvisoryCount?`<span class=fail>Known risk · ${r.knownAdvisoryCount}</span><br>`:''}<span class=muted>${r.riskScore}/100 internal</span></td><td>${esc(r.scan_status)}<div class="muted small">${esc(r.scanned_at_utc)}</div></td></tr>`).join('')||'<tr><td colspan=6 class=empty>No plugin variants match these filters.</td></tr>';$('pluginRows').querySelectorAll('[data-variant]').forEach(x=>x.addEventListener('click',()=>loadDetail(Number(x.dataset.variant))))}
function renderDataset(name,rows){if(name==='findings')return rows.map(f=>`<div class=finding><h4 class="${sev(f.severity)}">${esc(f.severity)} · ${esc(f.title)}</h4><div>${esc(f.description)}</div><div class="muted small">${esc(f.rule_id)} · ${esc(f.category)}</div>${evidence(f.evidence_json)}</div>`).join('')||'<span class=muted>No findings.</span>';if(name==='dependencies')return `<div style="overflow:auto"><table><thead><tr><th>Kind</th><th>Name</th><th>Version</th><th>Requirement</th><th>Relationship</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${esc(x.kind)}</td><td>${esc(x.name)}</td><td>${esc(x.resolved_version||x.version)}</td><td>${esc(x.requirement)}</td><td>${esc(x.relationship)}</td></tr>`).join('')}</tbody></table></div>`;if(name==='ipc')return `<div style="overflow:auto"><table><thead><tr><th>Role</th><th>Channel</th><th>Relationship</th><th>Confidence</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${esc(x.role)}</td><td>${esc(x.channel)}</td><td>${esc(x.relationship)}</td><td>${esc(x.relationship_confidence)}</td></tr>`).join('')}</tbody></table></div>`;if(name==='permissions')return rows.map(x=>`<div class=finding><b>${esc(x.permission_id)}</b> <span class=pill>${esc(x.risk)}</span> <span class=pill>${esc(x.confidence)}</span><div>${esc(x.reason)}</div>${evidence(x.evidence_json)}</div>`).join('')||'<span class=muted>No permission candidates.</span>';if(name==='automation')return rows.map(x=>`<div class=finding><b>${esc(x.label||x.capability_id)}</b> <span class=pill>${esc(x.automation_level)}</span> <span class=pill>${esc(x.confidence)}</span><div>${esc(x.reason)}</div>${evidence(x.evidence_json)}</div>`).join('')||'<span class=muted>No automation capabilities.</span>';return evidence(rows)}
async function loadDataset(id,name,body){body.innerHTML='<span class=muted>Loading published evidence shard…</span>';try{const rows=await api('/api/dataset?variant_id='+id+'&name='+encodeURIComponent(name));body.innerHTML=renderDataset(name,rows)}catch(e){body.innerHTML=`<span class=fail>${esc(e.message)}</span>`}}
async function loadDetail(id){const d=await api('/api/plugin?variant_id='+id),i=d.identity;$('detailTitle').textContent=i.canonical_name||i.name||i.internal_name;$('detailMeta').textContent=`variant ${id} · analysis record ${i.scan_id||'none'}`;const audits=d.audit.map(a=>`<div class="auditrow ${a.status}"><b>${esc(a.status.toUpperCase())} · ${esc(a.title)}</b><div class="muted small">${esc(a.code)} — ${esc(a.detail)}</div></div>`).join('');const counts=d.datasetCounts||{};const section=(name,label,open=false)=>{const inline=d[name]||[];if(!d.lazyDatasets)return `<details ${open?'open':''}><summary>${esc(label)} (${inline.length})</summary><div>${renderDataset(name,inline)}</div></details>`;const n=counts[name]??0;return `<details data-lazy-dataset="${esc(name)}" ${open?'open':''}><summary>${esc(label)} (${n})</summary><div data-lazy-body><span class=muted>${open?'Loading published evidence shard…':'Open to fetch this evidence from GitHub.'}</span></div></details>`};let m=d.marketplaceSecurity;$('pluginDetail').innerHTML=`<div class=section><div class=cards><div class=card><div class="n ${sev(i.highest_severity)}">${esc(i.highest_severity||'none')}</div><div class=muted>Recorded static conclusion</div></div><div class=card><div class=n>${d.riskScore}</div><div class=muted>Internal risk score</div></div><div class=card><div class=n>${d.advisorySummary.count}</div><div class=muted>Exact-version OSV matches</div></div><div class=card><div class=n>${esc(i.automation_level||'none')}</div><div class=muted>Automation level</div></div></div>${kv(i,[['internal_name','Internal name'],['assembly_version','Version'],['source_name','Source'],['source_url','Source URL'],['artifact_sha256','Artifact SHA-256'],['scanner_version','Sigmascope version'],['scanned_at_utc','Analyzed'],['source_repository','Source repository'],['source_commit','Source commit']])}</div><div class=section><h3>Conclusion audit</h3>${audits}</div>${section('findings','Static findings',true)}<details><summary>Known advisories (${d.advisories.length})</summary><div>${d.advisories.length?evidence(d.advisories):'<span class=muted>No matching advisories.</span>'}</div></details>${section('dependencies','Dependencies')}${section('ipc','IPC endpoints')}${section('permissions','Permission candidates')}${section('automation','Automation evidence')}<details><summary>Plugin source build scope</summary><div>${evidence(d.sourceScope)}</div></details><details><summary>Source ↔ package comparison</summary><div>${evidence(d.sourceArtifactComparison)}</div></details><details><summary>Sigmascope lineage and dependency drift</summary><div><h4>Lineage</h4>${evidence(d.lineage)}<h4>Drift</h4>${evidence(d.drift)}</div></details><details><summary>Client marketplace projection</summary><div>${m?evidence(m):'<span class=muted>Marketplace database not loaded.</span>'}</div></details><details><summary>Managed calls (lazy)</summary><div><input id="callQuery" placeholder="Filter target type/method/native library"><button id="loadCallsButton">Load calls</button><div id="callsOutput"></div></div></details>`;if(d.lazyDatasets){$('pluginDetail').querySelectorAll('[data-lazy-dataset]').forEach(node=>{let loaded=false;const load=()=>{if(loaded)return;loaded=true;loadDataset(id,node.dataset.lazyDataset,node.querySelector('[data-lazy-body]'))};node.addEventListener('toggle',()=>{if(node.open)load()});if(node.open)load()})}const b=$('loadCallsButton');if(b)b.addEventListener('click',()=>loadCalls(id))}
async function loadCalls(id){const q=$('callQuery')?.value||'';const rows=await api('/api/calls?variant_id='+id+'&q='+encodeURIComponent(q));$('callsOutput').innerHTML=`<div class=muted>${rows.length} rows</div>`+evidence(rows)}
async function runAudit(){$('detailTitle').textContent='Global consistency audit';$('detailMeta').textContent='running…';$('pluginDetail').innerHTML='<span class=muted>Recomputing current conclusions…</span>';try{const a=await api('/api/audit');$('detailMeta').textContent=`${a.counts.fail} fail · ${a.counts.warn} warn`;$('pluginDetail').innerHTML=`<div class=cards><div class=card><div class="n fail">${a.counts.fail}</div><div class=muted>Failures</div></div><div class=card><div class="n warn">${a.counts.warn}</div><div class=muted>Warnings</div></div><div class=card><div class="n pass">${a.counts.pass}</div><div class=muted>Passed global checks</div></div></div>`+a.items.map(x=>`<div class="auditrow ${x.status}"><b>${esc(x.status.toUpperCase())} · ${esc(x.title)}</b><div class=small>${esc(x.code)} ${x.plugin?'· '+esc(x.plugin):''}</div><div class=muted>${esc(x.detail)}</div></div>`).join('')}catch(e){$('pluginDetail').innerHTML=`<span class=fail>${esc(e.message)}</span>`}}
function renderTableList(){const needle=$('tableSearch').value.trim().toLowerCase();let last='';$('tableList').innerHTML=tables.map((t,i)=>({t,i})).filter(x=>!needle||x.t.name.toLowerCase().includes(needle)||x.t.label.toLowerCase().includes(needle)||x.t.category.toLowerCase().includes(needle)).map(({t,i})=>{let h='';if(t.category!==last){last=t.category;h=`<div class=table-group>${esc(t.category)}</div>`}return h+`<button class="table-button ${currentTable?.name===t.name?'active':''}" data-table-index="${i}">${esc(t.label)}<div class="muted small">${esc(t.name)} · ${t.columnCount} columns</div></button>`}).join('');$('tableList').querySelectorAll('[data-table-index]').forEach(x=>x.addEventListener('click',()=>openTable(tables[Number(x.dataset.tableIndex)].name)))}
async function openTable(name,filterColumn='',filterValue='',offset=0){const params=new URLSearchParams({name,limit:'100',offset:String(offset)});if(filterColumn){params.set('column',filterColumn);params.set('value',String(filterValue))}currentTable=await api('/api/table?'+params.toString());currentRows=currentTable.rows;currentFkLinks=[];$('tableTitle').textContent=currentTable.label;$('tableSubtitle').textContent=`${currentTable.name} · rows ${currentTable.offset+1}–${currentTable.offset+currentRows.length}${currentTable.hasMore?' · more available':''}`;$('tablePrev').disabled=currentTable.offset<=0;$('tableNext').disabled=!currentTable.hasMore;$('rowTitle').textContent='Row inspector';$('rowDetail').innerHTML='<span class=muted>Click a row to inspect every field and follow database relationships.</span>';renderTableList();renderTableFilter();renderTableGrid();$('tableTitle').scrollIntoView({behavior:'smooth',block:'nearest'})}
function renderTableFilter(){if(!currentTable?.filter){$('tableFilterBar').style.display='none';$('tableFilterBar').innerHTML='';return}$('tableFilterBar').style.display='block';$('tableFilterBar').innerHTML=`<span class=table-filter><span class=pill>${esc(currentTable.filter.column)} = ${esc(currentTable.filter.value)}</span><button id="clearTableFilter">Clear filter</button></span>`;$('clearTableFilter').addEventListener('click',()=>openTable(currentTable.name))}
function renderTableGrid(){if(!currentTable)return;const cols=currentTable.columns.map(c=>c.name);if(!currentRows.length){$('tableGrid').innerHTML='<div class=empty>No rows in this page.</div>';return}$('tableGrid').innerHTML=`<table><thead><tr>${cols.map(c=>`<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${currentRows.map((r,i)=>`<tr class=click data-row-index="${i}">${cols.map(c=>`<td title="${esc(r[c])}">${esc(formatCell(r[c]))}</td>`).join('')}</tr>`).join('')}</tbody></table>`;$('tableGrid').querySelectorAll('[data-row-index]').forEach(x=>x.addEventListener('click',()=>inspectRow(Number(x.dataset.rowIndex))))}
function formatCell(v){if(v==null)return'';const s=typeof v==='object'?JSON.stringify(v):String(v);return s.length>180?s.slice(0,177)+'…':s}
function inspectRow(index){const row=currentRows[index];if(!row)return;const fkMap={};(currentTable.foreignKeys||[]).forEach(f=>{fkMap[f.from]=f});currentFkLinks=[];const variant=Number(row.variant_id||row.source_variant_id||0);const top=variant?`<button id="openRowPlugin">Open plugin variant ${variant}</button>`:'';const body=Object.entries(row).map(([k,v])=>{const fk=fkMap[k];if(fk&&v!=null){const linkIndex=currentFkLinks.push({table:fk.table,column:fk.to,value:v})-1;return `<b>${esc(k)}</b><span><button class=linkbutton data-fk-link="${linkIndex}">${esc(formatCell(v))} → ${esc(fk.table)}.${esc(fk.to)}</button></span>`}return `<b>${esc(k)}</b><span>${looksJson(v)?evidenceJsonInline(v):esc(formatCell(v))}</span>`}).join('');$('rowTitle').textContent=`${currentTable.label} · row ${currentTable.offset+index+1}`;$('rowDetail').innerHTML=top+`<div class=kv>${body}</div>`;$('rowDetail').querySelectorAll('[data-fk-link]').forEach(x=>x.addEventListener('click',()=>{const f=currentFkLinks[Number(x.dataset.fkLink)];openTable(f.table,f.column,f.value)}));const b=$('openRowPlugin');if(b)b.addEventListener('click',()=>loadDetail(variant))}
function looksJson(v){if(typeof v!=='string')return false;const s=v.trim();return (s.startsWith('{')&&s.endsWith('}'))||(s.startsWith('[')&&s.endsWith(']'))}
function evidenceJsonInline(v){try{return `<span class=code style="display:block;max-height:180px">${esc(JSON.stringify(JSON.parse(v),null,2))}</span>`}catch{return esc(formatCell(v))}}
async function runSql(){try{const r=await api('/api/sql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:$('sqlText').value})});$('sqlOutput').innerHTML=`<table><thead><tr>${r.columns.map(c=>`<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${r.rows.map(row=>`<tr>${row.map(v=>`<td>${esc(typeof v==='object'?JSON.stringify(v):v)}</td>`).join('')}</tr>`).join('')}</tbody></table>`}catch(e){$('sqlOutput').innerHTML=`<span class=fail>${esc(e.message)}</span>`}}
$('pluginQuery').addEventListener('input',debouncedLoad);$('severityFilter').addEventListener('change',loadPlugins);$('scanStatusFilter').addEventListener('change',loadPlugins);$('knownRiskFilter').addEventListener('change',loadPlugins);$('refreshPlugins').addEventListener('click',loadPlugins);$('refreshEvidence').addEventListener('click',refreshEvidence);$('auditButton').addEventListener('click',runAudit);$('tableSearch').addEventListener('input',renderTableList);$('tablePrev').addEventListener('click',()=>currentTable&&openTable(currentTable.name,currentTable.filter?.column||'',currentTable.filter?.value||'',Math.max(0,currentTable.offset-currentTable.limit)));$('tableNext').addEventListener('click',()=>currentTable&&openTable(currentTable.name,currentTable.filter?.column||'',currentTable.filter?.value||'',currentTable.offset+currentTable.limit));$('runSqlButton').addEventListener('click',runSql);
init().then(()=>setInterval(checkEvidenceRevision,60000)).catch(e=>{document.body.innerHTML='<pre class=fail>'+esc(e.stack||e.message)+'</pre>'});
</script></body></html>'''


class AppHandler(BaseHTTPRequestHandler):
    inspector: Any
    server_version = "OmegaSigmascopeDeveloperView/2.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}", file=sys.stderr)

    def json_response(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            if parsed.path == "/":
                body = HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path == "/api/summary":
                return self.json_response(self.inspector.summary())
            if parsed.path == "/api/source":
                if hasattr(self.inspector, "source_status"):
                    return self.json_response(self.inspector.source_status(check_remote=(query.get("check") or ["0"])[0] == "1"))
                return self.json_response({"mode": "sqlite", "baseUrl": "", "currentRevision": "", "remoteRevision": "", "updateAvailable": False, "error": ""})
            if parsed.path == "/api/tables":
                return self.json_response(self.inspector.table_catalog())
            if parsed.path == "/api/table":
                return self.json_response(self.inspector.browse_table(
                    (query.get("name") or [""])[0],
                    limit=int((query.get("limit") or ["100"])[0]),
                    offset=int((query.get("offset") or ["0"])[0]),
                    filter_column=(query.get("column") or [""])[0],
                    filter_value=(query.get("value") or [""])[0],
                ))
            if parsed.path == "/api/plugins":
                rows = self.inspector.list_plugins(
                    q=(query.get("q") or [""])[0], severity=(query.get("severity") or [""])[0],
                    status=(query.get("status") or [""])[0], known_risk=(query.get("known_risk") or ["0"])[0] == "1",
                    limit=int((query.get("limit") or ["300"])[0]), offset=int((query.get("offset") or ["0"])[0]),
                )
                return self.json_response(rows)
            if parsed.path == "/api/plugin":
                return self.json_response(self.inspector.plugin_detail(int((query.get("variant_id") or ["0"])[0])))
            if parsed.path == "/api/dataset":
                variant_id = int((query.get("variant_id") or ["0"])[0])
                name = (query.get("name") or [""])[0]
                if hasattr(self.inspector, "plugin_dataset"):
                    return self.json_response(self.inspector.plugin_dataset(variant_id, name))
                detail = self.inspector.plugin_detail(variant_id)
                if name not in {"findings", "dependencies", "ipc", "permissions", "automation"}:
                    raise ValueError(f"unknown plugin dataset {name!r}")
                return self.json_response(detail.get(name) or [])
            if parsed.path == "/api/audit":
                return self.json_response(self.inspector.global_audit())
            if parsed.path == "/api/calls":
                return self.json_response(self.inspector.managed_calls(int((query.get("variant_id") or ["0"])[0]), (query.get("q") or [""])[0]))
            return self.json_response({"error": "not found"}, 404)
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)

    def do_POST(self) -> None:  # noqa: N802
        try:
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/refresh":
                if not hasattr(self.inspector, "refresh_online"):
                    return self.json_response({"error": "the current evidence source is not refreshable online"}, 400)
                return self.json_response(self.inspector.refresh_online())
            if path != "/api/sql":
                return self.json_response({"error": "not found"}, 404)
            length = min(int(self.headers.get("Content-Length") or 0), 1024 * 1024)
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            return self.json_response(self.inspector.read_sql(str(payload.get("query") or "")))
        except (ValueError, sqlite3.DatabaseError) as exc:
            return self.json_response({"error": str(exc)}, 400)
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)


def serve(inspector: Any, host: str, port: int, open_browser: bool) -> int:
    handler = type("BoundAppHandler", (AppHandler,), {"inspector": inspector})
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{server.server_address[1]}/"
    print(f"Omega Security Developer View: {url}", file=sys.stderr)
    print(f"Evidence source: {inspector.evidence_path}", file=sys.stderr)
    print("Press Ctrl+C to stop.", file=sys.stderr)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.", file=sys.stderr)
    finally:
        server.server_close()
        inspector.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Browse Omega Sigmascope evidence read-only. Published Evidence v2 is streamed lazily from GitHub by default.")
    parser.add_argument("command", nargs="?", choices=["fetch", "serve", "serve-online", "audit"], default="serve")
    parser.add_argument("--database", type=Path, help="Local omega-security-evidence.sqlite; uses legacy/local SQLite view.")
    parser.add_argument("--evidence-v2", type=Path, help="Local Security Evidence v2 JSON directory; opens it directly without publication or download.")
    parser.add_argument("--online-base-url", default=DEFAULT_ONLINE_BASE_URL, help="Published Evidence v2 raw HTTPS root. Default: dalagab/omega security-evidence-v2 branch.")
    parser.add_argument("--marketplace-database", type=Path, help="Optional local omega-marketplace.sqlite for projection comparison.")
    parser.add_argument("--cache-dir", type=Path, default=default_cache_dir())
    parser.add_argument("--online-cache-mb", type=int, default=DEFAULT_REMOTE_CACHE_BYTES // (1024 * 1024), help="Bounded on-demand Evidence v2 HTTP cache size in MiB.")
    parser.add_argument("--no-download", action="store_true", help="For local/legacy operation, do not download release databases.")
    parser.add_argument("--no-marketplace", action="store_true", help="Do not download/use the small marketplace DB for conclusion comparison.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address. Default is localhost only.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Local web UI port; use 0 for an automatic port.")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit audit result as JSON.")
    parser.add_argument("--strict-warnings", action="store_true", help="Audit exits non-zero for warnings as well as failures.")
    return parser


def resolve_databases(args: argparse.Namespace) -> tuple[Path, Path | None]:
    if args.database:
        return args.database.resolve(), args.marketplace_database.resolve() if args.marketplace_database else None
    if args.no_download:
        raise RuntimeError("--database is required with --no-download")
    return fetch_latest(args.cache_dir.resolve(), include_marketplace=not args.no_marketplace)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.evidence_v2 and args.database:
            raise ValueError("choose either --database or --evidence-v2, not both")
        if args.command == "fetch":
            if args.evidence_v2:
                raise ValueError("fetch is not available for a local --evidence-v2 directory")
            evidence, marketplace = fetch_latest(args.cache_dir.resolve(), include_marketplace=not args.no_marketplace)
            print(json.dumps({"evidence": str(evidence), "marketplace": str(marketplace) if marketplace else None}, indent=2))
            return 0

        use_online = args.command == "serve-online" or (args.command == "serve" and not args.database and not args.evidence_v2 and not args.no_download)
        if args.command == "serve-online" and (args.database or args.evidence_v2):
            raise ValueError("serve-online cannot be combined with --database or --evidence-v2")
        if use_online:
            inspector = V2SigmascopeInspector.online(
                base_url=args.online_base_url,
                cache_dir=args.cache_dir.resolve() / "evidence-v2-http",
                cache_limit_bytes=max(8, args.online_cache_mb) * 1024 * 1024,
            )
        elif args.evidence_v2:
            inspector = V2SigmascopeInspector(args.evidence_v2)
        else:
            evidence, marketplace = resolve_databases(args)
            inspector = SecurityInspector(evidence, marketplace)

        if args.command == "audit":
            result = inspector.global_audit()
            inspector.close()
            if args.json:
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print(f"Omega security audit: {result['counts']['fail']} fail, {result['counts']['warn']} warn, {result['counts']['pass']} pass")
                for item in result["items"]:
                    if item["status"] in {"fail", "warn"}:
                        identity = f" [{item['plugin']}]" if item.get("plugin") else ""
                        print(f"{item['status'].upper():4} {item['code']}{identity}: {item['title']} — {item['detail']}")
            return 1 if result["counts"]["fail"] or (args.strict_warnings and result["counts"]["warn"]) else 0
        return serve(inspector, args.host, args.port, not args.no_browser)
    except (RuntimeError, OSError, ValueError, sqlite3.DatabaseError, urllib.error.URLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

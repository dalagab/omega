#!/usr/bin/env python3
"""DeltaScope: Omega security investigation and Stigma-1 / SRL Core developer workbench.

Published Omega security evidence, Definitions and scanner state are always inspected read-only.
The Rules workspace additionally supports versioned local SRL authoring under the user home;
those files have no production, repository, queue or Evidence-v2 write-back authority.

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
Local My Rules are the sole intentional DeltaScope filesystem mutation surface.
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
import traceback
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile
from typing import Any, Iterable

import yaml

from evidence_v2_inspector import DEFAULT_ONLINE_BASE_URL, DEFAULT_REMOTE_CACHE_BYTES, V2SigmascopeInspector
from rule_author_reference import build_reference as build_rule_author_reference
import observation_projection
import definition_packs
import stigma1 as srl
import srl_evidence_replay
import srl_migration_parity
import rule_lab
import rule_reprojection
import deltascope_workbench
import deltascope_rule_store
import deltascope_operations
import deltascope_collectors
import deltascope_docs

CATALOG_MODULE_ROOT = Path(__file__).resolve().parents[1] / "catalog"
if str(CATALOG_MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(CATALOG_MODULE_ROOT))
import plugin_profile

REPOSITORY = "dalagab/omega"
EVIDENCE_TAG = "security-evidence-latest"
MARKETPLACE_TAG = "catalog-latest"
EVIDENCE_ASSET = "omega-security-evidence.sqlite.zip"
MARKETPLACE_ASSET = "omega-marketplace.sqlite.zip"
GITHUB_API = "https://api.github.com"
USER_AGENT = "Omega-Security-Developer-View/1.0"
DEFAULT_PORT = 8765
PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOCAL_DEFINITION_PACKS_ROOT = PROJECT_ROOT / "security-definitions" / "packs"
LOCAL_DEFINITION_LIBRARY_SCHEMA = "omega.deltascope.definition-library.v1"
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


def local_definition_library(packs_root: Path | None = None) -> dict[str, Any]:
    """Build a bounded read-only browser over repository Definition Pack source.

    This is intentionally separate from the published/frozen active-rule provenance.  It lets
    authors inspect and learn from the source-controlled packs that ship with the checkout even
    when the currently opened Evidence-v2 snapshot predates the provenance sidecar.  Nothing in
    this payload is activation state or a production policy input.
    """
    root = (packs_root or LOCAL_DEFINITION_PACKS_ROOT).resolve()
    if not root.exists() or not root.is_dir():
        return {
            "schema": LOCAL_DEFINITION_LIBRARY_SCHEMA,
            "available": False, "readOnly": True, "mutationAuthority": "none",
            "policyInput": False, "sourceAuthority": "repository-source-only",
            "sourceRoot": "security-definitions/packs", "packs": [],
            "packCount": 0, "ruleCount": 0, "fixtureCount": 0,
        }

    # Validate the whole source set first so duplicate rule/fact ownership and cross-pack
    # invariants fail closed before anything is presented as a useful authoring example.
    definition_packs.compile_pack_root(root, include_local=True)
    packs: list[dict[str, Any]] = []
    rule_count = 0
    fixture_count = 0
    for manifest_path in definition_packs.discover_pack_manifests(root, include_local=True):
        manifest = srl.load_yaml(manifest_path)
        if not isinstance(manifest, dict):
            continue
        pack_id = str(manifest.get("id") or manifest_path.parent.name)
        compiled = definition_packs.compile_pack(manifest_path, include_local=True)
        if not compiled:
            continue
        pack_root = manifest_path.parent.resolve()
        compiled_rules = {str(item.get("id") or ""): dict(item) for item in compiled.get("compiledRuleSet", {}).get("rules") or []}
        rule_files: list[dict[str, Any]] = []
        rules: list[dict[str, Any]] = []
        for file_entry in manifest.get("rules") or []:
            if not isinstance(file_entry, dict):
                continue
            rel = str(file_entry.get("path") or "").replace("\\", "/")
            source_path = (pack_root / rel).resolve()
            if pack_root not in source_path.parents or not source_path.is_file():
                continue
            source_text = source_path.read_text(encoding="utf-8")
            document = srl.load_yaml(source_path)
            if isinstance(document, dict) and document.get("schema") == srl.RULE_SCHEMA:
                raw_rules = [document]
            elif isinstance(document, dict) and document.get("schema") == srl.RULESET_SCHEMA and isinstance(document.get("rules"), list):
                raw_rules = [item for item in document.get("rules") or [] if isinstance(item, dict)]
            elif isinstance(document, list):
                raw_rules = [item for item in document if isinstance(item, dict)]
            else:
                raw_rules = []
            source_label = f"security-definitions/packs/{pack_id}/{rel}"
            ids: list[str] = []
            for raw_rule in raw_rules:
                rule_id = str(raw_rule.get("id") or "")
                if not rule_id:
                    continue
                ids.append(rule_id)
                compiled_rule = compiled_rules.get(rule_id, {})
                emit = raw_rule.get("emit") if isinstance(raw_rule.get("emit"), dict) else {}
                output = str(emit.get("findingId") or emit.get("fact") or "")
                candidate_yaml = yaml.safe_dump(
                    raw_rule, sort_keys=False, allow_unicode=True, default_flow_style=False, width=120
                ).strip() + "\n"
                rules.append({
                    "ruleId": rule_id,
                    "kind": str(raw_rule.get("kind") or compiled_rule.get("kind") or ""),
                    "status": str(raw_rule.get("status") or compiled_rule.get("status") or ""),
                    "requires": list(raw_rule.get("requires") or []),
                    "output": output,
                    "title": str(emit.get("title") or rule_id),
                    "description": str(emit.get("description") or ""),
                    "category": str(emit.get("category") or ""),
                    "severity": str(emit.get("severity") or ""),
                    "confidence": str(emit.get("confidence") or ""),
                    "selectors": raw_rule.get("selectors") if isinstance(raw_rule.get("selectors"), dict) else {},
                    "condition": raw_rule.get("condition"),
                    "emit": emit,
                    "ruleRevision": str(compiled_rule.get("ruleRevision") or ""),
                    "sourcePath": source_label,
                    "sourceFile": rel,
                    "candidateYaml": candidate_yaml,
                    "compiled": compiled_rule,
                })
            rule_files.append({
                "path": rel, "sourcePath": source_label, "ruleIds": ids, "sourceText": source_text,
            })

        fixtures: list[dict[str, Any]] = []
        compiled_fixtures = {str(item.get("path") or ""): item for item in compiled.get("fixtures") or []}
        for fixture_entry in manifest.get("fixtures") or []:
            rel = str(fixture_entry.get("path") if isinstance(fixture_entry, dict) else fixture_entry or "").replace("\\", "/")
            source_path = (pack_root / rel).resolve()
            if not rel or pack_root not in source_path.parents or not source_path.is_file():
                continue
            frozen = compiled_fixtures.get(rel, {})
            fixtures.append({
                "path": rel,
                "sourcePath": f"security-definitions/packs/{pack_id}/{rel}",
                "name": str(frozen.get("name") or rel),
                "passed": bool(frozen.get("passed")),
                "sourceText": source_path.read_text(encoding="utf-8"),
            })

        compiled_meta = compiled.get("metadata") if isinstance(compiled.get("metadata"), dict) else {}
        pack_review = compiled_meta.get("review") if isinstance(compiled_meta.get("review"), dict) else {}
        packs.append({
            "packId": pack_id,
            "title": str(manifest.get("title") or pack_id),
            "description": str(manifest.get("description") or ""),
            "trustTier": str(manifest.get("trustTier") or ""),
            "productionEligible": bool(compiled.get("productionEligible")),
            "packRevision": str(compiled.get("packRevision") or ""),
            "compiledRuleSetRevision": str(compiled.get("compiledRuleSetRevision") or ""),
            "review": dict(pack_review),
            "provenance": dict(compiled_meta.get("provenance") or {}) if isinstance(compiled_meta.get("provenance"), dict) else {},
            "license": str(compiled_meta.get("license") or ""),
            "manifestPath": f"security-definitions/packs/{pack_id}/pack.yaml",
            "manifestSource": manifest_path.read_text(encoding="utf-8"),
            "rules": sorted(rules, key=lambda item: item["ruleId"]),
            "ruleFiles": rule_files,
            "fixtures": sorted(fixtures, key=lambda item: item["path"]),
        })
        rule_count += len(rules)
        fixture_count += len(fixtures)

    packs.sort(key=lambda item: item["packId"])
    semantic = {
        "sourceAuthority": "repository-source-only",
        "sourceRoot": "security-definitions/packs",
        "packs": packs,
        "packCount": len(packs),
        "ruleCount": rule_count,
        "fixtureCount": fixture_count,
    }
    revision = hashlib.sha256(json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")).hexdigest()[:24]
    return {
        "schema": LOCAL_DEFINITION_LIBRARY_SCHEMA,
        "available": True, "readOnly": True, "mutationAuthority": "none",
        "policyInput": False, "libraryRevision": f"definition-library-v1-{revision}",
        **semantic,
    }


def rule_workspace_library(rule_store: deltascope_rule_store.LocalRuleStore, packs_root: Path | None = None) -> dict[str, Any]:
    """Combine repository rules and versioned local authoring rules for DeltaScope's tree.

    Repository Definitions remain read-only. The local store is explicitly non-production and
    lives outside the checkout, so editing/forking cannot mutate frozen Definitions by accident.
    """
    system = local_definition_library(packs_root)
    local = rule_store.list_rules()
    return {
        "schema": "omega.deltascope.rule-workspace-library.v1",
        "system": system,
        "local": local,
        "counts": {
            "systemRules": int(system.get("ruleCount") or 0),
            "systemPacks": int(system.get("packCount") or 0),
            "localRules": int(local.get("ruleCount") or 0),
        },
        "stigma1": srl.engine_reference(),
        "srlCore": {**srl.engine_reference(), "compatibilityAlias": True},
        "productionWriteBack": False,
        "repositoryWriteBack": False,
    }


@dataclass
class AuditItem:
    status: str
    code: str
    title: str
    detail: str
    plugin: str = ""
    variant_id: int | None = None


class SecurityInspector:
    def __init__(
        self,
        evidence_path: Path,
        marketplace_path: Path | None = None,
        advisory_coverage_path: Path | None = None,
    ):
        self.evidence_path = evidence_path.resolve()
        self.marketplace_path = marketplace_path.resolve() if marketplace_path else None
        self.advisory_coverage_path = advisory_coverage_path.resolve() if advisory_coverage_path else None
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
                # Headline finding totals are a statement about the current active plugin
                # surface, not the immutable archive. Older scan rows remain queryable but
                # must never keep a retired HIGH/CRITICAL alive on the dashboard.
                "findings": scalar("SELECT COUNT(*) FROM plugin_security_findings f JOIN plugin_security_current c ON c.scan_id=f.scan_id") if {"plugin_security_findings", "plugin_security_current"}.issubset(self.tables) else 0,
                "criticalFindings": scalar("SELECT COUNT(*) FROM plugin_security_findings f JOIN plugin_security_current c ON c.scan_id=f.scan_id WHERE lower(f.severity)='critical'") if {"plugin_security_findings", "plugin_security_current"}.issubset(self.tables) else 0,
                "highFindings": scalar("SELECT COUNT(*) FROM plugin_security_findings f JOIN plugin_security_current c ON c.scan_id=f.scan_id WHERE lower(f.severity)='high'") if {"plugin_security_findings", "plugin_security_current"}.issubset(self.tables) else 0,
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
        limit = min(max(1, limit), 2000)
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

    def latest_findings(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return newest current finding rows with enough identity for incident triage."""
        limit = min(max(1, int(limit or 20)), 100)
        if not {"plugin_security_current", "plugin_security_findings", "plugin_variants", "plugins", "sources"}.issubset(self.tables):
            return []
        sql = """
            SELECT f.*,sc.scanned_at_utc,sc.scan_id,v.variant_id,p.internal_name,p.canonical_name,
                   v.name AS variant_name,v.author,v.assembly_version,s.name AS source_name,s.url AS source_url
              FROM plugin_security_findings f
              JOIN plugin_security_current sc ON sc.scan_id=f.scan_id
              JOIN plugin_variants v ON v.variant_id=sc.variant_id
              JOIN plugins p ON p.plugin_id=v.plugin_id
              JOIN sources s ON s.source_id=v.source_id
             WHERE v.active=1
             ORDER BY sc.scanned_at_utc DESC,
                      CASE lower(COALESCE(f.severity,'none')) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'caution' THEN 2 WHEN 'moderate' THEN 2 WHEN 'informational' THEN 1 ELSE 0 END DESC,
                      f.finding_id
             LIMIT ?
        """
        with self.lock:
            raw = [dict(row) for row in self.db.execute(sql, (limit,)).fetchall()]
        rows: list[dict[str, Any]] = []
        for row in raw:
            rows.append({
                "variantId": int(row.get("variant_id") or 0),
                "scanId": int(row.get("scan_id") or 0),
                "plugin": str(row.get("canonical_name") or row.get("variant_name") or row.get("internal_name") or ""),
                "internalName": str(row.get("internal_name") or ""),
                "version": str(row.get("assembly_version") or ""),
                "sourceName": str(row.get("source_name") or ""),
                "occurredAtUtc": str(row.get("scanned_at_utc") or ""),
                "findingRowId": int(row.get("finding_id") or 0),
                "findingId": str(row.get("rule_id") or row.get("ruleId") or row.get("finding_id") or ""),
                "ruleId": str(row.get("rule_id") or row.get("ruleId") or ""),
                "title": str(row.get("title") or row.get("finding_id") or row.get("findingId") or "Security finding"),
                "category": str(row.get("category") or ""),
                "severity": str(row.get("severity") or "none").casefold(),
                "readOnly": True,
            })
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

    def version_history(self, variant_id: int) -> list[dict[str, Any]]:
        """Return current plus older immutable scans for one active catalog variant."""
        if "plugin_security_scans" not in self.tables:
            return []
        current_scan_id = 0
        if "plugin_security_current" in self.tables:
            row = self.db.execute("SELECT scan_id FROM plugin_security_current WHERE variant_id=?", (variant_id,)).fetchone()
            current_scan_id = int(row[0] or 0) if row else 0
        rows = self.db.execute(
            """SELECT scan_id,assembly_version,artifact_sha256,scanned_at_utc,highest_severity,
                      informational_count,caution_count,high_count,critical_count,status
                 FROM plugin_security_scans
                WHERE variant_id=?
                ORDER BY scan_id DESC""",
            (variant_id,),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            scan_id = int(item.get("scan_id") or 0)
            is_current = scan_id == current_scan_id and current_scan_id > 0
            result.append({
                "snapshotKind": "current" if is_current else "superseded",
                "isCurrent": is_current,
                "variantId": int(variant_id),
                "scanId": scan_id,
                "version": str(item.get("assembly_version") or ""),
                "scannedAtUtc": str(item.get("scanned_at_utc") or ""),
                "highestSeverity": str(item.get("highest_severity") or "none").casefold(),
                "findingCount": sum(int(item.get(key) or 0) for key in ("informational_count", "caution_count", "high_count", "critical_count")),
                "criticalCount": int(item.get("critical_count") or 0),
                "highCount": int(item.get("high_count") or 0),
                "artifactSha256": str(item.get("artifact_sha256") or ""),
                "variantPath": "",
                "status": str(item.get("status") or ""),
                "includedInCurrentTotals": is_current,
            })
        result.sort(key=lambda row: (not bool(row.get("isCurrent")), -int(row.get("scanId") or 0)))
        return result

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
                "versionHistory": self.version_history(variant_id),
                "currentTotalsOnly": True,
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
            if self.advisory_coverage_path is not None:
                try:
                    coverage_doc = json.loads(self.advisory_coverage_path.read_text(encoding="utf-8-sig"))
                    if not isinstance(coverage_doc, dict) or coverage_doc.get("schema") != "omega.public-advisories.v1":
                        raise ValueError("unsupported frozen advisory coverage schema")
                    declared_queries = max(0, int(coverage_doc.get("queriedPackages") or 0))
                    frozen_pairs = {
                        (str(row.get("name") or "").strip().casefold(), str(row.get("version") or "").strip())
                        for row in (coverage_doc.get("queriedPackageVersionPairs") or [])
                        if isinstance(row, dict) and str(row.get("name") or "").strip() and str(row.get("version") or "").strip()
                    }
                    if declared_queries != len(frozen_pairs):
                        items.append(AuditItem(
                            "fail", "osv.coverage.metadata", "Frozen OSV query universe is internally inconsistent",
                            f"declaredQueries={declared_queries}, exactQueryPairs={len(frozen_pairs)}",
                        ))
                    elif coverage_present and queried_nuget != declared_queries:
                        items.append(AuditItem(
                            "fail", "osv.coverage.projection", "Working security projection disagrees with frozen OSV coverage",
                            f"databaseQueriedPackages={queried_nuget}, frozenDeclaredQueries={declared_queries}",
                        ))
                    else:
                        observed_pairs = {
                            (str(row[0] or "").strip().casefold(), str(row[1] or "").strip())
                            for row in self.db.execute(
                                """SELECT lower(TRIM(d.name)),COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))
                                     FROM plugin_security_dependencies d
                                     JOIN plugin_security_current c ON c.scan_id=d.scan_id
                                    WHERE c.status='complete' AND lower(d.kind) IN ('nuget','nuget-lock','nuget-resolved')
                                      AND TRIM(d.name)<>''
                                      AND COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))<>''
                                    GROUP BY 1,2"""
                            )
                        } if {"plugin_security_dependencies", "plugin_security_current"}.issubset(self.tables) else set()
                        covered_pairs = observed_pairs & frozen_pairs
                        uncovered_pairs = observed_pairs - frozen_pairs
                        items.append(AuditItem(
                            "pass", "osv.coverage.queries", "Frozen OSV query universe is internally consistent",
                            f"observedNugetVersions={len(observed_pairs)}, frozenQueries={declared_queries}, currentlyCovered={len(covered_pairs)}",
                        ))
                        if uncovered_pairs:
                            items.append(AuditItem(
                                "warn", "osv.coverage.frozen_gap", "New NuGet versions await the next Definitions refresh",
                                f"notCoveredByFrozenDefinitions={len(uncovered_pairs)}; no live mid-day OSV query is permitted",
                            ))
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    items.append(AuditItem(
                        "fail", "osv.coverage.metadata", "Frozen OSV coverage could not be verified",
                        f"{type(exc).__name__}: {exc}",
                    ))
            elif observed_nuget and not coverage_present:
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


def developer_profile_validate_text(text: str) -> dict[str, Any]:
    """Validate a browser-authored developer profile without mutating repository state."""
    raw = str(text or "").encode("utf-8")
    observation = plugin_profile.validate_profile_bytes(raw, path=plugin_profile.PROFILE_PATH)
    return {
        "schema": "omega.deltascope.developer-profile-validation.v1",
        "ok": bool(observation.get("valid")),
        "validation": observation,
        "readOnly": True,
        "mutationAuthority": "none",
    }


def developer_profile_render(document: dict[str, Any]) -> dict[str, Any]:
    """Render and validate .omega/plugin.yaml from structured browser fields."""
    if not isinstance(document, dict):
        raise ValueError("profile must be an object")
    candidate = dict(document)
    candidate["schema"] = plugin_profile.PROFILE_SCHEMA
    ordered: dict[str, Any] = {"schema": plugin_profile.PROFILE_SCHEMA}
    for key in ("profile", "capabilities", "services", "nativeComponents", "ipc", "media"):
        value = candidate.get(key)
        if value not in (None, "", [], {}):
            ordered[key] = value
    rendered = yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True, default_flow_style=False)
    observation = plugin_profile.validate_profile_bytes(rendered.encode("utf-8"), path=plugin_profile.PROFILE_PATH)
    return {
        "schema": "omega.deltascope.developer-profile-preview.v1",
        "ok": bool(observation.get("valid")),
        "yaml": rendered,
        "validation": observation,
        "readOnly": True,
        "mutationAuthority": "browser-copy-download-only",
        "note": "Developer context never suppresses or downgrades independent SigmaScope evidence.",
    }


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Omega DeltaScope · Security Research Workbench</title>
<style>
:root{color-scheme:dark;--bg:#090c0f;--panel:#0f1419;--panel2:#141b22;--line:#27323c;--text:#eef4f7;--muted:#8fa1ad;--cyan:#36d5d0;--red:#ff5e62;--amber:#ffbf4d;--green:#55d98d;--blue:#68a7ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 Inter,Segoe UI,Arial,sans-serif}button,input,select,textarea{font:inherit;color:inherit;background:#111820;border:1px solid var(--line);border-radius:7px;padding:8px 10px}button{cursor:pointer}button:hover{border-color:var(--cyan)}a{color:var(--cyan)}
header{position:sticky;top:0;z-index:10;background:rgba(9,12,15,.96);border-bottom:1px solid var(--line);padding:14px 18px;display:flex;align-items:center;gap:12px}.logo{font-weight:800;letter-spacing:.08em}.badge{padding:3px 7px;border-radius:999px;background:#162028;color:var(--muted);font-size:12px}.badge.ro{color:var(--green)}main{padding:18px;max-width:1900px;margin:auto}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px}.card{padding:12px}.card.clickable{cursor:pointer}.card.clickable:hover{border-color:var(--cyan);background:#111a20}.card .n{font-size:24px;font-weight:700}.muted{color:var(--muted)}.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:14px 0}.toolbar input{min-width:280px;flex:1}.toolbar input[type=checkbox]{min-width:auto;width:auto;flex:0 0 auto;margin:0}.toolbar label{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}.split{display:grid;grid-template-columns:minmax(500px,1.05fr) minmax(520px,1.4fr);gap:14px;align-items:start}.panel{overflow:hidden}.panel h2,.panel h3{margin:0}.panelhead{padding:11px 13px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:10px}.scroll{overflow:auto;max-height:68vh}table{width:100%;border-collapse:collapse}th,td{padding:8px 9px;border-bottom:1px solid #1c252d;text-align:left;vertical-align:top}th{position:sticky;top:0;background:#131a20;color:#aebbc3;font-size:12px;z-index:1}tr.click:hover{background:#142028;cursor:pointer}.sev-critical{color:var(--red);font-weight:700}.sev-high{color:#ff866b;font-weight:700}.sev-caution,.sev-medium{color:var(--amber)}.sev-informational{color:var(--blue)}.sev-none{color:var(--muted)}.pass{color:var(--green)}.warn{color:var(--amber)}.fail{color:var(--red)}.info{color:var(--blue)}
.detail{padding:13px}.kv{display:grid;grid-template-columns:190px minmax(0,1fr);gap:5px 10px;margin:8px 0}.kv b{color:#aebbc3}.kv span{word-break:break-word}.section{border-top:1px solid var(--line);padding:12px 0}.section:first-child{border-top:0;padding-top:0}details{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:#0c1116}summary{cursor:pointer;padding:9px 11px;font-weight:600}details>div{padding:0 11px 11px}.finding{padding:9px;border:1px solid #28333c;border-radius:7px;margin:7px 0;background:#11171c}.finding h4{margin:0 0 4px}.pill{display:inline-block;padding:2px 7px;border:1px solid var(--line);border-radius:999px;margin:2px;font-size:12px}.code{font:12px/1.4 Consolas,monospace;white-space:pre-wrap;word-break:break-word;background:#080b0e;padding:8px;border-radius:6px;max-height:320px;overflow:auto}.auditrow{padding:7px 0;border-bottom:1px solid #1b242b}.auditrow:last-child{border:0}.small{font-size:12px}
.db-browser{display:grid;grid-template-columns:270px minmax(520px,1fr) minmax(300px,.55fr);min-height:520px}.db-sidebar{border-right:1px solid var(--line);padding:10px;max-height:70vh;overflow:auto}.db-main{min-width:0;border-right:1px solid var(--line)}.db-row{padding:12px;max-height:70vh;overflow:auto}.table-group{margin:10px 0 4px;color:var(--muted);font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.08em}.table-button{display:block;width:100%;text-align:left;border:0;background:transparent;padding:7px 9px;margin:1px 0}.table-button:hover,.table-button.active{background:#142028;color:var(--cyan)}.table-grid{overflow:auto;max-height:58vh}.table-grid td{max-width:260px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.table-filter{display:inline-flex;align-items:center;gap:7px}.linkbutton{border:0;padding:0;background:transparent;color:var(--cyan);text-align:left}.linkbutton:hover{text-decoration:underline}.empty{padding:28px;color:var(--muted);text-align:center}.advanced{margin-top:14px}.advanced>summary{background:var(--panel);border-radius:8px}.advanced[open]>summary{border-bottom:1px solid var(--line);border-radius:8px 8px 0 0}textarea{width:100%;min-height:90px;font-family:Consolas,monospace}.sqlout{max-height:340px;overflow:auto}
/* DeltaScope UI contract v4.0: self-contained Tailwind-inspired spacing, cards and TONI rail. */
body{background:radial-gradient(circle at 18% -20%,rgba(54,213,208,.08),transparent 32rem),radial-gradient(circle at 88% 0,rgba(255,94,98,.05),transparent 28rem),var(--bg)}
header{min-height:64px;padding:11px 20px;box-shadow:0 8px 28px rgba(0,0,0,.18)}
.brand{display:flex;align-items:center;gap:10px;font-weight:850;letter-spacing:.07em;white-space:nowrap}.omega-mark{position:relative;display:inline-grid;place-items:center;width:31px;height:31px;border:1px solid #34424e;border-radius:10px;background:linear-gradient(145deg,#111820,#0b1015);font:900 21px/1 Inter,Segoe UI,sans-serif;letter-spacing:0;color:#f4f7f9;box-shadow:inset 0 1px 0 rgba(255,255,255,.04),0 5px 16px rgba(0,0,0,.22)}.omega-mark::after{content:'';position:absolute;width:7px;height:7px;border-radius:999px;background:#ef4444;left:50%;top:50%;transform:translate(-50%,-50%);box-shadow:0 0 0 2px #10161c,0 0 12px rgba(239,68,68,.65)}
main{padding:22px;max-width:1900px}.hero-grid{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(330px,.72fr);gap:14px;align-items:stretch;margin-bottom:14px}.hero-copy{padding:18px 20px;border:1px solid var(--line);border-radius:14px;background:linear-gradient(145deg,rgba(20,27,34,.86),rgba(10,15,20,.94));box-shadow:0 12px 32px rgba(0,0,0,.18)}.eyebrow{font-size:11px;font-weight:800;letter-spacing:.16em;color:var(--cyan);text-transform:uppercase}.hero-copy h1{font-size:25px;line-height:1.15;margin:6px 0 7px}.hero-copy p{max-width:900px;margin:0;color:var(--muted)}
.toni-panel{position:relative;overflow:hidden;padding:16px 17px;border:1px solid #3a3135;border-radius:14px;background:linear-gradient(145deg,#16171a,#0d1115);box-shadow:0 12px 32px rgba(0,0,0,.2)}.toni-panel::after{content:'';position:absolute;right:-42px;top:-58px;width:150px;height:150px;border-radius:999px;background:radial-gradient(circle,rgba(239,68,68,.13),transparent 68%);pointer-events:none}.toni-head{display:flex;align-items:center;gap:9px;margin-bottom:8px}.toni-name{font-weight:850;letter-spacing:.08em}.toni-role{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}.toni-light{width:9px;height:9px;border-radius:999px;background:#ef4444;box-shadow:0 0 10px rgba(239,68,68,.65)}.toni-message{min-height:62px;color:#dce5ea}.toni-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}.toni-actions button{padding:6px 8px;font-size:12px;background:#11161c}
.cards{grid-template-columns:repeat(auto-fit,minmax(164px,1fr));gap:10px}.card,.panel{border-radius:12px;box-shadow:0 8px 26px rgba(0,0,0,.12)}.card{padding:13px 14px}.card.clickable{position:relative;transition:transform .14s ease,border-color .14s ease,background .14s ease}.card.clickable::after{content:'↗';position:absolute;right:10px;top:8px;font-size:12px;color:#5d7381}.card.clickable:hover{transform:translateY(-1px);border-color:#3d8f94;background:#111b20}.card .n{font-size:23px;letter-spacing:-.02em}.card .hint{margin-top:5px;color:#667d89;font-size:11px}.panelhead{padding:12px 14px}.panel{background:rgba(15,20,25,.95)}button{transition:border-color .14s ease,background .14s ease,transform .14s ease}button:active{transform:translateY(1px)}
.metric-note{display:flex;gap:7px;align-items:center;flex-wrap:wrap}.metric-note .pill{margin:0}.analysis-manifest{max-height:60vh;overflow:auto}
/* DeltaScope researcher workbench v3: triage first, raw database evidence advanced. */
.research-layout{display:grid;grid-template-columns:minmax(420px,.86fr) minmax(650px,1.55fr);gap:14px;align-items:start}.triage-panel{position:sticky;top:78px}.triage-row.selected{background:#13252a;box-shadow:inset 3px 0 0 var(--cyan)}.case-panel{min-height:620px}.case-header{padding:16px;border-bottom:1px solid var(--line);background:linear-gradient(145deg,rgba(20,27,34,.9),rgba(11,16,21,.94))}.case-title{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}.case-title h2{font-size:22px;margin:0}.case-subtitle{margin-top:4px;color:var(--muted)}.research-tabs{display:flex;gap:6px;flex-wrap:wrap;padding:10px 12px;border-bottom:1px solid var(--line);background:#0b1015}.research-tab{padding:7px 10px;border-radius:999px;background:#111820;color:#aebbc3}.research-tab.active{border-color:var(--cyan);color:var(--text);background:#102127}.research-pane{display:none;padding:14px}.research-pane.active{display:block}.signal-list{display:grid;gap:7px;margin:10px 0}.signal{display:flex;gap:9px;align-items:flex-start;padding:9px 10px;border:1px solid var(--line);border-radius:9px;background:#0c1217}.signal-dot{width:8px;height:8px;border-radius:999px;margin-top:6px;background:var(--muted);flex:0 0 auto}.signal.critical .signal-dot{background:var(--red)}.signal.high .signal-dot{background:#ff866b}.signal.caution .signal-dot{background:var(--amber)}.signal.informational .signal-dot{background:var(--blue)}.research-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.research-box{padding:11px;border:1px solid var(--line);border-radius:10px;background:#0c1217}.research-box h4{margin:0 0 7px}.cap-list{display:flex;gap:5px;flex-wrap:wrap}.priority{font-weight:850;text-transform:uppercase;letter-spacing:.06em}.priority-urgent{color:var(--red)}.priority-review{color:#ff866b}.priority-watch{color:var(--amber)}.priority-routine{color:var(--green)}.dataset-actions{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0}.dataset-actions button{font-size:12px}.raw-browser{margin-top:14px}.raw-browser>summary{font-weight:800;padding:13px 14px}.raw-browser .panel{border-radius:0 0 12px 12px;border-left:0;border-right:0;border-bottom:0;margin:0!important}.triage-scroll{max-height:72vh;overflow:auto}.triage-row td{padding-top:10px;padding-bottom:10px}.source-confidence{font-weight:700}.research-error{padding:14px;border:1px solid rgba(255,94,98,.45);border-radius:10px;background:rgba(255,94,98,.06)}
/* Asset Journey: evidence-backed top-to-bottom reconstruction of a plugin through Omega security services. */
.journey-intro{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:12px}.journey-intro h3{margin:0 0 4px}.journey-legend{display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}.journey-legend .pill{margin:0}.journey-flow{position:relative;max-width:760px;margin:4px auto 18px;padding:2px 0}.journey-stage{position:relative;display:grid;grid-template-columns:42px minmax(0,1fr);gap:10px;padding:0 0 18px}.journey-stage:last-child{padding-bottom:0}.journey-stage::before{content:'';position:absolute;left:20px;top:29px;bottom:-2px;width:2px;background:#26333c}.journey-stage:last-child::before{display:none}.journey-stage::after{content:'▼';position:absolute;left:14px;bottom:0;color:#425764;font-size:11px;line-height:1}.journey-stage:last-child::after{display:none}.journey-marker{position:relative;z-index:2;width:28px;height:28px;margin:4px auto 0;border-radius:9px;border:2px solid #42515b;background:#10171d;display:grid;place-items:center;font-size:11px;font-weight:900;color:#a9b7c0;box-shadow:0 0 0 4px #0f1419}.journey-stage.complete .journey-marker,.journey-stage.current .journey-marker{border-color:var(--green);color:var(--green)}.journey-stage.failed .journey-marker{border-color:var(--red);color:var(--red)}.journey-stage.partial .journey-marker,.journey-stage.requested .journey-marker,.journey-stage.needs-evidence .journey-marker{border-color:var(--amber);color:var(--amber)}.journey-stage.skipped .journey-marker,.journey-stage.not-requested .journey-marker,.journey-stage.not-recorded .journey-marker,.journey-stage.not-run .journey-marker{border-style:dashed;color:#657984}.journey-node{position:relative;border:1px solid var(--line);border-radius:11px;background:#0b1116;padding:12px 13px;min-width:0}.journey-node::before{content:'';position:absolute;left:-11px;top:16px;width:10px;height:2px;background:#26333c}.journey-stage.complete .journey-node{border-color:#244b43}.journey-stage.current .journey-node{border-color:#2f6f67;background:#0d1717}.journey-stage.failed .journey-node{border-color:rgba(255,94,98,.5)}.journey-stage.requested .journey-node,.journey-stage.needs-evidence .journey-node,.journey-stage.partial .journey-node{border-color:rgba(245,183,77,.45)}.journey-stage.skipped .journey-node,.journey-stage.not-requested .journey-node,.journey-stage.not-recorded .journey-node,.journey-stage.not-run .journey-node{border-style:dashed;opacity:.82}.journey-node-head{display:flex;gap:10px;align-items:flex-start;justify-content:space-between}.journey-node-title{font-weight:800;font-size:14px}.journey-status{font-size:10px;font-weight:850;letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--line);border-radius:999px;padding:2px 6px;white-space:nowrap;color:var(--muted)}.journey-stage.complete .journey-status,.journey-stage.current .journey-status{color:var(--green);border-color:#285b50}.journey-stage.failed .journey-status{color:var(--red);border-color:#6e343c}.journey-stage.requested .journey-status,.journey-stage.needs-evidence .journey-status,.journey-stage.partial .journey-status{color:var(--amber);border-color:#66512d}.journey-summary{margin-top:4px;color:#c8d3d9}.journey-details{display:flex;gap:5px;flex-wrap:wrap;margin-top:8px}.journey-detail{font:11px/1.35 Consolas,monospace;color:#8da2ad;background:#080d11;border:1px solid #202b33;border-radius:6px;padding:3px 6px;max-width:100%;overflow-wrap:anywhere}.journey-evidence{margin-top:7px;color:#617783;font-size:10px;text-transform:uppercase;letter-spacing:.06em}.journey-note{padding:9px 10px;border-left:3px solid #36505e;background:#0b1116;color:var(--muted);font-size:12px;margin-top:10px}@media(max-width:760px){.journey-intro{display:block}.journey-legend{justify-content:flex-start;margin-top:8px}.journey-stage{grid-template-columns:34px minmax(0,1fr)}.journey-stage::before{left:16px}.journey-stage::after{left:10px}.journey-marker{width:25px;height:25px}.journey-node::before{left:-9px;width:8px}}
.focusbar{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center;padding:11px 13px;margin-bottom:10px;border:1px solid var(--line);border-radius:12px;background:linear-gradient(145deg,rgba(16,23,29,.9),rgba(10,15,20,.96))}.focus-title{font-weight:800;font-size:16px}.focus-sub{color:var(--muted);font-size:12px;margin-top:2px}.focus-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap;justify-content:flex-end}.engine-pill,.source-state{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border:1px solid var(--line);border-radius:999px;background:#111820;font-size:11px}.engine-pill b{color:var(--text)}.focus-cards{grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:12px}.focus-cards .card{min-height:82px}.metrics-drawer{margin-top:14px}.metrics-drawer>summary{font-weight:800;padding:12px 14px}.metrics-drawer .cards{padding:0 12px 12px}.source-state.ok{color:var(--green);border-color:rgba(85,217,141,.35)}.source-state.warn{color:var(--amber);border-color:rgba(255,191,77,.35)}.source-state.muted{color:var(--muted)}.source-mode{font-weight:800;white-space:nowrap}.case-coverage{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}.case-summary{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.case-summary .pill{padding:5px 8px;background:#111820}.source-repo{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.toni-inline{display:flex;gap:8px;align-items:flex-start}.toni-inline .toni-light{margin-top:5px;flex:0 0 auto}.toni-inline-message{color:#dce5ea}.source-cell{min-width:145px}.source-cell .small{margin-top:3px}.coverage-label{font-size:11px;color:var(--muted);max-width:190px}.research-layout{margin-top:0}.triage-scroll{max-height:78vh}.hero-grid{display:none}.toni-panel{display:none}
.rule-browser-shell{display:grid;grid-template-columns:minmax(300px,360px) minmax(0,1fr);gap:12px;align-items:start;margin-bottom:12px}.rule-library-panel{position:sticky;top:78px;max-height:calc(100vh - 96px);display:flex;flex-direction:column}.rule-library-search{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:6px;padding:9px 10px;border-bottom:1px solid var(--line)}.rule-library-search input{min-width:0;width:100%}.rule-library-search button{padding:7px 9px;font-size:11px}.rule-library-legend{padding:8px 10px;border-bottom:1px solid var(--line);color:#8fa1ad;font-size:11px;line-height:1.4}.source-pill{color:#84d8ff;border-color:rgba(104,167,255,.35);background:rgba(104,167,255,.05)}.rule-tree{padding:7px;overflow:auto;min-height:300px;max-height:72vh}.rule-tree details{margin:2px 0;border:0;background:transparent}.rule-tree details>summary{display:flex;align-items:center;gap:6px;padding:6px 7px;border-radius:7px;font-weight:650;list-style:none}.rule-tree details>summary::-webkit-details-marker{display:none}.rule-tree details>summary::before{content:'▸';width:12px;color:#607984;flex:0 0 auto}.rule-tree details[open]>summary::before{content:'▾';color:var(--cyan)}.rule-tree details>div{padding:1px 0 2px 18px}.rule-tree-row{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:7px;align-items:center;width:100%;padding:6px 7px;margin:1px 0;border:1px solid transparent;border-radius:7px;background:transparent;text-align:left;color:#b9c8d0}.rule-tree-row:hover{border-color:#263743;background:#101820}.rule-tree-row.active{border-color:#2b6467;background:#102127;color:#eef4f7}.rule-tree-icon{display:inline-grid;place-items:center;min-width:19px;height:19px;padding:0 4px;border:1px solid #273640;border-radius:5px;color:#78a0b3;font:800 9px/1 ui-monospace,SFMono-Regular,Consolas,monospace}.rule-tree-title{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.rule-tree-meta{color:#607984;font-size:10px;white-space:nowrap}.rule-tree-folder-meta{margin-left:auto;color:#607984;font-size:10px;font-weight:500}.rule-inspector-panel{min-height:620px}.rule-inspector{padding:14px}.rule-inspector-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;padding-bottom:12px;border-bottom:1px solid var(--line)}.rule-inspector-head h2{font-size:20px;margin:0}.rule-inspector-kicker{font-size:10px;text-transform:uppercase;letter-spacing:.11em;color:var(--cyan);font-weight:800}.rule-inspector-actions{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}.rule-inspector-actions button{font-size:11px;padding:6px 8px}.rule-learning-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;margin:12px 0}.rule-learning-card{padding:10px;border:1px solid var(--line);border-radius:9px;background:#0b1116}.rule-learning-card h4{margin:0 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8197a3}.rule-learning-card .big{font-weight:750;color:#dce7ec}.rule-source-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:12px 0 8px}.rule-source-tab{font-size:11px;padding:6px 9px}.rule-source-tab.active{border-color:var(--cyan);background:#102127}.rule-source-pane{display:none}.rule-source-pane.active{display:block}.rule-source-code{max-height:560px;overflow:auto;font:12px/1.52 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;white-space:pre;background:#070b0f;border:1px solid #1d2a33;border-radius:8px;padding:12px;color:#d7e3e8}.rule-path{margin-top:7px;color:#6f8997;font:10px ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}.rule-list-mini{display:grid;gap:5px}.rule-list-mini button{display:flex;justify-content:space-between;gap:10px;text-align:left;background:#0d151b;border-color:#22313b;padding:7px 8px}.active-rule-snapshot{margin-bottom:12px}.active-snapshot-note{padding:9px 10px;margin-bottom:10px;border:1px solid rgba(104,167,255,.28);border-radius:8px;background:rgba(104,167,255,.04);color:#b8c9d2}.rule-output-badge{display:inline-flex;gap:5px;align-items:center;padding:3px 7px;border:1px solid #293945;border-radius:999px;background:#0e171d;font-size:10px}.rule-empty-note{padding:10px;border:1px dashed #2a3943;border-radius:8px;color:#778e9a}.rule-structure{margin-top:10px}.rule-structure .code{max-height:260px}.rule-library-error{padding:14px;color:#ffc1c3}.rule-browser-shell code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#b9d8e8}@media(max-width:1150px){.rule-browser-shell{grid-template-columns:300px minmax(0,1fr)}.rule-learning-grid{grid-template-columns:1fr}}@media(max-width:860px){.rule-browser-shell{grid-template-columns:1fr}.rule-library-panel{position:static;max-height:none}.rule-tree{max-height:360px}.rule-inspector-panel{min-height:0}}
.rule-lab-shell{display:grid;grid-template-columns:minmax(420px,.95fr) minmax(520px,1.25fr);gap:12px;padding:12px}.rule-lab-editor,.rule-lab-output,.rule-lab-fixture{border:1px solid var(--line);border-radius:10px;background:#0c1217;padding:12px}.rule-lab textarea{min-height:360px;resize:vertical}.rule-lab-fixture textarea{min-height:220px}.rule-proposal-grid{display:grid;grid-template-columns:1fr 1fr;gap:9px}.rule-proposal-grid .wide{grid-column:1/-1}.rule-proposal-grid input,.rule-proposal-grid textarea{width:100%}.rule-proposal-grid textarea.meta{min-height:88px}.proposal-result{margin-top:9px;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:#091016}.proposal-result.warn{border-color:rgba(255,193,92,.42)}.rule-lab-actions{display:flex;gap:7px;flex-wrap:wrap;margin:9px 0}.rule-lab-actions input{min-width:240px;flex:1}.rule-lab-note{padding:9px 10px;border:1px solid rgba(85,217,141,.28);border-radius:8px;background:rgba(85,217,141,.04);color:#cde9d8}.rule-lab-diag{padding:8px 9px;margin:6px 0;border:1px solid var(--line);border-radius:8px}.rule-lab-diag.error{border-color:rgba(255,94,98,.45);color:#ffc1c3}.rule-lab-diag.info{border-color:rgba(104,167,255,.32);color:#bdd5ff}.rule-lab-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin:8px 0}.rule-lab-summary .card{min-height:72px}.selector-card{padding:9px;border:1px solid var(--line);border-radius:8px;margin:7px 0;background:#0a1015}.selector-card.matched{border-color:rgba(85,217,141,.35)}.rule-lab-output .code{max-height:440px}.rule-lab .readonly-pill{color:var(--green);border-color:rgba(85,217,141,.32)}
.rule-smart-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;padding:8px 10px;border:1px solid var(--line);border-bottom:0;border-radius:10px 10px 0 0;background:linear-gradient(180deg,#101820,#0c1319)}.rule-smart-toolbar .left,.rule-smart-toolbar .right{display:flex;align-items:center;gap:6px;flex-wrap:wrap}.editor-chip{display:inline-flex;align-items:center;gap:5px;padding:3px 7px;border:1px solid #2d3b46;border-radius:999px;background:#0a1116;color:#9fb2be;font-size:11px}.editor-chip.clean{border-color:rgba(85,217,141,.34);color:#8be3ad}.editor-chip.error{border-color:rgba(255,94,98,.42);color:#ffb6b8}.editor-chip.busy{border-color:rgba(104,167,255,.38);color:#aecaff}.rule-smart-toolbar button{padding:5px 8px;font-size:11px}.rule-spell-toggle{display:inline-flex;align-items:center;gap:5px;color:var(--muted);font-size:11px;user-select:none}.rule-spell-toggle input{min-width:auto;width:auto;margin:0}.rule-smart-editor{display:grid;grid-template-columns:48px minmax(0,1fr);height:430px;border:1px solid var(--line);background:#070b0f;position:relative;overflow:hidden}.rule-editor-gutter{padding:14px 8px 14px 0;background:#0a1015;border-right:1px solid #1c2831;color:#536773;text-align:right;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre;overflow:hidden;user-select:none}.rule-editor-gutter .diag-line{color:#ff8488;font-weight:800}.rule-editor-gutter .warn-line{color:#ffd07a}.rule-code-wrap{position:relative;min-width:0;overflow:hidden}.rule-code-wrap pre,.rule-code-wrap textarea{position:absolute;inset:0;margin:0;padding:14px 16px;border:0;border-radius:0;outline:0;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;tab-size:2;white-space:pre;overflow:auto}.rule-code-wrap pre{z-index:1;pointer-events:none;color:#d9e4ea;background:#070b0f;scrollbar-width:none}.rule-code-wrap pre::-webkit-scrollbar{display:none}.rule-code-wrap textarea{z-index:2;resize:none;background:transparent;color:transparent;-webkit-text-fill-color:transparent;caret-color:#f4fbff;overflow:scroll;scrollbar-color:#293946 transparent}.rule-code-wrap textarea::selection{background:rgba(54,213,208,.24)}.yaml-key{color:#74c7ff}.yaml-schema{color:#d09cff}.yaml-string{color:#b8e986}.yaml-number{color:#ffca7a}.yaml-bool{color:#ff9db5}.yaml-operator{color:#f4b86a;font-weight:650}.yaml-comment{color:#526a76;font-style:italic}.yaml-punct{color:#8094a1}.rule-completion-popup{position:absolute;z-index:9;min-width:310px;max-width:440px;max-height:270px;overflow:auto;border:1px solid #38505d;border-radius:9px;background:#0c141a;box-shadow:0 16px 38px rgba(0,0,0,.5);padding:4px}.rule-completion-item{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;padding:7px 8px;border-radius:6px;cursor:pointer}.rule-completion-item.active,.rule-completion-item:hover{background:#14242c}.rule-completion-label{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:#e6f1f5}.rule-completion-kind{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:#6f8997}.rule-completion-detail{grid-column:1/-1;color:#8298a4;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.rule-editor-statusbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:5px 9px;border:1px solid var(--line);border-top:0;background:#0c1217;color:#718895;font-size:10px}.rule-editor-statusbar .push{margin-left:auto}.rule-intelligence-grid{display:grid;grid-template-columns:1.25fr .75fr;gap:8px;margin-top:8px}.rule-intel-panel{border:1px solid var(--line);border-radius:8px;background:#0a1015;padding:8px 9px;min-height:86px}.rule-intel-title{font-size:10px;font-weight:800;letter-spacing:.09em;text-transform:uppercase;color:#718895;margin-bottom:5px}.rule-context-doc{font-size:11px;color:#b9c8d0}.rule-context-token{font:11px ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--cyan)}.rule-suggestion-chips{display:flex;gap:4px;flex-wrap:wrap;margin-top:6px}.rule-suggestion-chip,.rule-symbol{border:1px solid #263743;background:#0f1820;border-radius:6px;padding:3px 6px;font:10px ui-monospace,SFMono-Regular,Consolas,monospace;color:#aac0cb;cursor:pointer}.rule-suggestion-chip:hover,.rule-symbol:hover{border-color:#3f8187;color:#dff}.rule-outline{display:flex;gap:4px;flex-wrap:wrap}.rule-flow-panel{grid-column:1/-1}.rule-flow-edge{display:inline-flex;align-items:center;gap:5px;padding:3px 6px;border:1px solid #253642;border-radius:6px;background:#0e171d;font:10px ui-monospace,SFMono-Regular,Consolas,monospace;color:#a9bdc8}.rule-flow-arrow{color:var(--cyan)}.rule-inline-diagnostics{display:grid;gap:5px;margin-top:8px}.rule-inline-diagnostic{display:grid;grid-template-columns:auto 1fr;gap:7px;align-items:start;padding:6px 8px;border:1px solid #26343e;border-radius:7px;background:#0b1116;font-size:11px;cursor:pointer}.rule-inline-diagnostic.error{border-color:rgba(255,94,98,.36)}.rule-inline-diagnostic.info{border-color:rgba(104,167,255,.25)}.rule-inline-diagnostic .where{font:10px ui-monospace,SFMono-Regular,Consolas,monospace;color:#6f8997}.rule-editor-hint{color:#607984;font-size:10px}.rule-lab textarea#ruleYaml{min-height:0}.rule-lab-editor.smart{min-width:0}@media(max-width:760px){.rule-intelligence-grid{grid-template-columns:1fr}.rule-smart-editor{height:360px}.rule-smart-toolbar .right{width:100%}}
@media(max-width:1250px){.rule-lab-shell{grid-template-columns:1fr}.hero-grid{grid-template-columns:1fr}.research-layout{grid-template-columns:1fr}.triage-panel{position:static}.split{grid-template-columns:1fr}.scroll{max-height:48vh}.db-browser{grid-template-columns:230px 1fr}.db-row{grid-column:1/-1;border-top:1px solid var(--line);max-height:none}.db-main{border-right:0}}

/* DeltaScope Phase-11 read-only security-information workbench shell. */
.app-shell{display:grid;grid-template-columns:190px minmax(0,1fr);min-height:calc(100vh - 64px)}.workbench-nav{position:sticky;top:64px;height:calc(100vh - 64px);padding:14px 10px;border-right:1px solid var(--line);background:#0b0f13;overflow:auto}.workbench-nav-title{padding:4px 8px 10px;color:var(--muted);font-size:10px;font-weight:850;letter-spacing:.15em;text-transform:uppercase}.workbench-nav button{display:flex;width:100%;align-items:center;gap:9px;text-align:left;margin:2px 0;padding:9px 10px;border:1px solid transparent;background:transparent;color:#aebbc3}.workbench-nav button:hover{background:#111820;border-color:#22303a}.workbench-nav button.active{background:#102127;border-color:#2b6467;color:var(--text)}.workbench-nav .nav-mark{display:inline-grid;place-items:center;width:22px;height:22px;border:1px solid #273640;border-radius:6px;color:var(--cyan);font-size:11px;font-weight:850}.workbench-nav-note{margin:14px 8px 0;padding-top:12px;border-top:1px solid var(--line);color:#667d89;font-size:11px}.workspace-view{display:none}.workspace-view.active{display:block}.workspace-heading{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin:4px 0 12px}.workspace-heading h1{font-size:23px;margin:0}.workspace-heading p{color:var(--muted);margin:4px 0 0;max-width:900px}.workbench-table-wrap{overflow:auto;max-height:72vh}.workbench-table td{padding:10px}.incident-badge{display:inline-block;padding:2px 7px;border-radius:999px;border:1px solid var(--line);font-size:11px}.readonly-boundary{padding:10px 12px;border:1px solid #29454a;border-radius:9px;background:#0c171a;color:#b7d5d5;margin-bottom:12px}.workspace-cards{margin-bottom:12px}.dashboard-activity{margin-top:12px}.workspace-empty{padding:36px;text-align:center;color:var(--muted)}.case-projection{margin-top:12px}.case-projection-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.case-projection-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.6fr);gap:12px;margin-top:12px}.case-projection .timeline{max-height:58vh;overflow:auto}.timeline-row{border-left:3px solid #263641}.timeline-row.finding{border-left-color:#8b5d3f}.timeline-row.observation{border-left-color:#2b6467}.timeline-row.intelligence{border-left-color:#6c5b9b}.timeline-row.reprojection{border-left-color:#587a55}.timeline-source{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}.case-findings{max-height:58vh;overflow:auto}.case-relations{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}@media(max-width:1050px){.case-projection-grid{grid-template-columns:1fr}}
@media(max-width:980px){.app-shell{grid-template-columns:1fr}.workbench-nav{position:sticky;top:64px;height:auto;z-index:9;display:flex;gap:4px;overflow:auto;border-right:0;border-bottom:1px solid var(--line);padding:7px}.workbench-nav-title,.workbench-nav-note{display:none}.workbench-nav button{width:auto;white-space:nowrap;margin:0}.workbench-nav .nav-mark{display:none}}
@media(max-width:760px){main{padding:10px}.focusbar{grid-template-columns:1fr}.focus-actions{justify-content:flex-start}.focus-cards{grid-template-columns:repeat(2,minmax(0,1fr))}.research-grid{grid-template-columns:1fr}.db-browser{grid-template-columns:1fr}.db-sidebar{border-right:0;border-bottom:1px solid var(--line);max-height:220px}.db-row{grid-column:auto}.toolbar input{min-width:100%}.kv{grid-template-columns:1fr}}

/* DeltaScope 4.6.2 adaptive Stigma-1 deep-scan orchestration. */
.unified-rule-workspace{grid-template-columns:minmax(280px,330px) minmax(0,1fr)}
.rule-workspace-panel{min-width:0;overflow:hidden;padding:0}.rule-workspace-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:12px 14px;border-bottom:1px solid var(--line)}.rule-workspace-head h2{margin:2px 0 3px}.rule-workspace-actions{display:flex;align-items:center;justify-content:flex-end;gap:6px;flex-wrap:wrap}.rule-workspace-tabs{display:flex;gap:2px;padding:7px 10px 0;border-bottom:1px solid var(--line);background:#0a1116}.rule-workspace-tabs button{border-bottom-left-radius:0;border-bottom-right-radius:0;border-bottom:2px solid transparent;background:transparent}.rule-workspace-tabs button.active{color:#e8fbff;border-color:var(--cyan);background:#101a21}.rule-workspace-pane{display:none;padding:10px}.rule-workspace-pane.active{display:block}.rule-workspace-pane[data-rule-workspace-pane="yaml"]{padding:0}.rule-workspace-pane .rule-lab-editor{padding:10px}.rule-workspace-pane .rule-smart-editor{height:min(62vh,720px);min-height:470px}.local-pill{color:#8be3ad;border-color:rgba(85,217,141,.34);background:rgba(85,217,141,.05)}.rule-local-home{display:block;margin-top:6px;color:#607984;font:9px/1.35 ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}.rule-tree-divider{height:1px;background:var(--line);margin:7px 4px}.rule-tree-new{border-style:dashed!important;border-color:#315a4b!important;color:#a7e5bd!important}.rule-tree-row .active-badge{font-size:9px;color:#89e7c6}.rule-tree-row .local-rev{font-size:9px;color:#8fa1ad}.rule-tree-row.invalid{border-color:rgba(255,94,98,.35);color:#ffb6b8}.rule-workspace-origin-system{color:#84d8ff;border-color:rgba(104,167,255,.35)}.rule-workspace-origin-local{color:#8be3ad;border-color:rgba(85,217,141,.34)}.rule-workspace-origin-dirty{color:#ffd07a;border-color:rgba(255,190,82,.34)}
.visual-workspace{display:grid;grid-template-columns:185px minmax(0,1fr);gap:10px;min-height:620px}.visual-palette{border-right:1px solid var(--line);padding:5px 10px 5px 0;display:flex;flex-direction:column;gap:6px}.visual-palette button{text-align:left;cursor:grab}.visual-palette button:active{cursor:grabbing}.visual-help{margin-top:8px;color:#718895;font-size:10px;line-height:1.45}.visual-main{min-width:0;display:grid;grid-template-rows:auto minmax(420px,1fr) auto;gap:8px}.visual-toolbar{display:flex;gap:6px;align-items:center;flex-wrap:wrap}.visual-toolbar .editor-chip{margin-right:auto}.visual-canvas{position:relative;min-height:500px;overflow:auto;border:1px solid var(--line);border-radius:9px;background-color:#070b0f;background-image:linear-gradient(#101820 1px,transparent 1px),linear-gradient(90deg,#101820 1px,transparent 1px);background-size:24px 24px}.visual-edges,.visual-nodes{position:absolute;inset:0;min-width:100%;min-height:100%;width:1200px;height:800px}.visual-edges{z-index:1;pointer-events:none}.visual-edges path{stroke:#365463;stroke-width:2;fill:none}.visual-edges path.active{stroke:#5fd8d2;stroke-width:3}.visual-nodes{z-index:2;pointer-events:none}.visual-node{position:absolute;width:190px;min-height:82px;border:1px solid #2b3d48;border-radius:9px;background:#0d161c;box-shadow:0 7px 22px rgba(0,0,0,.32);pointer-events:auto;user-select:none}.visual-node.selected{border-color:#4eafb0;box-shadow:0 0 0 1px rgba(54,213,208,.25),0 10px 26px rgba(0,0,0,.4)}.visual-node.connect-source{border-color:#ffd07a}.visual-node-head{display:flex;justify-content:space-between;gap:5px;padding:6px 8px;border-bottom:1px solid #22323c;background:#101c23;border-radius:8px 8px 0 0;cursor:move}.visual-node-type{font:800 9px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.06em;color:#72b8c6}.visual-node-title{font-size:11px;font-weight:750;color:#e3edf1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.visual-node-body{padding:7px 8px;color:#8fa7b3;font:10px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;max-height:95px;overflow:hidden}.visual-port{display:inline-grid;place-items:center;width:18px;height:18px;border:1px solid #38515e;border-radius:50%;color:#7fd7dd;background:#0a1116;font-size:9px}.visual-empty{position:absolute;inset:0;display:grid;place-items:center;color:#526a76;z-index:0}.visual-properties{border:1px solid var(--line);border-radius:8px;background:#0a1015;padding:9px}.visual-properties-grid{display:grid;grid-template-columns:150px minmax(0,1fr);gap:7px 10px;align-items:center}.visual-properties-grid label{color:#8196a2;font-size:10px}.visual-properties-grid input,.visual-properties-grid select,.visual-properties-grid textarea{width:100%}.visual-properties-grid textarea{min-height:80px;font:11px ui-monospace,SFMono-Regular,Consolas,monospace}.visual-predicate-row{display:grid;grid-template-columns:1fr 150px 1fr auto;gap:5px;margin-top:5px}.visual-property-actions{display:flex;gap:5px;flex-wrap:wrap;margin-top:8px}.rule-explain-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:9px}.rule-explain-actions input:first-of-type{min-width:260px;flex:1}.rule-test-drawer{margin-top:12px}.rule-test-drawer textarea{min-height:120px}.rule-dirty-dot::after{content:' •';color:#ffd07a}.rule-workspace-disabled{opacity:.65;pointer-events:none}@media(max-width:1050px){.unified-rule-workspace{grid-template-columns:260px minmax(0,1fr)}.visual-workspace{grid-template-columns:1fr}.visual-palette{border-right:0;border-bottom:1px solid var(--line);display:flex;flex-direction:row;flex-wrap:wrap}.visual-palette .rule-intel-title,.visual-help{width:100%}}@media(max-width:760px){.unified-rule-workspace{grid-template-columns:1fr}.rule-library-panel{position:relative;top:auto;max-height:none}.rule-tree{max-height:330px}.rule-workspace-head{flex-direction:column}.rule-workspace-actions{justify-content:flex-start}.rule-workspace-pane .rule-smart-editor{height:480px;min-height:360px}}

/* DeltaScope 4.1 fixed-shell contract: the browser window never becomes a page scroller.
   Every workspace owns the viewport and long data scrolls only inside the panel that owns it. */
html,body{height:100%;min-height:0;overflow:hidden;overscroll-behavior:none}
body{display:grid;grid-template-rows:64px minmax(0,1fr)}
header{position:relative;top:auto;height:64px;min-height:64px;overflow-x:auto;overflow-y:hidden;white-space:nowrap;flex-wrap:nowrap}
.app-shell{height:100%;min-height:0;overflow:hidden;grid-template-rows:minmax(0,1fr)}
.app-shell>main{height:100%;min-height:0;overflow:hidden;max-width:none;width:100%;margin:0;padding:14px 18px}
.workbench-nav{position:relative;top:auto;height:100%;min-height:0;overflow:auto;overscroll-behavior:contain}
.workspace-view{height:100%;min-height:0;overflow:hidden}
.workspace-view.active{display:flex;flex-direction:column;gap:10px}
.workspace-view.active>.workspace-heading{flex:0 0 auto;margin:0}
.workspace-view.active>.workspace-cards{flex:0 0 auto;margin:0}
.workspace-view.active>.readonly-boundary{flex:0 0 auto;margin:0}
.workbench-table-wrap,.scroll,.triage-scroll,.table-grid,.db-sidebar,.db-row,.case-findings,.case-projection .timeline,.rule-tree,.rule-workspace-pane,.visual-canvas,.visual-properties,.sqlout{overscroll-behavior:contain;scrollbar-gutter:stable}
/* Dashboard */
#workbench-dashboard>.focusbar,#workbench-dashboard>.focus-cards{flex:0 0 auto;margin:0}
#workbench-dashboard>.dashboard-grid{flex:1 1 auto;min-height:0;display:grid;grid-template-columns:minmax(330px,.85fr) minmax(0,1.35fr);gap:12px;overflow:hidden}
#dashboardComponents,#dashboardActivity{height:100%;min-height:0;margin:0;display:flex;flex-direction:column;overflow:hidden}
#dashboardComponentRows,#dashboardActivityRows{flex:1 1 auto;min-height:0;overflow:auto;overscroll-behavior:contain}
.component-status-row{display:grid;grid-template-columns:minmax(125px,.72fr) auto minmax(160px,1fr);gap:8px;align-items:center;padding:9px 11px;border-bottom:1px solid #1b242b}.component-status-row:last-child{border-bottom:0}.component-state{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:800;letter-spacing:.05em;text-transform:uppercase}.component-state:before{content:'';width:8px;height:8px;border-radius:50%;background:#56646d}.component-state.running:before{background:#5cc8d7;box-shadow:0 0 0 3px #183d44}.component-state.healthy:before{background:#67b86a}.component-state.failed:before{background:#d7685e}.component-state.warning:before{background:#c39a50}
/* Incidents + Events */
#workbench-incidents>.incident-overview-grid,#workbench-events>.event-overview-grid{flex:0 1 40%;min-height:150px;display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,1fr);gap:12px;overflow:hidden}
#workbench-incidents>.incident-overview-grid>.panel,#workbench-events>.event-overview-grid>.panel{height:100%;min-height:0;margin:0;display:flex;flex-direction:column;overflow:hidden}
#workbench-incidents>.incident-overview-grid .workbench-table-wrap,#workbench-events>.event-overview-grid .workbench-table-wrap{flex:1 1 auto;min-height:0;max-height:none}
#incidentCasePanel,#eventCasePanel{flex:1 1 60%;min-height:0;margin:0;overflow:auto;overscroll-behavior:contain}
.operation-link{color:var(--cyan);text-decoration:none}.operation-link:hover{text-decoration:underline}
/* Intelligence */
#workbench-intelligence>.research-grid{flex:1 1 auto;min-height:0;overflow:hidden;grid-template-rows:minmax(0,1fr) minmax(0,1fr)}
#workbench-intelligence>.research-grid>.panel{min-height:0;display:flex;flex-direction:column;overflow:hidden}
#workbench-intelligence>.research-grid>.panel .workbench-table-wrap{flex:1 1 auto;min-height:0;max-height:none}
#intelligencePivotPanel{flex:0 0 min(180px,20vh);min-height:0;margin:0;overflow:auto;overscroll-behavior:contain}
#workbench-intelligence>details.advanced{flex:0 0 auto;max-height:30vh;margin:0;overflow:auto;overscroll-behavior:contain}
/* Assets */
#workbench-assets{margin-top:0!important}
#workbench-assets>.research-layout{flex:1 1 auto;height:100%;min-height:0;overflow:hidden;align-items:stretch;grid-template-columns:minmax(360px,.86fr) minmax(0,1.55fr)}
#workbench-assets .triage-panel,#workbench-assets .case-panel{position:relative;top:auto;height:100%;min-height:0;max-height:none;display:flex;flex-direction:column;overflow:hidden}
#workbench-assets .triage-scroll{flex:1 1 auto;min-height:0;max-height:none;overflow:auto}
#workbench-assets #pluginDetail{flex:1 1 auto;min-height:0;overflow:auto;overscroll-behavior:contain}
/* Rules: heading/boundary stay fixed; the rule tree/editor consumes the remaining viewport. */
#workbench-rules>.rule-browser-shell{flex:1 1 auto;height:auto;min-height:0;margin:0;align-items:stretch;overflow:hidden}
#workbench-rules>.active-rule-snapshot{flex:0 0 auto;max-height:30vh;margin:0;overflow:auto;overscroll-behavior:contain}
#workbench-rules .rule-library-panel{position:relative;top:auto;height:100%;min-height:0;max-height:none}
#workbench-rules .rule-tree{flex:1 1 auto;min-height:0;max-height:none}
#workbench-rules .rule-workspace-panel{height:100%;min-height:0;display:flex;flex-direction:column}
#workbench-rules .rule-workspace-head,#workbench-rules .rule-workspace-tabs{flex:0 0 auto}
#workbench-rules .rule-workspace-pane.active{flex:1 1 auto;min-height:0;overflow:auto}
#workbench-rules .rule-workspace-pane[data-rule-workspace-pane="visual"].active{overflow:hidden}
#workbench-rules .rule-workspace-pane .rule-smart-editor{height:min(52vh,640px);min-height:320px}
#workbench-rules .visual-workspace{height:100%;min-height:0}
#workbench-rules .visual-palette{min-height:0;overflow:auto}
#workbench-rules .visual-main{height:100%;min-height:0;grid-template-rows:auto minmax(0,1fr) auto}
#workbench-rules .visual-canvas{height:100%;min-height:0}
#workbench-rules .visual-properties{max-height:24vh;overflow:auto}
/* Reports */
#workbench-reports>.panel{flex:1 1 auto;min-height:0;display:flex;flex-direction:column;overflow:hidden}
#workbench-reports>#metricsDrawer{flex:0 0 auto;max-height:34vh;margin:0;overflow:auto;overscroll-behavior:contain}
#reportRows{flex:1 1 auto;min-height:0;overflow:auto;overscroll-behavior:contain}
/* Documentation */
#workbench-docs>.docs-shell{flex:1 1 auto;min-height:0;display:grid;grid-template-columns:minmax(250px,.38fr) minmax(0,1fr);gap:12px;overflow:hidden}
#workbench-docs .docs-list-panel,#workbench-docs .docs-viewer{height:100%;min-height:0;margin:0;display:flex;flex-direction:column;overflow:hidden}
#docTree,#docContent{flex:1 1 auto;min-height:0;overflow:auto;overscroll-behavior:contain}
.doc-group{padding:9px 11px 4px;color:var(--muted);font-size:10px;font-weight:850;letter-spacing:.12em;text-transform:uppercase}.doc-item{display:block;width:100%;padding:9px 11px;border:0;border-top:1px solid #1b242b;border-radius:0;background:transparent;text-align:left;color:var(--text)}.doc-item:hover,.doc-item.active{background:#102127}.doc-item .small{display:block;margin-top:3px;color:var(--muted)}#docContent{margin:0;padding:16px;white-space:pre-wrap;word-break:break-word;background:#090d10;border-top:1px solid var(--line);font:13px/1.55 Consolas,'Courier New',monospace}
/* System */
#workbench-system>.research-grid{flex:0 1 min(220px,28vh);min-height:0;overflow:hidden}
#workbench-system>.research-grid>.panel{min-height:0;display:flex;flex-direction:column;overflow:hidden}
#workbench-system>.research-grid>.panel>.detail{flex:1 1 auto;min-height:0;overflow:auto;overscroll-behavior:contain}
#rawEvidence{flex:0 0 auto;min-height:0;margin:0;overflow:hidden}
#rawEvidence[open]{display:flex;flex:1 1 auto;flex-direction:column}
#rawEvidence>summary{flex:0 0 auto}
#rawEvidence>section.panel{flex:1 1 auto;min-height:0;display:flex;flex-direction:column;overflow:hidden}
#rawEvidence .db-browser{flex:1 1 auto;height:auto;min-height:0}
#rawEvidence .db-sidebar,#rawEvidence .db-row{height:100%;min-height:0;max-height:none}
#rawEvidence .db-main{height:100%;min-height:0;display:flex;flex-direction:column}
#rawEvidence .table-grid{flex:1 1 auto;height:auto;min-height:0;max-height:none}
#advancedSql{flex:0 0 auto;max-height:34vh;margin:0;overflow:auto;overscroll-behavior:contain}
@media(max-width:980px){
 .app-shell{grid-template-columns:1fr;grid-template-rows:auto minmax(0,1fr)}
 .workbench-nav{position:relative;top:auto;height:auto;min-height:0;max-height:54px}
 .app-shell>main{height:100%;min-height:0}
}
@media(max-width:850px){
 #workbench-dashboard>.dashboard-grid,#workbench-incidents>.incident-overview-grid,#workbench-events>.event-overview-grid,#workbench-docs>.docs-shell{grid-template-columns:1fr;grid-template-rows:minmax(0,1fr) minmax(0,1fr)}
 #workbench-assets>.research-layout{grid-template-columns:1fr;grid-template-rows:minmax(0,1fr) minmax(0,1fr)}
 #workbench-rules>.rule-browser-shell{grid-template-columns:1fr;grid-template-rows:minmax(180px,.35fr) minmax(0,1fr)}
 #workbench-rules .rule-library-panel{height:100%;max-height:none}
 #workbench-rules .rule-tree{max-height:none}
}

/* DeltaScope 4.8 object-centric investigation UX. */
header{overflow:visible}.omnibox-wrap{position:relative;min-width:260px;max-width:520px;flex:1 1 360px}.omnibox-wrap input{width:100%;min-width:0;padding-left:34px;background:#0c1217}.omnibox-wrap::before{content:'⌕';position:absolute;left:11px;top:7px;color:#708793;font-size:17px;z-index:2}.omnibox-results{position:absolute;left:0;right:0;top:42px;z-index:80;max-height:min(520px,70vh);overflow:auto;border:1px solid #34434e;border-radius:10px;background:#0b1015;box-shadow:0 18px 48px rgba(0,0,0,.48);padding:6px}.omnibox-results[hidden]{display:none}.search-group{padding:5px 8px 3px;color:#718793;font-size:10px;font-weight:850;letter-spacing:.12em;text-transform:uppercase}.search-result{display:grid;grid-template-columns:26px minmax(0,1fr) auto;gap:8px;align-items:center;width:100%;padding:8px;border:1px solid transparent;background:transparent;text-align:left}.search-result:hover,.search-result.active{background:#102027;border-color:#23424b}.search-kind{display:grid;place-items:center;width:22px;height:22px;border:1px solid #2c3d47;border-radius:6px;color:#78a6b6;font:800 10px ui-monospace,Consolas,monospace}.search-result-title{font-weight:750}.search-result-sub{font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.lens-select{padding:6px 8px;font-size:12px;min-width:112px}
.workbench-nav-title.group{margin-top:11px;color:#6f8490}.workbench-nav-title.group:first-child{margin-top:0}.nav-divider{height:1px;background:#1c2830;margin:8px 4px}.app-shell>main{display:grid;grid-template-rows:auto minmax(0,1fr);gap:8px}.subjectbar{display:none;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:center;padding:9px 11px;border:1px solid #2a3b45;border-radius:10px;background:linear-gradient(145deg,#111920,#0a1015);min-width:0}.subjectbar.active{display:grid}.subject-name{font-weight:850;font-size:15px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.subject-meta{font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.subject-actions{display:flex;gap:5px;align-items:center;flex-wrap:wrap;justify-content:flex-end}.subject-actions button{padding:6px 8px;font-size:11px}.subject-severity{font-size:11px;font-weight:800;text-transform:uppercase}.subject-questions{display:none;grid-column:1/-1;padding-top:8px;border-top:1px solid #223039;gap:6px;flex-wrap:wrap}.subject-questions.open{display:flex}.question-chip{font-size:11px;padding:5px 8px;background:#0d151b}
.context-help{display:inline-grid;place-items:center;width:20px;height:20px;padding:0;margin-left:4px;border-radius:999px;font-size:11px}.help-drawer{position:absolute;z-index:70;top:72px;right:18px;width:min(430px,calc(100% - 36px));max-height:calc(100% - 90px);overflow:auto;border:1px solid #34434e;border-radius:12px;background:#0c1217;box-shadow:0 20px 55px rgba(0,0,0,.52);padding:14px}.help-drawer[hidden]{display:none}.help-drawer-head{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.help-drawer h3{margin:0}.help-drawer p{color:#c6d3d9}.help-drawer .muted{font-size:12px}
.dossier-overview{display:grid;gap:10px}.dossier-hero{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(260px,.65fr);gap:10px}.version-history{border:1px solid var(--line);background:var(--panel);padding:0}.version-history-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;padding:10px 12px;border-bottom:1px solid var(--line)}.version-history-head h4{margin:0}.version-history-list{display:grid}.version-row{display:grid;grid-template-columns:minmax(130px,.8fr) minmax(100px,.55fr) minmax(120px,.7fr) minmax(170px,1fr);gap:10px;align-items:center;padding:9px 12px;border-top:1px solid #d9d9d9}.version-row:first-child{border-top:0}.version-row.current{border-left:4px solid #0f62fe;background:#edf5ff}.version-row.archive{color:#525252}.version-badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:2px 6px;background:#e0e0e0;color:#161616}.version-row.current .version-badge{background:#0f62fe;color:#fff}.version-security{display:flex;gap:6px;align-items:center;flex-wrap:wrap}.version-note{font-size:11px;color:#6f6f6f}.dossier-summary{padding:13px;border:1px solid #294049;border-radius:10px;background:linear-gradient(145deg,#0d171b,#0b1116)}.dossier-summary h3{margin:0 0 5px}.dossier-summary p{margin:0;color:#c2d0d6}.coverage-matrix{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px}.coverage-item{padding:8px;border:1px solid #24313a;border-radius:8px;background:#0a1015}.coverage-item .label{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#718792}.coverage-item .value{font-weight:750;margin-top:2px}.explain-card{margin:8px 0;padding:9px 10px;border-left:3px solid #365661;background:#0a1116;border-radius:0 8px 8px 0}.explain-card b{display:block;margin-bottom:3px}.explain-actions{display:flex;gap:5px;flex-wrap:wrap;margin-top:7px}.explain-actions button{padding:5px 7px;font-size:11px}.lens-explorer .technical-detail{opacity:.72}.lens-researcher .plain-language{font-size:12px}.lens-developer .developer-emphasis{border-color:#3a5963}
.relation-graph{position:relative;min-height:380px;overflow:auto;border:1px solid #22313a;border-radius:10px;background:radial-gradient(circle at 50% 45%,rgba(54,213,208,.045),transparent 35%),#080d11}.relation-graph-inner{position:relative;min-width:720px;min-height:380px}.relation-graph svg{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}.relation-node{position:absolute;width:150px;min-height:52px;transform:translate(-50%,-50%);padding:7px 8px;border:1px solid #30414b;border-radius:9px;background:#10171d;font-size:11px;word-break:break-word;z-index:2}.relation-node b{display:block;color:#e8f0f3}.relation-node.plugin,.relation-node.variant{border-color:#327079}.relation-node.endpoint{border-color:#415f87}.relation-node.component{border-color:#5a5b7e}.relation-node.advisory{border-color:#80504d}.relation-node.source{border-color:#446a55}.relation-node.artifact{border-color:#6b5d42}.relation-edge{stroke:#334752;stroke-width:1.4;fill:none}.relation-edge-label{fill:#7d919c;font-size:9px}.relation-filterbar{display:flex;gap:5px;flex-wrap:wrap;margin:8px 0}.relation-filterbar button.active{border-color:var(--cyan);background:#102127}
.compare-toolbar{display:flex;gap:7px;flex-wrap:wrap;align-items:center;margin-bottom:10px}.compare-toolbar select{min-width:300px;max-width:100%}.compare-change{display:grid;grid-template-columns:76px minmax(0,1fr);gap:9px;padding:8px 0;border-bottom:1px solid #1b252c}.compare-change:last-child{border-bottom:0}.compare-direction{text-transform:uppercase;font-size:10px;font-weight:850;letter-spacing:.06em}.compare-direction.added,.compare-direction.increased{color:var(--amber)}.compare-direction.removed,.compare-direction.decreased{color:var(--green)}.compare-direction.changed{color:var(--blue)}.compare-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}
.system-health-card .n{font-size:18px}.system-health-state{display:flex;align-items:center;gap:7px;font-weight:800}.system-health-state::before{content:'';width:9px;height:9px;border-radius:50%;background:#596975}.system-health-state.pass::before{background:var(--green)}.system-health-state.fail::before{background:var(--red)}.system-health-state.gated::before{background:var(--amber)}.technical-revisions{max-height:32vh;overflow:auto}
@media(max-width:1100px){.omnibox-wrap{min-width:220px}.dossier-hero{grid-template-columns:1fr}.subjectbar{grid-template-columns:1fr}.subject-actions{justify-content:flex-start}}
@media(max-width:760px){.omnibox-wrap{order:20;flex-basis:100%;max-width:none}.subject-actions{overflow-x:auto;flex-wrap:nowrap}.coverage-matrix,.compare-grid{grid-template-columns:1fr}.help-drawer{right:8px;width:calc(100% - 16px)}}


/* DeltaScope 4.9 perspectives: the selector changes the user's workbench, not just density. */
.perspective-switch{display:flex;align-items:center;gap:7px;padding:4px 7px;border:1px solid #2a3943;border-radius:9px;background:#0d1419}.perspective-switch-label{font-size:9px;font-weight:850;letter-spacing:.1em;text-transform:uppercase;color:#6e8490}.perspective-select{min-width:155px;padding:5px 8px;border:0;background:#111a20;font-size:12px;font-weight:750}.perspective-select:focus{outline:1px solid var(--cyan)}
#perspectiveNav{display:flex;flex-direction:column;min-height:0}.perspective-nav-description{padding:0 10px 9px;color:#6f8490;font-size:11px;line-height:1.35}.workbench-nav button[data-perspective-route].active{background:#102127;border-color:#285b62;color:#eef4f7}.workbench-nav button[data-perspective-route] .nav-mark{flex:0 0 auto}
.subjectbar.perspective-hidden{display:none!important}
.perspective-developer .developer-only{display:block}.perspective-investigator .developer-only,.perspective-researcher .developer-only,.perspective-operations .developer-only{display:none}
.developer-home{display:grid;gap:11px}.developer-welcome{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(280px,.8fr);gap:11px}.developer-primary{padding:16px;border:1px solid #2d5058;border-radius:12px;background:linear-gradient(145deg,#0d181c,#0a1116)}.developer-primary h2{margin:0 0 5px}.developer-primary p{margin:0;color:#c5d2d7}.developer-health{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}.developer-status{padding:10px;border:1px solid #27353e;border-radius:9px;background:#0b1116}.developer-status .label{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:#718692}.developer-status .value{margin-top:3px;font-weight:800}.developer-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:11px}.developer-actions button{padding:6px 8px}.developer-needs{display:grid;gap:7px}.developer-need{display:grid;grid-template-columns:24px minmax(0,1fr) auto;gap:9px;align-items:start;padding:10px;border:1px solid #26333b;border-radius:9px;background:#0b1116}.developer-need.good{border-color:#23483e}.developer-need.warn{border-color:#5d4c2c}.developer-need.bad{border-color:#68383b}.developer-need-mark{display:grid;place-items:center;width:22px;height:22px;border-radius:7px;background:#121b21;font-weight:900}.developer-need button{padding:5px 7px;font-size:11px}
.profile-builder-shell{display:grid;gap:10px}.profile-builder-intro{padding:11px 12px;border-left:3px solid var(--cyan);border-radius:0 9px 9px 0;background:#0b1419}.profile-builder-intro p{margin:4px 0 0}.profile-progress{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px}.profile-progress .card .n{font-size:20px}.profile-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.profile-field{display:grid;gap:4px}.profile-field.wide{grid-column:1/-1}.profile-field label{font-size:11px;font-weight:750;color:#aab9c1}.profile-field textarea{min-height:80px}.profile-capability-list{display:grid;gap:8px}.profile-capability{padding:10px;border:1px solid #283741;border-radius:9px;background:#0b1116}.profile-capability-head{display:flex;gap:8px;align-items:flex-start;justify-content:space-between}.profile-capability-id{font:11px Consolas,monospace;color:#7d949f}.profile-capability-controls{display:flex;gap:9px;flex-wrap:wrap}.profile-capability-controls label{display:inline-flex;gap:5px;align-items:center;font-size:11px}.profile-capability input[type=checkbox]{width:auto;min-width:0}.profile-capability textarea{min-height:54px;margin-top:7px}.profile-destination-suggestion{font-size:11px;color:#8296a0;margin-top:4px}.profile-preview{min-height:330px;font:12px/1.45 Consolas,monospace}.profile-validation{padding:9px 10px;border:1px solid #26343c;border-radius:8px;background:#0a1014}.profile-validation.pass{border-color:#285544}.profile-validation.fail{border-color:#6b3438}.profile-builder-actions{display:flex;gap:6px;flex-wrap:wrap}.profile-builder-actions button.primary{border-color:#2b6e70;background:#10282a}.profile-existing{padding:8px 10px;border:1px solid #2a3942;border-radius:8px;background:#0a1014}
.journey-node.click{cursor:pointer}.journey-node.click:hover{border-color:#3b7477;background:#0e171b}.journey-node.selected{border-color:var(--cyan)!important;box-shadow:0 0 0 1px rgba(54,213,208,.2)}.journey-explanation{max-width:860px;margin:14px auto 4px;padding:13px 14px;border:1px solid #31505b;border-radius:11px;background:linear-gradient(145deg,#0d171c,#0a1116)}.journey-explanation-head{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.journey-explanation h4{margin:0}.journey-explanation-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:10px}.journey-explanation-block{padding:9px;border:1px solid #24333b;border-radius:8px;background:#0a1015}.journey-explanation-block b{display:block;margin-bottom:3px}.journey-produced{display:flex;gap:5px;flex-wrap:wrap}.journey-actionbar{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}.journey-actionbar button{padding:6px 8px;font-size:11px}.journey-technical{margin-top:8px}
.dashboard-gate-shell{margin:0 0 10px;border:1px solid rgba(255,191,77,.42);border-left:4px solid var(--amber);border-radius:11px;background:linear-gradient(145deg,rgba(255,191,77,.07),rgba(15,20,25,.96));padding:11px 12px}.dashboard-gate-head{display:flex;gap:10px;align-items:flex-start;justify-content:space-between}.dashboard-gate-title{font-weight:850}.dashboard-gate-kicker{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--amber);font-weight:850}.dashboard-gate-items{display:grid;gap:5px;margin-top:7px}.report-block{border:1px solid var(--line);border-radius:9px;background:#0b1116;margin:0 0 9px;overflow:hidden}.report-block-head{display:flex;justify-content:space-between;gap:9px;padding:10px 11px;border-bottom:1px solid var(--line)}.report-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:7px;padding:9px 11px}.report-metric{padding:8px;border:1px solid #22313a;border-radius:8px;background:#0e151a}.report-metric .n{font-size:18px;font-weight:850}.report-provenance{padding:0 11px 9px;color:var(--muted);font-size:11px}
@media(max-width:980px){.developer-welcome{grid-template-columns:1fr}.profile-progress,.profile-form-grid,.journey-explanation-grid{grid-template-columns:1fr}.profile-field.wide{grid-column:auto}.perspective-switch{order:2}.perspective-select{min-width:135px}}


/* DeltaScope 4.11 OpenShift/Carbon shell: perspective in the left rail, minimal global header. */
:root{color-scheme:light;--bg:#f4f4f4;--panel:#ffffff;--panel2:#f4f4f4;--line:#e0e0e0;--text:#161616;--muted:#525252;--cyan:#0f62fe;--red:#da1e28;--amber:#f1c21b;--green:#198038;--blue:#0f62fe}
body{background:#f4f4f4!important;color:#161616!important;font-family:'IBM Plex Sans',Inter,'Segoe UI',Arial,sans-serif}
header{height:48px!important;min-height:48px!important;padding:0 16px!important;background:#161616!important;color:#f4f4f4!important;border-bottom:0!important;box-shadow:none!important;overflow:visible!important;gap:12px!important}
.brand{height:48px;gap:9px;color:#f4f4f4;font-size:14px;letter-spacing:.04em}.omega-mark{width:28px;height:28px;border-radius:0!important;background:#262626!important;border-color:#525252!important;box-shadow:none!important;color:#f4f4f4!important}
.perspective-switch{height:48px;padding:0 12px!important;margin:0;border:0!important;border-left:1px solid #393939!important;border-radius:0!important;background:#161616!important;gap:8px}.perspective-switch-label{color:#c6c6c6!important;font-size:10px}.perspective-select{height:32px;min-width:166px!important;padding:0 28px 0 8px!important;border:1px solid #525252!important;border-radius:0!important;background:#262626!important;color:#f4f4f4!important}.perspective-select:focus{outline:2px solid #78a9ff!important;outline-offset:-2px}
.header-plugin-switch{display:flex;align-items:center;gap:7px;height:48px;padding-left:12px;border-left:1px solid #393939}.header-plugin-switch label{font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#c6c6c6;white-space:nowrap}.header-plugin-select{height:32px;width:min(310px,26vw);min-width:170px;border:1px solid #525252!important;border-radius:0!important;background:#262626!important;color:#f4f4f4!important;padding:0 28px 0 9px!important}.header-plugin-select:focus{outline:2px solid #78a9ff!important;outline-offset:-2px}
.omnibox-wrap{min-width:210px!important;max-width:440px!important;flex:1 1 300px!important}.omnibox-wrap input{height:32px!important;border:1px solid #525252!important;border-radius:0!important;background:#262626!important;color:#f4f4f4!important;padding:0 10px 0 34px!important}.omnibox-wrap input::placeholder{color:#a8a8a8}.omnibox-wrap::before{top:5px!important;color:#c6c6c6!important}.omnibox-results{top:37px!important;border-radius:0!important;border-color:#8d8d8d!important;background:#fff!important;color:#161616!important;box-shadow:0 4px 16px rgba(0,0,0,.24)!important}.search-result:hover,.search-result.active{background:#e8e8e8!important;border-color:#0f62fe!important}.search-kind{border-radius:0!important;color:#0f62fe!important;border-color:#a8a8a8!important}.search-result-sub,.search-group{color:#525252!important}
.header-icon-button{position:relative;display:grid;place-items:center;width:48px;height:48px;padding:0!important;border:0!important;border-radius:0!important;background:#161616!important;color:#f4f4f4!important}.header-icon-button:hover{background:#353535!important}.header-icon-button svg{width:20px;height:20px;fill:currentColor}.notification-count{position:absolute;right:7px;top:6px;display:none;min-width:17px;height:17px;padding:0 4px;border-radius:9px;background:#da1e28;color:#fff;font-size:10px;font-weight:700;line-height:17px;text-align:center}.notification-count.active{display:block}.notification-drawer{position:fixed;z-index:120;right:8px;top:52px;width:min(430px,calc(100vw - 16px));max-height:calc(100vh - 64px);overflow:auto;background:#fff;color:#161616;border:1px solid #8d8d8d;box-shadow:0 8px 24px rgba(0,0,0,.24)}.notification-drawer[hidden]{display:none}.notification-head{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid #e0e0e0}.notification-head h2{margin:0;font-size:18px}.notification-head-actions{display:flex;gap:4px}.notification-head-actions button{border:0!important;background:transparent!important;color:#0f62fe!important;border-radius:0!important}.notification-list{display:grid}.notification-item{display:grid;grid-template-columns:4px minmax(0,1fr);padding:0;border-bottom:1px solid #e0e0e0;background:#fff}.notification-item:hover{background:#f4f4f4}.notification-level{background:#8d8d8d}.notification-item.critical .notification-level,.notification-item.fail .notification-level{background:#da1e28}.notification-item.warn .notification-level{background:#f1c21b}.notification-item.info .notification-level{background:#0f62fe}.notification-body{padding:12px 14px}.notification-title{font-weight:700}.notification-detail{margin-top:3px;color:#525252;font-size:12px}.notification-meta{margin-top:7px;color:#6f6f6f;font-size:11px}.notification-empty{padding:24px 16px;color:#525252;text-align:center}
.app-switcher-button{margin-left:0}.app-switcher-drawer{position:fixed;z-index:121;right:8px;top:52px;width:min(360px,calc(100vw - 16px));background:#fff;color:#161616;border:1px solid #8d8d8d;box-shadow:0 8px 24px rgba(0,0,0,.24)}.app-switcher-drawer[hidden]{display:none}.app-switcher-head{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid #e0e0e0}.app-switcher-head h2{margin:0;font-size:18px}.app-switcher-close{width:36px;height:36px;padding:0!important;border:0!important;border-radius:0!important;background:transparent!important;color:#161616!important;font-size:22px}.app-switcher-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;background:#e0e0e0}.app-switcher-item{min-height:116px;padding:14px 10px!important;border:0!important;border-radius:0!important;background:#fff!important;color:#161616!important;text-align:left;display:flex;flex-direction:column;justify-content:space-between;gap:10px}.app-switcher-item:hover{background:#f4f4f4!important}.app-switcher-icon{width:28px;height:28px;display:grid;place-items:center;color:#0f62fe}.app-switcher-icon svg{width:24px;height:24px;fill:currentColor}.app-switcher-title{font-weight:700;font-size:13px}.app-switcher-sub{display:block;margin-top:2px;color:#6f6f6f;font-size:11px;line-height:1.3}.app-switcher-note{padding:10px 14px;color:#6f6f6f;font-size:11px;border-top:1px solid #e0e0e0;background:#f4f4f4}
.app-shell{grid-template-columns:256px minmax(0,1fr)!important;background:#f4f4f4!important}.workbench-nav{background:#161616!important;color:#f4f4f4!important;border-right:0!important;padding:8px 0!important}.workbench-nav-title,.workbench-nav-title.group{padding:12px 16px 6px!important;margin:0!important;color:#8d8d8d!important;font-size:10px!important;letter-spacing:.08em!important}.perspective-nav-description{padding:0 16px 12px!important;color:#a8a8a8!important}.workbench-nav button[data-perspective-route]{min-height:40px;margin:0!important;padding:0 16px!important;border:0!important;border-radius:0!important;background:#161616!important;color:#c6c6c6!important;text-align:left}.workbench-nav button[data-perspective-route]:hover{background:#262626!important;color:#f4f4f4!important}.workbench-nav button[data-perspective-route].active{background:#262626!important;color:#fff!important;box-shadow:inset 4px 0 0 #0f62fe!important}.workbench-nav button[data-perspective-route] .nav-mark{border:0!important;background:transparent!important;color:#78a9ff!important}.workbench-nav-note{margin:10px 16px 0!important;padding:12px 0!important;border-top:1px solid #393939!important;color:#a8a8a8!important}
.app-shell>main{background:#f4f4f4!important;padding:24px 28px!important;gap:16px!important;max-width:none!important}.subjectbar{display:none!important}.workspace-heading{color:#161616!important}.workspace-heading h1{font-size:28px!important;font-weight:400!important;letter-spacing:0!important}.workspace-heading p{color:#525252!important;max-width:900px}.badge,.badge.ro{border-radius:999px;background:#e0e0e0;color:#393939}.workspace-heading .badge.ro{background:#defbe6;color:#0e6027}
.panel,.card{background:#fff!important;color:#161616!important;border:1px solid #e0e0e0!important;border-radius:0!important;box-shadow:none!important}.panelhead{background:#fff!important;border-bottom:1px solid #e0e0e0!important}.card{min-height:104px;padding:16px!important}.card .n{font-size:24px!important;font-weight:400!important}.card .muted,.muted{color:#525252!important}.card.clickable:hover{transform:none!important;background:#f4f4f4!important;border-color:#0f62fe!important}.card.clickable::after{color:#0f62fe!important}
button,input,select,textarea{border-radius:0!important}.app-shell>main button{background:#fff;color:#161616;border:1px solid #8d8d8d}.app-shell>main button:hover{border-color:#0f62fe;background:#f4f4f4}.app-shell>main input,.app-shell>main select,.app-shell>main textarea{background:#fff!important;color:#161616!important;border:1px solid #8d8d8d!important}.app-shell>main input:focus,.app-shell>main select:focus,.app-shell>main textarea:focus{outline:2px solid #0f62fe;outline-offset:-2px}
.focusbar,.developer-primary,.developer-status,.developer-need,.research-box,.profile-builder-intro,.profile-capability,.profile-validation,.profile-existing,.journey-explanation,.journey-explanation-block,.dossier-summary,.coverage-item,.explain-card,.report-block,.report-metric,.readonly-boundary,.relation-node,.rule-workspace-panel,.rule-library-panel,.rule-intel-panel,.visual-palette,.visual-properties{background:#fff!important;color:#161616!important;border-color:#e0e0e0!important;border-radius:0!important;box-shadow:none!important}.developer-primary,.profile-builder-intro,.explain-card{border-left:4px solid #0f62fe!important}.developer-primary p,.dossier-summary p,.toni-inline-message,.plain-language{color:#525252!important}.profile-field label,.source-confidence,.case-subtitle{color:#525252!important}.research-tabs,.case-header{background:#fff!important;border-color:#e0e0e0!important}.research-tab{background:#fff!important;color:#393939!important;border-color:#8d8d8d!important;border-radius:0!important}.research-tab.active{background:#e8e8e8!important;color:#161616!important;border-bottom:3px solid #0f62fe!important}.finding,.signal{background:#fff!important;border-color:#e0e0e0!important;border-radius:0!important}.code{background:#f4f4f4!important;color:#161616!important;border:1px solid #e0e0e0!important;border-radius:0!important}.relation-graph,.visual-canvas{background:#f4f4f4!important;border-color:#e0e0e0!important;border-radius:0!important}.relation-node{border-color:#8d8d8d!important}.relation-edge{stroke:#8d8d8d!important}.relation-edge-label{fill:#525252!important}.profile-preview,#docContent{background:#f4f4f4!important;color:#161616!important;border-color:#e0e0e0!important}.table-button:hover,.table-button.active,.doc-item:hover,.doc-item.active{background:#e8e8e8!important;color:#161616!important}.db-sidebar,.db-main,th,td{border-color:#e0e0e0!important}th{background:#e8e8e8!important;color:#393939!important}.triage-row.selected{background:#edf5ff!important;box-shadow:inset 4px 0 0 #0f62fe!important}tr.click:hover{background:#f4f4f4!important}.help-drawer{background:#fff!important;color:#161616!important;border-color:#8d8d8d!important;border-radius:0!important;box-shadow:0 8px 24px rgba(0,0,0,.24)!important}.help-drawer p{color:#393939!important}
.dashboard-gate-shell{background:#fff!important;border:1px solid #f1c21b!important;border-left:4px solid #f1c21b!important;border-radius:0!important}.dashboard-overview-grid{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(320px,.65fr);gap:16px;margin-bottom:16px}.dashboard-platform-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0}.dashboard-platform-item{min-height:96px;padding:14px 16px;border-right:1px solid #e0e0e0;border-bottom:1px solid #e0e0e0}.dashboard-platform-item:nth-child(2n){border-right:0}.dashboard-platform-item .label{font-size:11px;color:#525252;text-transform:uppercase;letter-spacing:.05em}.dashboard-platform-item .value{margin-top:7px;font-size:18px;font-weight:400;word-break:break-word}.dashboard-platform-item .detail{padding:4px 0 0;color:#6f6f6f;font-size:11px}.dashboard-notification-preview{display:grid}.dashboard-notification-preview .notification-item:last-child{border-bottom:0}.dashboard-actions{display:flex;gap:8px;align-items:center}.dashboard-actions button.primary{background:#0f62fe!important;color:#fff!important;border-color:#0f62fe!important}.dashboard-actions button.primary:hover{background:#0043ce!important}.dashboard-grid{gap:16px!important}
.sev-critical{color:#da1e28!important}.sev-high{color:#a2191f!important}.sev-caution,.sev-medium{color:#8e6a00!important}.sev-informational{color:#0043ce!important}.pass{color:#198038!important}.warn{color:#8e6a00!important}.fail{color:#da1e28!important}.info{color:#0043ce!important}.system-health-state.pass::before{background:#198038!important}.system-health-state.fail::before{background:#da1e28!important}.system-health-state.gated::before{background:#f1c21b!important}
main details,main details>summary{background:#fff!important;color:#161616!important;border-color:#e0e0e0!important;border-radius:0!important}.engine-pill,.source-state,.case-summary .pill{background:#fff!important;color:#393939!important;border-color:#8d8d8d!important;border-radius:999px!important}.engine-pill b{color:#161616!important}.readonly-boundary{color:#393939!important}.timeline-row{border-color:#8d8d8d!important}.rule-tree,.rule-smart-editor,.rule-code-wrap,.rule-outline,.rule-context-doc,.rule-inline-diagnostics{color:#161616!important}.active-snapshot-note{background:#f4f4f4!important;color:#525252!important}.component-state,.incident-badge{border-radius:999px!important}

/* Plugin Developer owns one selected plugin from the global My plugin selector.
   Corpus browsing belongs to Investigator / Security Researcher, so never show the
   Assets research queue inside developer routes such as Security Review, Journey,
   Changes, Omega Profile or Source & Build. */
body.perspective-developer #workbench-assets>.research-layout{grid-template-columns:minmax(0,1fr)!important}
body.perspective-developer #workbench-assets .triage-panel{display:none!important}
body.perspective-developer #workbench-assets #researchCase{grid-column:1/-1!important;width:100%!important;max-width:none!important}
body.perspective-developer #workbench-assets #pluginDetail{width:100%!important}

/* DeltaScope 4.11.2 shell alignment: the global bar is exactly 48px, with no
   unused 64px grid row below it, and the product name is stacked like the
   compact OpenShift product masthead. */
body{grid-template-rows:48px minmax(0,1fr)!important}
.brand{min-width:150px!important;display:flex!important;align-items:center!important}
.brand-copy{display:flex;flex-direction:column;justify-content:center;line-height:1.02;white-space:nowrap}
.brand-omega{font-size:12px;font-weight:800;letter-spacing:.08em;color:#f4f4f4}
.brand-deltascope{margin-top:2px;font-size:10px;font-weight:500;letter-spacing:.06em;color:#c6c6c6}

/* OpenShift-style shell placement: the perspective is a left-rail system switch. */
.sr-only{position:absolute!important;width:1px!important;height:1px!important;padding:0!important;margin:-1px!important;overflow:hidden!important;clip:rect(0,0,0,0)!important;white-space:nowrap!important;border:0!important}
.shell-nav-toggle{flex:0 0 48px;margin-left:-16px!important;border-right:1px solid #393939!important}.brand{min-width:210px}.header-plugin-switch{margin-left:0!important}.notification-button{margin-left:auto}
.workbench-nav{padding-top:0!important}.rail-perspective-switch{display:block!important;width:100%;height:52px!important;padding:0!important;border:0!important;border-bottom:1px solid #525252!important;background:#262626!important}.rail-perspective-switch .perspective-select{display:block;width:100%;height:52px;min-width:0!important;padding:0 38px 0 18px!important;border:0!important;background:#262626!important;color:#f4f4f4!important;font-size:14px;font-weight:600}.rail-perspective-switch .perspective-select:hover{background:#353535!important}.rail-perspective-switch .perspective-select:focus{outline:2px solid #78a9ff!important;outline-offset:-2px!important}
.nav-collapsed .app-shell{grid-template-columns:0 minmax(0,1fr)!important}.nav-collapsed .workbench-nav{display:none!important}.nav-collapsed .shell-nav-toggle{background:#353535!important}
.developer-home>.developer-welcome,.developer-home>.panel{margin-bottom:0}.developer-home .developer-primary{min-height:180px}.developer-home .developer-health{align-content:stretch}.developer-home .developer-status{min-height:86px;padding:14px!important}
@media(max-width:1180px){.header-plugin-select{width:210px}.omnibox-wrap{max-width:300px!important}.dashboard-overview-grid{grid-template-columns:1fr}}
@media(max-width:900px){header{height:auto!important;min-height:48px!important;flex-wrap:wrap!important;padding:0 8px!important}.header-plugin-switch{height:40px}.omnibox-wrap{order:8;flex-basis:100%!important;max-width:none!important}.app-shell{grid-template-columns:1fr!important}.workbench-nav{max-height:44px!important;overflow-x:auto!important;display:flex!important}.workbench-nav #perspectiveNav{flex-direction:row!important}.rail-perspective-switch{flex:0 0 180px!important;height:44px!important}.rail-perspective-switch .perspective-select{height:44px!important}.workbench-nav-title,.perspective-nav-description,.workbench-nav-note{display:none!important}.workbench-nav button[data-perspective-route]{white-space:nowrap!important}.dashboard-platform-grid{grid-template-columns:1fr}.dashboard-platform-item{border-right:0!important}}


/* DeltaScope 4.12.0 workbench refinement: OpenShift-style navigation, TONI rail,
   compact plugin picker, collapsible rule library and dark Stigma-1 editor. */
header .plugin-picker-button{margin-left:auto!important}
.header-plugin-switch{display:none!important}
.plugin-picker-state{position:absolute;right:8px;bottom:7px;width:7px;height:7px;border-radius:50%;background:transparent}
.plugin-picker-state.active{background:#42be65;box-shadow:0 0 0 2px #161616}
.plugin-picker-drawer{position:fixed;z-index:122;right:104px;top:52px;width:min(390px,calc(100vw - 16px));max-height:calc(100vh - 64px);display:flex;flex-direction:column;background:#fff;color:#161616;border:1px solid #8d8d8d;box-shadow:0 8px 24px rgba(0,0,0,.24)}
.plugin-picker-drawer[hidden]{display:none}
.plugin-picker-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;border-bottom:1px solid #e0e0e0}
.plugin-picker-head h2{margin:0;font-size:18px;font-weight:400}
.plugin-picker-close{width:36px;height:36px;padding:0!important;border:0!important;background:transparent!important;color:#161616!important;font-size:22px}
.plugin-picker-search-wrap{padding:12px 14px;background:#f4f4f4;border-bottom:1px solid #e0e0e0}
.plugin-picker-search-wrap input{width:100%;height:40px;background:#fff!important;color:#161616!important;border:0!important;border-bottom:1px solid #8d8d8d!important;padding:0 12px!important}
.plugin-picker-search-wrap input:focus{outline:2px solid #0f62fe!important;outline-offset:-2px!important}
.plugin-picker-list{overflow:auto;min-height:120px;max-height:min(560px,65vh)}
.plugin-picker-item{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;width:100%;padding:11px 14px!important;border:0!important;border-bottom:1px solid #e0e0e0!important;background:#fff!important;color:#161616!important;text-align:left}
.plugin-picker-item:hover,.plugin-picker-item.active{background:#e8e8e8!important}
.plugin-picker-item.active{box-shadow:inset 4px 0 0 #0f62fe!important}
.plugin-picker-name{font-weight:600}.plugin-picker-meta{display:block;margin-top:2px;color:#6f6f6f;font-size:11px}.plugin-picker-severity{font-size:10px;font-weight:700;text-transform:uppercase}
.plugin-picker-empty{padding:24px 14px;color:#525252;text-align:center}

.workbench-nav{display:flex!important;flex-direction:column!important;overflow:hidden!important;background:#151515!important}
#perspectiveNav{flex:1 1 auto;min-height:0;overflow:auto;padding-bottom:8px}
.nav-section{border-bottom:1px solid #393939}
.nav-section-toggle{display:flex!important;align-items:center!important;justify-content:space-between!important;width:100%!important;min-height:40px!important;margin:0!important;padding:0 16px!important;border:0!important;border-radius:0!important;background:#252525!important;color:#f4f4f4!important;font-size:13px!important;font-weight:600!important}
.nav-section-toggle:hover{background:#353535!important}
.nav-section-toggle svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:1.7;transition:transform .12s ease}
.nav-section.collapsed .nav-section-toggle svg{transform:rotate(-90deg)}
.nav-section.collapsed .nav-section-items{display:none}
.nav-section-items{padding:0}
.workbench-nav button[data-perspective-route]{gap:12px!important;padding-left:20px!important}
.nav-icon{display:grid;place-items:center;width:20px;height:20px;flex:0 0 20px;color:#c6c6c6}
.nav-icon svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.workbench-nav button[data-perspective-route].active .nav-icon{color:#78a9ff}
.perspective-nav-description{padding:10px 16px 12px!important;border-bottom:1px solid #393939!important;color:#a8a8a8!important}
.toni-rail{flex:0 0 auto;margin-top:auto;padding:12px 14px 14px;border-top:1px solid #393939;background:#111;color:#c6c6c6}
.toni-rail-head{display:flex;align-items:center;gap:8px;color:#fff}.toni-rail-head>span:last-child{display:grid;line-height:1.05}.toni-rail-head small{margin-top:3px;color:#8d8d8d;font-size:9px;text-transform:uppercase;letter-spacing:.08em}
.toni-rail-message{margin-top:9px;color:#a8a8a8;font-size:11px;line-height:1.45;max-height:84px;overflow:auto}
.toni-rail-actions{display:flex;gap:4px;margin-top:9px}.toni-rail-actions button{min-height:28px!important;padding:0 7px!important;border:1px solid #525252!important;background:#161616!important;color:#c6c6c6!important;font-size:10px!important}.toni-rail-actions button:hover{border-color:#78a9ff!important;color:#fff!important;background:#262626!important}

#workbench-rules>.compact-rule-heading{flex:0 0 auto;margin:0 0 8px}
#workbench-rules>.compact-rule-heading h1{font-size:22px!important}
#workbench-rules>.compact-rule-heading p{font-size:12px;margin-top:2px}
#workbench-rules>#ruleCatalogCards{display:none!important}
#workbench-rules>.readonly-boundary{display:none!important}
#workbench-rules .rule-workspace-head{min-height:44px;padding:7px 10px!important;align-items:center!important}
#workbench-rules #ruleWorkspaceKicker,#workbench-rules #ruleWorkspaceMeta{display:none!important}
#workbench-rules .rule-workspace-head h2{margin:0!important;font-size:16px!important;font-weight:600!important}
#workbench-rules .rule-workspace-actions{gap:4px!important}
#workbench-rules .rule-workspace-actions button{min-height:32px;padding:0 9px!important;font-size:11px}
.rule-library-head{min-height:44px;padding:0 8px 0 12px!important;align-items:center!important}
.rule-library-heading-copy{min-width:0}.rule-library-heading-copy h2{font-size:15px!important}.rule-library-heading-copy .small{font-size:10px}
.rule-library-toggle{width:32px;height:32px;padding:0!important;border:0!important;background:transparent!important;color:#525252!important;font-size:24px!important;line-height:1}
.rule-library-toggle:hover{background:#e8e8e8!important;color:#0f62fe!important}
#ruleBrowserShell.rule-library-collapsed{grid-template-columns:42px minmax(0,1fr)!important}
#ruleBrowserShell.rule-library-collapsed .rule-library-panel{overflow:hidden!important}
#ruleBrowserShell.rule-library-collapsed .rule-library-heading-copy,#ruleBrowserShell.rule-library-collapsed #ruleLibraryCount,#ruleBrowserShell.rule-library-collapsed .rule-library-search,#ruleBrowserShell.rule-library-collapsed .rule-library-legend,#ruleBrowserShell.rule-library-collapsed #ruleTree{display:none!important}
#ruleBrowserShell.rule-library-collapsed .rule-library-head{padding:0!important;justify-content:center!important;border-bottom:0!important}
#ruleBrowserShell.rule-library-collapsed .rule-library-toggle{width:42px;height:44px;color:#0f62fe!important;transform:rotate(180deg)}
#ruleBrowserShell.rule-library-collapsed .rule-lab-editor.smart{display:grid!important;grid-template-columns:250px minmax(0,1fr);grid-template-rows:auto minmax(0,1fr) auto auto auto;grid-template-areas:"intel toolbar" "intel editor" "intel status" "intel diagnostics" "intel actions";gap:0!important;padding:0!important}
#ruleBrowserShell.rule-library-collapsed .rule-smart-toolbar{grid-area:toolbar}
#ruleBrowserShell.rule-library-collapsed .rule-smart-editor{grid-area:editor;height:min(68vh,820px)!important;min-height:480px!important}
#ruleBrowserShell.rule-library-collapsed .rule-editor-statusbar{grid-area:status}
#ruleBrowserShell.rule-library-collapsed .rule-intelligence-grid{grid-area:intel;display:flex!important;flex-direction:column!important;gap:8px!important;margin:0!important;padding:8px!important;overflow:auto;border-right:1px solid #343a40;background:#0d1117}
#ruleBrowserShell.rule-library-collapsed .rule-intel-panel{flex:0 0 auto}
#ruleBrowserShell.rule-library-collapsed .rule-flow-panel{grid-column:auto}
#ruleBrowserShell.rule-library-collapsed .rule-inline-diagnostics{grid-area:diagnostics;margin:0!important;padding:8px}
#ruleBrowserShell.rule-library-collapsed .rule-lab-actions{grid-area:actions;margin:0!important;padding:8px;border-top:1px solid #343a40}
#workbench-rules .rule-workspace-panel{background:#fff!important}

/* Keep the authoring surface dark inside the light workbench. */
#workbench-rules .rule-lab-editor.smart{background:#0d1117!important;color:#f4f4f4!important;border-color:#343a40!important}
#workbench-rules .rule-smart-toolbar{background:#161b22!important;color:#f4f4f4!important;border-color:#343a40!important;border-radius:0!important}
#workbench-rules .rule-smart-toolbar button{background:#262b33!important;color:#f4f4f4!important;border-color:#525860!important}
#workbench-rules .rule-smart-editor{background:#080c10!important;border-color:#343a40!important}
#workbench-rules .rule-editor-gutter{background:#0d1117!important;border-color:#2d333b!important;color:#697682!important}
#workbench-rules .rule-code-wrap pre{background:#080c10!important;color:#d9e4ea!important}
#workbench-rules .rule-code-wrap textarea,#workbench-rules textarea#ruleYaml{background:transparent!important;color:transparent!important;-webkit-text-fill-color:transparent!important;border:0!important;caret-color:#f4fbff!important}
#workbench-rules .rule-editor-statusbar{background:#161b22!important;color:#a8b3bc!important;border-color:#343a40!important}
#workbench-rules .rule-intel-panel{background:#10151b!important;color:#e0e6ea!important;border-color:#343a40!important}
#workbench-rules .rule-intel-title{color:#8fa1ad!important}
#workbench-rules .rule-context-doc{color:#c6d0d6!important}
#workbench-rules .rule-suggestion-chip,#workbench-rules .rule-symbol,#workbench-rules .rule-flow-edge{background:#181e25!important;color:#c6d0d6!important;border-color:#3a424c!important}
#workbench-rules .rule-inline-diagnostic{background:#10151b!important;color:#d7e0e5!important;border-color:#343a40!important}
#workbench-rules .rule-lab-actions{background:#0d1117!important;color:#f4f4f4!important}
#workbench-rules .rule-lab-actions button{background:#262b33!important;color:#f4f4f4!important;border-color:#525860!important}
#workbench-rules .rule-lab-actions input{background:#161b22!important;color:#f4f4f4!important;border-color:#525860!important}
#workbench-rules .editor-chip{background:#10151b!important;color:#c6d0d6!important;border-color:#3a424c!important}
#workbench-rules .rule-spell-toggle{color:#a8b3bc!important}
#workbench-rules .rule-workspace-tabs{background:#161616!important;border-color:#393939!important;padding:0!important}
#workbench-rules .rule-workspace-tabs button{min-height:40px!important;padding:0 14px!important;background:#161616!important;color:#c6c6c6!important;border:0!important;border-bottom:3px solid transparent!important}
#workbench-rules .rule-workspace-tabs button.active{background:#262626!important;color:#fff!important;border-bottom-color:#0f62fe!important}
#workbench-rules .rule-workspace-pane[data-rule-workspace-pane="yaml"]{background:#0d1117!important}
@media(max-width:900px){
 .plugin-picker-drawer{right:8px;top:52px}
 .toni-rail{display:none!important}
 .nav-section{display:contents}
 .nav-section-toggle{display:none!important}
 .nav-section-items{display:flex!important}
}



/* DeltaScope 4.13.1 usability fixes: rendered docs, compact rail collapse,
   unboxed Omega mark, full-size visual authoring canvas. */
.omega-mark{border:0!important;background:transparent!important;box-shadow:none!important;border-radius:0!important}
.omega-mark::after{box-shadow:0 0 0 2px #161616,0 0 10px rgba(239,68,68,.5)!important}

/* Keep a dark icon rail when the hamburger collapses navigation; never replace the
   navigation area with the white workspace. */
.nav-collapsed .app-shell{grid-template-columns:52px minmax(0,1fr)!important}
.nav-collapsed .workbench-nav{display:flex!important;width:52px!important;min-width:52px!important;background:#161616!important}
.nav-collapsed .rail-perspective-switch,.nav-collapsed .perspective-nav-description,.nav-collapsed .nav-section-toggle,.nav-collapsed .toni-rail{display:none!important}
.nav-collapsed #perspectiveNav{display:block!important;overflow-y:auto!important;overflow-x:hidden!important;padding:0!important}
.nav-collapsed .nav-section{display:block!important;border-bottom:0!important}
.nav-collapsed .nav-section .nav-section-items{display:block!important}
.nav-collapsed .workbench-nav button[data-perspective-route]{width:52px!important;min-width:52px!important;height:44px!important;min-height:44px!important;padding:0!important;justify-content:center!important;gap:0!important}
.nav-collapsed .workbench-nav button[data-perspective-route]>span:not(.nav-icon){display:none!important}
.nav-collapsed .workbench-nav button[data-perspective-route].active{box-shadow:inset 3px 0 0 #0f62fe!important}
.nav-collapsed .nav-icon{width:52px!important;height:44px!important}
.nav-collapsed .shell-nav-toggle{background:#353535!important}

/* Render the platform manual as readable Markdown rather than a raw source file. */
#docContent.markdown-body{margin:0;padding:24px 32px 48px;background:#fff!important;color:#161616!important;border-top:1px solid #e0e0e0;font:14px/1.62 'IBM Plex Sans',Inter,'Segoe UI',Arial,sans-serif;white-space:normal;word-break:normal}
.markdown-body>*:first-child{margin-top:0}.markdown-body>*:last-child{margin-bottom:0}
.markdown-body h1{font-size:30px;font-weight:400;line-height:1.2;margin:0 0 20px;padding-bottom:10px;border-bottom:1px solid #e0e0e0}
.markdown-body h2{font-size:23px;font-weight:400;line-height:1.25;margin:30px 0 12px;padding-bottom:7px;border-bottom:1px solid #e0e0e0}
.markdown-body h3{font-size:18px;font-weight:600;margin:24px 0 10px}.markdown-body h4{font-size:15px;margin:20px 0 8px}
.markdown-body p{margin:0 0 14px}.markdown-body ul,.markdown-body ol{margin:0 0 16px;padding-left:26px}.markdown-body li{margin:4px 0}
.markdown-body blockquote{margin:16px 0;padding:10px 14px;border-left:4px solid #0f62fe;background:#f4f4f4;color:#393939}
.markdown-body code{padding:2px 5px;background:#e8e8e8;color:#161616;font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}
.markdown-body pre{margin:16px 0;padding:14px 16px;overflow:auto;background:#161616;color:#f4f4f4;border-left:4px solid #0f62fe;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre}
.markdown-body pre code{padding:0;background:transparent;color:inherit;font:inherit}
.markdown-body table{display:block;width:max-content;max-width:100%;overflow:auto;border-collapse:collapse;margin:16px 0;background:#fff}
.markdown-body th,.markdown-body td{position:static;padding:8px 12px;border:1px solid #c6c6c6;background:#fff;color:#161616;white-space:normal}
.markdown-body th{font-weight:600;background:#f4f4f4}.markdown-body hr{border:0;border-top:1px solid #c6c6c6;margin:24px 0}
.markdown-body a{color:#0f62fe;text-decoration:none}.markdown-body a:hover{text-decoration:underline}
.markdown-body .md-task{display:inline-flex;align-items:center;gap:7px}.markdown-body input[type=checkbox]{accent-color:#0f62fe}

/* Visual authoring is a three-column workbench: palette | canvas | properties.
   Keep the canvas as the dominant surface instead of squeezing it above properties. */
#workbench-rules .rule-workspace-pane[data-rule-workspace-pane="visual"].active{overflow:hidden!important}
#workbench-rules .visual-workspace{grid-template-columns:150px minmax(0,1fr)!important;min-height:0!important;height:100%!important}
#workbench-rules .visual-main{grid-template-columns:minmax(0,1fr) 320px!important;grid-template-rows:auto minmax(0,1fr)!important;gap:8px!important;height:100%!important;min-height:0!important}
#workbench-rules .visual-toolbar{grid-column:1/-1;grid-row:1}
#workbench-rules .visual-canvas{grid-column:1;grid-row:2;height:100%!important;min-height:620px!important}
#workbench-rules .visual-properties{grid-column:2;grid-row:2;min-height:0!important;max-height:none!important;height:100%!important;overflow:auto!important}
#workbench-rules .visual-edges,#workbench-rules .visual-nodes{width:1600px!important;height:1100px!important}
#ruleBrowserShell.visual-focus{grid-template-columns:minmax(0,1fr)!important}
#ruleBrowserShell.visual-focus .rule-library-panel{display:none!important}
#ruleBrowserShell.visual-focus .visual-workspace{grid-template-columns:minmax(0,1fr)!important}
#ruleBrowserShell.visual-focus .visual-palette,#ruleBrowserShell.visual-focus .visual-properties{display:none!important}
#ruleBrowserShell.visual-focus .visual-main{grid-template-columns:minmax(0,1fr)!important}
#ruleBrowserShell.visual-focus .visual-canvas{grid-column:1!important;grid-row:2!important;min-height:680px!important}
@media(max-width:1180px){
 #workbench-rules .visual-main{grid-template-columns:minmax(0,1fr) 260px!important}
}
@media(max-width:900px){
 .nav-collapsed .app-shell{grid-template-columns:52px minmax(0,1fr)!important}
 #workbench-rules .visual-workspace{grid-template-columns:1fr!important}
 #workbench-rules .visual-palette{display:none!important}
 #workbench-rules .visual-main{grid-template-columns:1fr!important;grid-template-rows:auto minmax(520px,1fr) auto!important}
 #workbench-rules .visual-toolbar{grid-column:1;grid-row:1}
 #workbench-rules .visual-canvas{grid-column:1;grid-row:2;min-height:520px!important}
 #workbench-rules .visual-properties{grid-column:1;grid-row:3;height:auto!important;max-height:260px!important}
}

/* Collector review: operational acquisition health derived from recent runner history. */
#workbench-collectors{min-height:0}
#workbench-collectors>.collector-guide{min-height:0;display:flex;flex-direction:column}
.collector-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(430px,1fr));gap:1px;background:#e0e0e0;overflow:auto;min-height:0}
.collector-item{background:#fff;min-width:0;display:flex;flex-direction:column}
.collector-item-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:16px;border-bottom:1px solid #e0e0e0}
.collector-title{font-size:18px;font-weight:600}.collector-purpose{margin-top:4px;color:#525252;font-size:12px;max-width:760px}
.collector-state{display:inline-flex;align-items:center;gap:6px;white-space:nowrap;font-size:11px;font-weight:700;text-transform:uppercase}.collector-state::before{content:'';width:9px;height:9px;border-radius:999px;background:#8d8d8d}.collector-state.healthy::before{background:#24a148}.collector-state.running::before{background:#0f62fe}.collector-state.failed::before{background:#da1e28}.collector-state.warning::before{background:#f1c21b}.collector-state.skipped::before{background:#8d8d8d}
.collector-body{padding:14px 16px;display:grid;gap:14px}.collector-meta{display:grid;grid-template-columns:110px minmax(0,1fr);gap:4px 10px;font-size:12px}.collector-meta b{color:#525252}.collector-meta span{word-break:break-word}
.collector-io{display:grid;grid-template-columns:1fr 1fr;gap:12px}.collector-io h4{margin:0 0 5px;font-size:12px}.collector-io ul{margin:0;padding-left:18px;color:#525252;font-size:12px}
.collector-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:8px}.collector-metric{background:#f4f4f4;padding:10px;border-left:3px solid #0f62fe}.collector-metric-value{font-size:18px;font-weight:500;word-break:break-word}.collector-metric-label{font-size:11px;color:#525252}.collector-metric-source{font-size:10px;color:#6f6f6f;margin-top:3px}
.collector-artifacts{display:flex;gap:6px;flex-wrap:wrap}.collector-artifact{display:inline-flex;gap:6px;align-items:center;padding:4px 7px;background:#e8e8e8;font-size:11px}.collector-artifact.expired{text-decoration:line-through;color:#6f6f6f}
.collector-run-summary{display:flex;flex-wrap:wrap;gap:12px;align-items:center;padding:9px 0;border-top:1px solid #e0e0e0;color:#525252;font-size:12px}.collector-run-summary strong{color:#161616}
.collector-history{overflow:auto;max-height:220px;border-top:1px solid #e0e0e0}.collector-history table{font-size:11px}.collector-history th,.collector-history td{padding:7px 8px}.collector-history a{color:#0f62fe;text-decoration:none}.collector-history a:hover{text-decoration:underline}.collector-error{padding:10px;background:#fff1f1;border-left:3px solid #da1e28;color:#750e13;font-size:12px}
.collector-actions{display:flex;gap:8px;flex-wrap:wrap}.collector-actions button{font-size:12px;padding:6px 9px!important}
@media(max-width:900px){.collector-grid{grid-template-columns:1fr}.collector-io{grid-template-columns:1fr}}

</style></head>
<body class="perspective-developer" data-perspective="developer"><header><button id="navToggle" class="header-icon-button shell-nav-toggle" aria-label="Toggle navigation" aria-expanded="true"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M4 7h24v2H4zm0 8h24v2H4zm0 8h24v2H4z"/></svg></button><div class="brand"><span class="omega-mark" aria-label="Omega">O</span><span class="brand-copy"><span class="brand-omega">OMEGA</span><span class="brand-deltascope">DELTASCOPE</span></span></div><select id="headerPluginSelect" class="sr-only" aria-label="Selected plugin" tabindex="-1"><option value="">Select a plugin…</option></select><div class="omnibox-wrap"><input id="globalSearch" autocomplete="off" aria-label="Search DeltaScope" title="Search plugins, hashes, endpoints, authors, rules, CVEs" placeholder="Search DeltaScope…"><div id="globalSearchResults" class="omnibox-results" hidden></div></div><button id="pluginPickerButton" class="header-icon-button plugin-picker-button" aria-label="Select plugin" aria-expanded="false" title="Select plugin"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M7 5h18v6H7Zm0 8h18v6H7Zm0 8h18v6H7Zm2-14v2h14V7Zm0 8v2h14v-2Zm0 8v2h14v-2Z"/></svg><span id="pluginPickerState" class="plugin-picker-state"></span></button><button id="notificationButton" class="header-icon-button" aria-label="Notifications" aria-expanded="false"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M28 24h-2v-8a10 10 0 0 0-8-9.8V4h-4v2.2A10 10 0 0 0 6 16v8H4v2h9a3 3 0 0 0 6 0h9Zm-12 4a1 1 0 0 1-1-1h2a1 1 0 0 1-1 1Zm8-4H8v-8a8 8 0 0 1 16 0Z"/></svg><span id="notificationCount" class="notification-count"></span></button><button id="appSwitcherButton" class="header-icon-button app-switcher-button" aria-label="Omega applications" aria-expanded="false" title="Omega applications"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M6 5h4v4H6zm8 0h4v4h-4zm8 0h4v4h-4zM6 14h4v4H6zm8 0h4v4h-4zm8 0h4v4h-4zM6 23h4v4H6zm8 0h4v4h-4zm8 0h4v4h-4z"/></svg></button></header><aside id="notificationDrawer" class="notification-drawer" hidden><div class="notification-head"><div><div class="muted small">DELTASCOPE</div><h2>Notifications</h2></div><div class="notification-head-actions"><button id="markNotificationsRead">Mark all read</button><button id="notificationClose" aria-label="Close notifications">×</button></div></div><div id="notificationList" class="notification-list"><div class="notification-empty">No important notifications.</div></div></aside><aside id="appSwitcherDrawer" class="app-switcher-drawer" hidden><div class="app-switcher-head"><div><div class="muted small">OMEGA</div><h2>Applications</h2></div><button id="appSwitcherClose" class="app-switcher-close" aria-label="Close applications">×</button></div><div class="app-switcher-grid"><button class="app-switcher-item" data-app-action="support"><span class="app-switcher-icon"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 3a12 12 0 1 0 12 12A12 12 0 0 0 16 3Zm0 22a10 10 0 1 1 10-10 10 10 0 0 1-10 10Zm-1-6h2v2h-2Zm5.1-8.2A4.2 4.2 0 0 1 18 14.5c-.9.5-1 .8-1 1.5v1h-2v-1.2a3.2 3.2 0 0 1 1.9-3c.8-.4 1.2-.9 1.2-1.7a2.1 2.1 0 0 0-4.1-.5l-1.9-.6a4.1 4.1 0 0 1 8 .8Z"/></svg></span><span><span class="app-switcher-title">Support</span><span class="app-switcher-sub">Issues & feedback</span></span></button><button class="app-switcher-item" data-app-action="github"><span class="app-switcher-icon"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2a14 14 0 0 0-4.4 27.3c.7.1 1-.3 1-.7v-2.5c-4 .9-4.9-1.7-4.9-1.7-.6-1.7-1.6-2.1-1.6-2.1-1.3-.9.1-.9.1-.9 1.5.1 2.2 1.5 2.2 1.5 1.3 2.2 3.4 1.6 4.2 1.2.1-.9.5-1.6.9-2-3.2-.4-6.5-1.6-6.5-7a5.5 5.5 0 0 1 1.5-3.8 5.1 5.1 0 0 1 .1-3.8s1.2-.4 3.9 1.5a13.5 13.5 0 0 1 7.1 0c2.7-1.9 3.9-1.5 3.9-1.5a5.1 5.1 0 0 1 .1 3.8 5.5 5.5 0 0 1 1.5 3.8c0 5.4-3.3 6.6-6.5 7 .5.4 1 1.3 1 2.6v3.8c0 .4.3.8 1 .7A14 14 0 0 0 16 2Z"/></svg></span><span><span class="app-switcher-title">GitHub</span><span class="app-switcher-sub">dalagab/omega</span></span></button><button class="app-switcher-item" data-app-action="new-rule"><span class="app-switcher-icon"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M27 15H17V5h-2v10H5v2h10v10h2V17h10Z"/></svg></span><span><span class="app-switcher-title">Add rule</span><span class="app-switcher-sub">New Stigma-1 rule</span></span></button></div><div class="app-switcher-note">External destinations open in a new tab. Add rule switches to the Security Researcher rule workspace; production activation still requires normal GitHub review/CI.</div></aside><aside id="pluginPickerDrawer" class="plugin-picker-drawer" hidden><div class="plugin-picker-head"><div><div class="muted small" id="pluginPickerKicker">PLUGIN CONTEXT</div><h2 id="pluginPickerTitle">Select a plugin</h2></div><button id="pluginPickerClose" class="plugin-picker-close" aria-label="Close plugin selector">×</button></div><div class="plugin-picker-search-wrap"><input id="pluginPickerSearch" autocomplete="off" placeholder="Type a plugin name…" aria-label="Search plugins"></div><div id="pluginPickerList" class="plugin-picker-list"><div class="plugin-picker-empty">Loading plugins…</div></div></aside>
<div class="app-shell"><aside class="workbench-nav" aria-label="DeltaScope workbench"><div class="perspective-switch rail-perspective-switch"><span class="perspective-switch-label sr-only">Perspective</span><select id="perspectiveSelect" class="perspective-select" aria-label="DeltaScope perspective"><option value="developer" selected>Plugin Developer</option><option value="investigator">Investigator</option><option value="researcher">Security Researcher</option><option value="operations">Operations</option></select></div><div id="perspectiveNav"><div class="workbench-nav-title group">Develop</div></div><div id="toniRail" class="toni-rail"><div class="toni-rail-head"><span class="toni-light"></span><span><b>TONI</b><small>deterministic evidence guide</small></span></div><div id="toniMessage" class="toni-rail-message">Choose a perspective or plugin and I’ll keep the useful context close.</div><div class="toni-rail-actions"><button id="toniOverview" title="Coverage overview">Coverage</button><button id="toniQueue" title="Queue status">Queue</button><button id="toniSelection" title="Selected plugin summary">Selected</button></div></div></aside><main><section id="subjectBar" class="subjectbar" aria-live="polite"><div><div id="subjectName" class="subject-name"></div><div id="subjectMeta" class="subject-meta"></div></div><div id="subjectActions" class="subject-actions"><span id="subjectSeverity" class="subject-severity"></span><button data-subject-tab="overview">Overview</button><button data-subject-tab="journey">Journey</button><button data-subject-tab="findings">Findings</button><button data-subject-tab="network">Network</button><button data-subject-tab="compare">Compare</button><button id="subjectAsk">Questions</button><button id="subjectClear">× Clear</button></div><div id="subjectQuestions" class="subject-questions"><button class="question-chip" data-question="why">Why this severity?</button><button class="question-chip" data-question="network">What connects to the internet?</button><button class="question-chip" data-question="changed">What changed?</button><button class="question-chip" data-question="deep">Why was deeper analysis requested?</button><button class="question-chip" data-question="missing">What evidence is missing?</button></div></section><aside id="helpDrawer" class="help-drawer" hidden><div class="help-drawer-head"><div><div class="eyebrow">Context help</div><h3 id="helpTitle">DeltaScope</h3></div><button id="helpClose">×</button></div><div id="helpBody"></div></aside>
<section id="workbench-developer" class="workspace-view active" data-workbench-view="developer"><div class="workspace-heading"><div><h1>Plugin Developer</h1><p>Understand what Omega found on your plugin, explain expected behavior, and improve the metadata/source context Omega can index.</p></div><span class="badge ro">DEVELOPER CONTEXT · READ ONLY</span></div><div id="developerHomeContent" class="developer-home"><div class="workspace-empty">Select your plugin from My Plugin or the global search box to open its developer review.</div></div></section>
<section id="workbench-dashboard" class="workspace-view" data-workbench-view="dashboard"><div id="dashboardGate" aria-live="polite"></div><div class="dashboard-overview-grid"><section class="panel"><div class="panelhead"><div><h2>Security platform overview</h2><div class="muted small">The context that used to live in the header now lives here: source, scanner, evidence, Definitions and last published analysis.</div></div><div class="dashboard-actions"><button id="refreshEvidence" class="primary" style="display:none">Refresh evidence</button><button id="auditButton">Run consistency audit</button></div></div><div id="dashboardPlatformCards" class="dashboard-platform-grid"><div class="dashboard-platform-item"><div class="label">Source</div><div id="sourceBadge" class="value">Loading…</div></div><div class="dashboard-platform-item"><div class="label">SigmaScope</div><div id="scannerBadge" class="value">Loading…</div></div><div class="dashboard-platform-item"><div class="label">Evidence</div><div id="revisionBadge" class="value">Loading…</div></div><div class="dashboard-platform-item"><div class="label">Latest analysis</div><div id="latestBadge" class="value">Loading…</div></div><div class="dashboard-platform-item"><div class="label">Definitions</div><div id="dashboardDefinitions" class="value">Loading…</div></div><div class="dashboard-platform-item"><div class="label">Authority state</div><div id="dashboardAuthority" class="value">Loading…</div><div id="dashboardAuthorityDetail" class="detail"></div></div></div></section><section class="panel"><div class="panelhead"><div><h2>Needs attention</h2><div class="muted small">The same active important items shown by the notification bell.</div></div><button id="openNotificationsFromDashboard">Open all</button></div><div id="dashboardNotificationPreview" class="dashboard-notification-preview"><div class="notification-empty">No important notifications.</div></div></section></div><div id="summaryCards" class="cards focus-cards"></div><div class="dashboard-grid"><section id="dashboardComponents" class="panel"><div class="panelhead"><div><h2>Components & Actions</h2><div class="muted small">Live read-only GitHub Actions status; public API, short cached poll.</div></div><button id="refreshOperations">Refresh</button></div><div id="dashboardComponentRows" class="detail"><div class="workspace-empty">Loading component status…</div></div></section><div id="dashboardActivity" class="panel dashboard-activity"><div class="panelhead"><div><h2>Current security activity</h2><div class="muted small">Read-only priority view over published current evidence.</div></div></div><div id="dashboardActivityRows" class="detail"></div></div></div></section>
<section id="workbench-incidents" class="workspace-view" data-workbench-view="incidents"><div class="workspace-heading"><div><h1>Incidents</h1><p>The newest concrete security findings are surfaced first, followed by derived cases requiring investigation. DeltaScope does not assign, close or mutate incidents.</p></div><span class="badge ro">DERIVED · READ ONLY</span></div><div class="incident-overview-grid"><section id="latestFindingsPanel" class="panel"><div class="panelhead"><div><h2>Latest security findings</h2><div class="muted small">Newest current findings from published SigmaScope evidence.</div></div><span id="latestFindingCount" class="muted"></span></div><div class="workbench-table-wrap"><table class="workbench-table"><thead><tr><th>Time</th><th>Asset</th><th>Finding</th><th>Severity</th></tr></thead><tbody id="latestFindingRows"><tr><td colspan="4" class="workspace-empty">Loading latest findings…</td></tr></tbody></table></div></section><section class="panel"><div class="panelhead"><h2>Cases requiring attention</h2><span id="incidentCount" class="muted"></span></div><div class="workbench-table-wrap"><table class="workbench-table"><thead><tr><th>Asset</th><th>Priority</th><th>Findings</th><th>Intelligence</th><th>Last evidence</th></tr></thead><tbody id="incidentRows"></tbody></table></div></section></div><section id="incidentCasePanel" class="panel case-projection"><div class="workspace-empty">Select a finding or incident to compose its contributing findings, observations, intelligence and reprojection relationships.</div></section></section>
<section id="workbench-events" class="workspace-view" data-workbench-view="events"><div class="workspace-heading"><div><h1>Events</h1><p>Operational activity from GitHub Actions alongside evidence events produced by SigmaScope. GitHub data is fetched read-only and is never control-plane authority.</p></div><span class="badge ro">READ ONLY</span></div><div class="event-overview-grid"><section class="panel"><div class="panelhead"><div><h2>Operations / Actions</h2><div class="muted small">What ran, what is running, branch and outcome.</div></div><span id="operationEventCount" class="muted"></span></div><div class="workbench-table-wrap"><table class="workbench-table"><thead><tr><th>Time</th><th>Component</th><th>Action</th><th>State</th><th>Branch</th></tr></thead><tbody id="operationEventRows"><tr><td colspan="5" class="workspace-empty">Loading GitHub activity…</td></tr></tbody></table></div></section><section class="panel"><div class="panelhead"><h2>Evidence events</h2><span id="eventCount" class="muted"></span></div><div class="workbench-table-wrap"><table class="workbench-table"><thead><tr><th>Time</th><th>Asset</th><th>Event</th><th>Severity</th><th>Source</th></tr></thead><tbody id="eventRows"></tbody></table></div></section></div><section id="eventCasePanel" class="panel case-projection"><div class="workspace-empty">Select an evidence event to open the normalized read-only evidence timeline for that asset.</div></section></section>
<section id="workbench-intelligence" class="workspace-view" data-workbench-view="intelligence"><div class="workspace-heading"><div><h1>Intelligence</h1><p>Read-only ecosystem pivots across advisories, shared components and observed network endpoints. These relationships help investigation; they are not policy inputs.</p></div><span class="badge ro">READ ONLY · CONTEXT ONLY</span></div><div id="intelligenceCards" class="cards workspace-cards"></div><div class="research-grid"><section class="panel"><div class="panelhead"><h2>Endpoint intelligence</h2><span id="endpointIntelCount" class="muted"></span></div><div class="workbench-table-wrap"><table class="workbench-table"><thead><tr><th>Endpoint</th><th>Assets</th><th>Class</th></tr></thead><tbody id="endpointIntelRows"></tbody></table></div></section><section class="panel"><div class="panelhead"><h2>Shared components</h2><span id="componentIntelCount" class="muted"></span></div><div class="workbench-table-wrap"><table class="workbench-table"><thead><tr><th>Component</th><th>Assets</th><th>Divergence</th></tr></thead><tbody id="componentIntelRows"></tbody></table></div></section><section class="panel" style="grid-column:1/-1"><div class="panelhead"><h2>Known advisories</h2><span id="advisoryIntelCount" class="muted"></span></div><div class="workbench-table-wrap"><table class="workbench-table"><thead><tr><th>Advisory</th><th>Component</th><th>Affected assets</th><th>Severity</th><th>Fixed</th></tr></thead><tbody id="advisoryIntelRows"></tbody></table></div></section></div><section id="intelligencePivotPanel" class="panel case-projection"><div class="workspace-empty">Select an endpoint, component or advisory to pivot across affected plugins.</div></section><details class="advanced"><summary>Asset-oriented advisory view</summary><section class="panel"><div class="panelhead"><h2>Assets with known advisory intelligence</h2><span id="intelligenceCount" class="muted"></span></div><div class="workbench-table-wrap"><table class="workbench-table"><thead><tr><th>Asset</th><th>Advisories</th><th>Highest advisory</th><th>Static severity</th><th>Source</th></tr></thead><tbody id="intelligenceRows"></tbody></table></div></section></details></section>
<section id="workbench-assets" class="workspace-view" data-workbench-view="assets" style="margin-top:14px"><div class="research-layout"><section class="panel triage-panel"><div class="panelhead"><div><h2>Plugins</h2><div class="muted small">Select a plugin once; its dossier stays available while you investigate elsewhere.</div></div><span id="pluginRowCount" class="muted"></span></div><div style="padding:0 12px"><div class="toolbar"><input id="pluginQuery" placeholder="Filter this plugin list…"><select id="severityFilter"><option value="">Any severity</option><option>critical</option><option>high</option><option>caution</option><option>informational</option><option>none</option></select><select id="scanStatusFilter"><option value="">Any scan status</option><option>complete</option><option>failed</option><option>unscanned</option></select><label><input id="knownRiskFilter" type="checkbox"> OSV</label><button id="refreshPlugins">Refresh</button></div></div><div class="triage-scroll"><table><thead><tr><th>Plugin</th><th>Severity</th><th>Automation</th><th>Source</th><th>Scan</th></tr></thead><tbody id="pluginRows"></tbody></table></div></section><section id="researchCase" class="panel case-panel"><div class="case-header"><div class="case-title"><div><h2 id="detailTitle">Select a plugin to investigate</h2><div id="detailMeta" class="case-subtitle">Overview → journey → findings → relationships → retained evidence</div></div></div></div><div id="pluginDetail" class="detail"><div class="empty">Choose a plugin. DeltaScope will open its persistent read-only dossier and keep it as the current subject while you investigate elsewhere.</div></div></section></div></section>
<section id="workbench-rules" class="workspace-view" data-workbench-view="rules"><div class="workspace-heading compact-rule-heading"><div><h1>Rules</h1><p>Read system rules, author local Stigma-1 rules, visualize logic and replay them against retained evidence.</p><span class="sr-only">NO DIRECT ACTIVATION · One Stigma-1 workspace. My Rules stay local until normal GitHub review/CI.</span></div></div><div id="ruleCatalogCards" class="cards workspace-cards" hidden></div><section id="ruleBrowserShell" class="rule-browser-shell unified-rule-workspace"><aside class="panel rule-library-panel"><div class="panelhead rule-library-head"><div class="rule-library-heading-copy"><h2>Rule library</h2><div class="muted small">System Rules + versioned My Rules</div></div><span id="ruleLibraryCount" class="muted"></span><button id="ruleLibraryToggle" class="rule-library-toggle" title="Collapse rule library" aria-label="Collapse rule library" aria-expanded="true">‹</button></div><div class="rule-library-search"><input id="ruleLibrarySearch" aria-label="Filter rule library" placeholder="Filter rules or packs…"><button id="ruleLibraryExpand" title="Expand all folders">Expand</button><button id="ruleLibraryCollapse" title="Collapse all folders">Collapse</button></div><div class="rule-library-legend"><span class="pill source-pill">SYSTEM</span><span class="pill local-pill">MY RULES</span><span id="ruleLocalHome" class="rule-local-home">Loading local rule home…</span></div><div id="ruleTree" class="rule-tree"><div class="workspace-empty">Loading Stigma-1 rule workspace…</div></div></aside><section class="panel rule-workspace-panel"><div class="rule-workspace-head"><div><div id="ruleWorkspaceKicker" class="rule-inspector-kicker">Stigma-1 · SRL Core</div><h2 id="ruleWorkspaceTitle">Select a rule</h2><div id="ruleWorkspaceMeta" class="muted small">System rules are read-only; fork one or create a local rule to edit.</div></div><div class="rule-workspace-actions"><span id="ruleWorkspaceOrigin" class="pill readonly-pill">NO RULE</span><button id="ruleNewLocal">+ New Rule</button><button id="ruleForkLocal" disabled>Fork to My Rules</button><button id="ruleSaveLocal" disabled>Save revision</button></div></div><div class="rule-workspace-tabs"><button class="active" data-rule-workspace-tab="yaml">YAML</button><button data-rule-workspace-tab="visual">Visual</button><button data-rule-workspace-tab="explain">Explain / Test</button></div><div class="rule-workspace-pane active" data-rule-workspace-pane="yaml"><section class="rule-lab-editor smart"><div class="rule-smart-toolbar"><div class="left"><span class="editor-chip">SRL v1</span><span id="ruleEditorHealth" class="editor-chip busy">INITIALIZING</span><span id="ruleEditorScope" class="editor-chip">typed retained evidence</span></div><div class="right"><button id="ruleEditorComplete" title="Context completion · Ctrl/Cmd+Space">Complete</button><button id="ruleFormat" title="Canonical YAML format · Shift+Alt+F">Format</button><label class="rule-spell-toggle" title="Use the browser spell checker for prose fields while editing"><input id="ruleSpellcheck" type="checkbox">Prose spellcheck</label></div></div><div class="rule-smart-editor"><div id="ruleGutter" class="rule-editor-gutter">1</div><div class="rule-code-wrap"><pre id="ruleHighlight" aria-hidden="true"></pre><textarea id="ruleYaml" spellcheck="false" autocapitalize="off" autocomplete="off" autocorrect="off" placeholder="Select a System Rule, My Rule, or create a new rule…"></textarea><div id="ruleCompletionPopup" class="rule-completion-popup" hidden></div></div></div><div class="rule-editor-statusbar"><span id="ruleCursor">Ln 1, Col 1</span><span id="ruleEditorMetrics">0 B · 1 line</span><span id="ruleEditorRevision">not compiled</span><span class="push">Ctrl/Cmd+Z undo · Ctrl/Cmd+Shift+Z redo · Ctrl/Cmd+Space complete · Ctrl/Cmd+Enter validate</span></div><div class="rule-intelligence-grid"><div class="rule-intel-panel"><div class="rule-intel-title">Context intelligence</div><div id="ruleContextHelp" class="rule-context-doc">Move the caret through a rule to inspect keys, collections, fields, operators and symbols.</div><div id="ruleSuggestions" class="rule-suggestion-chips"></div></div><div class="rule-intel-panel"><div class="rule-intel-title">Outline / symbols</div><div id="ruleOutline" class="rule-outline"></div></div><div class="rule-intel-panel rule-flow-panel"><div class="rule-intel-title">Rule flow</div><div id="ruleFlow" class="rule-outline"><span class="rule-editor-hint">Collections, selectors, facts and findings are connected here as the rule becomes valid.</span></div></div></div><div id="ruleInlineDiagnostics" class="rule-inline-diagnostics"></div><div class="rule-lab-actions"><input id="ruleImport" type="file" accept=".yaml,.yml,text/yaml"><button id="ruleExample">New example</button><button id="ruleCompile">Validate now</button><button id="ruleEvaluate">Dry-run selected plugin</button></div></section></div><div class="rule-workspace-pane" data-rule-workspace-pane="visual"><div class="visual-workspace"><div class="visual-palette"><div class="rule-intel-title">Drag nodes into the canvas</div><button draggable="true" data-visual-add="collection-selector">Collection selector</button><button draggable="true" data-visual-add="fact-selector">Fact selector</button><button draggable="true" data-visual-add="all">ALL</button><button draggable="true" data-visual-add="any">ANY</button><button draggable="true" data-visual-add="not">NOT</button><button draggable="true" data-visual-add="count">COUNT</button><button draggable="true" data-visual-add="emit">Emit</button><div class="visual-help">Select a node to edit it. Click <b>Connect</b>, then a source node and target node, to create a flow edge. Every visual change is converted back to YAML through Stigma-1 before it can be saved or evaluated.</div></div><div class="visual-main"><div class="visual-toolbar"><span id="ruleVisualStatus" class="editor-chip">Open Visual to parse YAML</span><button id="ruleVisualConnect">Connect</button><button id="ruleVisualDelete" disabled>Delete node</button><button id="ruleVisualToYaml">Apply graph to YAML</button><button id="ruleVisualFocus" title="Use the full rule workspace for the graph">Focus canvas</button></div><div id="ruleVisualCanvas" class="visual-canvas" tabindex="0"><svg id="ruleVisualSvg" class="visual-edges"></svg><div id="ruleVisualNodes" class="visual-nodes"></div><div id="ruleVisualEmpty" class="visual-empty">Select or create a rule, then open Visual.</div></div><div id="ruleVisualProperties" class="visual-properties"><div class="workspace-empty">Select a node to edit its SRL properties.</div></div></div></div></div><div class="rule-workspace-pane" data-rule-workspace-pane="explain"><div class="rule-explain-actions"><button id="ruleReplaySet">Replay set</button><button id="ruleReplayCorpus">Replay corpus</button><input id="ruleVariantIds" placeholder="Variant IDs for set replay, comma-separated"><input id="ruleReplayLimit" type="number" min="1" max="1000" value="250" style="max-width:110px"></div><div id="ruleLabStatus" class="muted">Select or compile a rule to begin.</div><div id="ruleLabResult"></div><details class="advanced rule-test-drawer"><summary>Fixtures & GitHub proposal</summary><div><div class="rule-lab-fixture"><div class="muted small">Candidate bundles require both polarities. These remain local until you explicitly open GitHub's reviewed proposal workflow.</div><div class="rule-proposal-grid"><div><h4>Positive fixture</h4><textarea id="rulePositiveFixture" spellcheck="false" placeholder="Positive fixture YAML…"></textarea><div class="rule-lab-actions"><button id="ruleCreatePositiveFixture">Create from selected</button><button id="ruleTestPositiveFixture">Test positive</button></div></div><div><h4>Negative fixture</h4><textarea id="ruleNegativeFixture" spellcheck="false" placeholder="Negative fixture YAML…"></textarea><div class="rule-lab-actions"><button id="ruleCreateNegativeFixture">Create from selected</button><button id="ruleTestNegativeFixture">Test negative</button></div></div></div><h3>GitHub proposal</h3><div class="muted small">This only opens GitHub's normal issue form with query-string prefills. The proposal path uses no GitHub API write or repository credentials and never submits the issue itself.</div><div class="rule-proposal-grid" style="margin-top:8px"><input id="rulePackId" placeholder="Candidate pack ID"><input id="rulePackTitle" placeholder="Candidate pack title"><textarea id="ruleRationale" class="meta" placeholder="Rationale"></textarea><textarea id="ruleFalsePositives" class="meta" placeholder="False-positive expectations"></textarea><textarea id="ruleProvenance" class="meta" placeholder="External provenance / source"></textarea><div><input id="ruleLicense" value="MIT" placeholder="License"><input id="ruleExportNotes" style="margin-top:8px" placeholder="Optional local export notes"></div><div class="wide rule-lab-actions"><button id="ruleExport">Export candidate bundle</button><button id="ruleProposeGitHub">Propose on GitHub</button></div></div><div id="ruleProposalResult"></div></div></div></details></div></section></section><details class="advanced active-rule-snapshot"><summary>Published active snapshot provenance · exact frozen Definition Packs and rules</summary><div><div class="active-snapshot-note">This section reflects only the Definition provenance embedded in the Evidence-v2 snapshot you opened. The tree above always shows repository System Rules; ACTIVE badges identify rules that are also published in the selected snapshot.</div><div class="research-grid"><section class="panel"><div class="panelhead"><div><h2>Active Definition Packs</h2><div class="muted small">Exact frozen pack/review/fixture provenance published with Evidence-v2.</div></div><span id="rulePackCount" class="muted"></span></div><div class="workbench-table-wrap"><table class="workbench-table"><thead><tr><th>Pack</th><th>Tier</th><th>Review</th><th>Fixtures</th></tr></thead><tbody id="rulePackRows"></tbody></table></div></section><section class="panel"><div class="panelhead"><div><h2>Active rules</h2><div class="muted small">Frozen compiled SRL rules, not repository/development YAML.</div></div><span id="activeRuleCount" class="muted"></span></div><div class="workbench-table-wrap"><table class="workbench-table"><thead><tr><th>Rule</th><th>Kind</th><th>Output</th><th>Revision</th></tr></thead><tbody id="activeRuleRows"></tbody></table></div></section></div><section id="ruleProvenancePanel" class="panel case-projection"><div class="workspace-empty">Select an active rule or pack to inspect its exact provenance, reviewer, fixture and compiled semantics.</div></section></div></details></section>
<section id="workbench-collectors" class="workspace-view" data-workbench-view="collectors"><div class="workspace-heading"><div><h1>Collectors</h1><p>Review how Omega acquires and normalizes data: what each collector consumes, what it produces, recent GitHub Actions runs, parsed throughput and failure signals, and the published evidence that resulted.</p></div><span class="badge ro">RUNNER HISTORY · READ ONLY</span></div><div id="collectorCards" class="cards workspace-cards"></div><section class="panel collector-guide"><div class="panelhead"><div><h2>Data acquisition health</h2><div class="muted small">Runner history is diagnostic evidence. Published catalog and Security Evidence remain authoritative outputs.</div></div><button id="refreshCollectors">Refresh runner history</button></div><div id="collectorRows" class="collector-grid"><div class="workspace-empty">Loading collector health…</div></div></section></section>
<section id="workbench-reports" class="workspace-view" data-workbench-view="reports"><div class="workspace-heading"><div><h1>Reports</h1><p>Coverage, queue, replay and reanalysis readiness derived from published evidence. Reports are generated views, not stored mutable records.</p></div><span class="badge ro">READ ONLY</span></div><div id="reportCards" class="cards workspace-cards"></div><section class="panel"><div class="panelhead"><div><h2>Operational security reports</h2><div class="muted small">Coverage, queue and SRL cutover-readiness summaries.</div></div><span id="reportRevision" class="muted"></span></div><div id="reportRows" class="detail"></div></section><details id="metricsDrawer" class="advanced metrics-drawer" open><summary>Metrics & coverage · exact drill-down counts</summary><div id="allMetricCards" class="cards"></div></details></section>
<section id="workbench-docs" class="workspace-view" data-workbench-view="docs"><div class="workspace-heading"><div><h1>Documentation</h1><p>Task-oriented manual for the Omega platform: plugin developers, investigators, security researchers, operators, rule authors and contributors.</p></div><span class="badge ro">LOCAL · READ ONLY</span></div><div class="docs-shell"><aside class="panel docs-list-panel"><div class="panelhead"><div><h2>Platform manual</h2><div class="muted small">Start with Platform overview, then choose the role or task you are working on.</div></div><span id="docCount" class="muted"></span></div><div id="docTree"><div class="workspace-empty">Loading documentation…</div></div></aside><section class="panel docs-viewer"><div class="panelhead"><div><h2 id="docTitle">Select a document</h2><div id="docMeta" class="muted small">Documentation is read from the local checkout through an allow-list.</div></div></div><article id="docContent" class="markdown-body"><p>Choose a document from the left.</p></article></section></div></section>
<section id="workbench-system" class="workspace-view" data-workbench-view="system"><div class="workspace-heading"><div><h1>System health</h1><p>Is the evidence current, are the security components healthy, and are any authority gates intentionally closed?</p></div><span class="badge ro">READ ONLY · NO CONTROL PLANE</span></div><div id="systemCards" class="cards workspace-cards"></div><div class="research-grid"><section class="panel"><div class="panelhead"><h2>Health & gates</h2><span class="muted">plain-language status</span></div><div id="systemChecks" class="detail"></div></section><section class="panel technical-detail"><div class="panelhead"><h2>Technical revisions</h2><span class="muted">exact published identities</span></div><div id="systemRevisions" class="detail technical-revisions"></div></section></div><details id="rawEvidence" class="advanced raw-browser technical-detail"><summary>Advanced · raw Evidence-v2 / database browser</summary><section class="panel"><div class="panelhead"><h2>Raw evidence browser</h2><span class="muted">Lifecycle, queue, identities, normalized datasets and relationship traversal · read only.</span></div><div class="db-browser"><aside class="db-sidebar"><input id="tableSearch" style="width:100%" placeholder="Find an evidence table…"><div id="tableList"></div></aside><section class="db-main"><div class="panelhead"><div><h3 id="tableTitle">Choose an evidence set</h3><div id="tableSubtitle" class="muted small"></div></div><div><button id="tablePrev" disabled>← Previous</button> <button id="tableNext" disabled>Next →</button></div></div><div id="tableFilterBar" class="detail" style="display:none"></div><div id="tableGrid" class="table-grid"><div class="empty">Choose a dataset, or click a headline metric above.</div></div></section><aside class="db-row"><h3 id="rowTitle">Evidence row</h3><div id="rowDetail" class="muted" style="margin-top:10px">Click a row to inspect fields and follow relationships.</div></aside></div></section></details>
<details id="advancedSql" class="advanced"><summary>Advanced · read-only SQL console</summary><div><div class="muted small" style="margin:8px 0">Optional escape hatch: SELECT / PRAGMA / WITH / EXPLAIN only · max 1000 rows.</div><textarea id="sqlText">SELECT severity, category, rule_id, COUNT(*) AS n
FROM plugin_security_findings
GROUP BY severity, category, rule_id
ORDER BY n DESC
LIMIT 100</textarea><div style="margin:7px 0"><button id="runSqlButton">Run query</button></div><div id="sqlOutput" class="sqlout"></div></div></details></section>
</main></div><script>
const $=id=>document.getElementById(id);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sev=s=>`sev-${String(s||'none').toLowerCase()}`;const fmt=n=>Number(n||0).toLocaleString();let timer;let tables=[];let currentTable=null;let currentRows=[];let currentFkLinks=[];let currentSummary=null;let currentPluginDetail=null;let currentMetric=null;let currentAssetRows=[];let currentWorkbenchView='developer';let currentWorkbenchCase=null;let currentRuleCatalog=null;let currentRuleLibrary=null;let currentRuleWorkspace=null;let currentRuleLibrarySelection=null;let currentWorkspaceRule=null;let currentVisualGraph=null;let selectedVisualNode=null;let visualConnectMode=false;let visualConnectSource=null;let ruleWorkspaceDirty=false;let currentReports=null;let currentSystemStatus=null;let currentOperations=null;let currentCollectors=null;let currentDocs=null;let currentDocId=null;let ruleUndoStack=[];let ruleRedoStack=[];let ruleHistoryCurrent='';let ruleHistoryApplying=false;let globalSearchTimer=null;let currentSubject=null;let currentPerspective='developer';let currentPerspectiveRoute='developer:';let currentProfileBuilderBase={};let currentProfileBuilderCapabilities=[];let currentProfileYaml='';let currentCompare=null;let currentAssetRelationGraph=null;let headerPluginRows=[];let currentSourceStatus=null;let notificationItems=new Map();let latestFindingsPayload=null;let pluginPickerFilter='';let ruleLibraryCollapsed=false;
async function api(path,opts){const r=await fetch(path,opts);const j=await r.json();if(!r.ok)throw new Error(j.error||r.statusText);return j}
function evidence(v){if(v==null)return'';return `<div class=code>${esc(typeof v==='string'?v:JSON.stringify(v,null,2))}</div>`}
function kv(obj,keys){return `<div class=kv>`+keys.map(([k,l])=>`<b>${esc(l)}</b><span>${esc(obj?.[k]??'')}</span>`).join('')+`</div>`}
function card(label,value,action={},hint=''){const table=action.table||'';return `<div class="card ${table?'clickable':''}" ${table?`data-table="${esc(table)}" data-column="${esc(action.column||'')}" data-value="${esc(action.value??'')}" data-metric="${esc(action.metric||'')}" data-label="${esc(label)}" data-count="${esc(value)}"`:''}><div class=n>${fmt(value)}</div><div class=muted>${esc(label)}</div>${hint?`<div class=hint>${esc(hint)}</div>`:''}</div>`}
function textCard(label,value,hint=''){return `<div class=card><div class=n style="font-size:18px">${esc(value||'—')}</div><div class=muted>${esc(label)}</div>${hint?`<div class=hint>${esc(hint)}</div>`:''}</div>`}
function wireMetricCards(root){if(!root)return;root.querySelectorAll('[data-table]').forEach(x=>x.addEventListener('click',()=>{const metric=x.dataset.metric||'';const count=Number(x.dataset.count||0);const label=x.dataset.label||x.dataset.table;currentMetric=metric?{label,count,metric}:null;toniSay(metric?`${label} is ${fmt(count)}. I’m opening the contribution rows; the card value is the sum of ${metric} across these rows. Click a row to inspect the variant behind it.`:`${label} is ${fmt(count)}. I’m opening the exact records behind that headline count.`);openTable(x.dataset.table,x.dataset.column||'',x.dataset.value||'',0,metric)}))}


function notificationSeenSet(){try{return new Set(JSON.parse(localStorage.getItem('deltascope.notificationSeen.v1')||'[]'))}catch{return new Set()}}
function storeNotificationSeen(set){try{localStorage.setItem('deltascope.notificationSeen.v1',JSON.stringify([...set].slice(-250)))}catch{}}
function upsertNotification(item){if(!item?.id)return;notificationItems.set(String(item.id),item);renderNotifications()}
function removeNotification(id){notificationItems.delete(String(id));renderNotifications()}
function notificationItemHtml(n,{compact=false}={}){const level=String(n.level||'info').toLowerCase();return `<button class="notification-item ${esc(level)}" data-notification-id="${esc(n.id)}"><span class=notification-level></span><span class=notification-body><span class=notification-title>${esc(n.title||'DeltaScope notification')}</span><span class=notification-detail>${esc(n.detail||'')}</span>${compact?'':`<span class=notification-meta>${esc(n.meta||'')}</span>`}</span></button>`}
function renderNotifications(){const rows=[...notificationItems.values()].sort((a,b)=>(b.rank||0)-(a.rank||0)||String(b.time||'').localeCompare(String(a.time||''))),seen=notificationSeenSet(),unread=rows.filter(x=>!seen.has(String(x.id))).length,count=$('notificationCount');if(count){count.textContent=unread>99?'99+':String(unread);count.classList.toggle('active',unread>0)}const list=$('notificationList');if(list){list.innerHTML=rows.length?rows.map(x=>notificationItemHtml(x)).join(''):'<div class=notification-empty>No important notifications.</div>';list.querySelectorAll('[data-notification-id]').forEach(x=>x.addEventListener('click',()=>openNotification(notificationItems.get(x.dataset.notificationId))))}const preview=$('dashboardNotificationPreview');if(preview){preview.innerHTML=rows.length?rows.slice(0,4).map(x=>notificationItemHtml(x,{compact:true})).join(''):'<div class=notification-empty>No important notifications.</div>';preview.querySelectorAll('[data-notification-id]').forEach(x=>x.addEventListener('click',()=>openNotification(notificationItems.get(x.dataset.notificationId))))}}
function markAllNotificationsRead(){const seen=notificationSeenSet();for(const id of notificationItems.keys())seen.add(String(id));storeNotificationSeen(seen);const defs=currentSystemStatus?.revisions?.definitionsRevision;if(defs)try{localStorage.setItem('deltascope.lastDefinitionsRevision.v1',String(defs))}catch{}renderNotifications()}
async function openNotification(n){if(!n)return;const seen=notificationSeenSet();seen.add(String(n.id));storeNotificationSeen(seen);renderNotifications();$('notificationDrawer').hidden=true;$('notificationButton').setAttribute('aria-expanded','false');if(n.variantId){setPerspective(currentPerspective,{navigate:false});await loadDetail(Number(n.variantId),n.tab||'findings');setWorkbenchView('assets');return}if(n.action==='refresh-evidence'){await refreshEvidence();return}if(n.view){setWorkbenchView(n.view);return}}
const RULE_LIBRARY_COLLAPSED_KEY='omega.deltascope.rule-library-collapsed.v1';
function applyRuleLibraryCollapsed(collapsed){ruleLibraryCollapsed=!!collapsed;const shell=$('ruleBrowserShell'),button=$('ruleLibraryToggle');if(shell)shell.classList.toggle('rule-library-collapsed',ruleLibraryCollapsed);if(button){button.setAttribute('aria-expanded',ruleLibraryCollapsed?'false':'true');button.setAttribute('aria-label',ruleLibraryCollapsed?'Expand rule library':'Collapse rule library');button.title=ruleLibraryCollapsed?'Expand rule library':'Collapse rule library'}try{localStorage.setItem(RULE_LIBRARY_COLLAPSED_KEY,ruleLibraryCollapsed?'1':'0')}catch(_e){}}
function toggleRuleLibrary(){applyRuleLibraryCollapsed(!ruleLibraryCollapsed)}
function setVisualFocus(enabled){const shell=$('ruleBrowserShell'),button=$('ruleVisualFocus');if(shell)shell.classList.toggle('visual-focus',!!enabled);if(button){button.textContent=enabled?'Exit focus':'Focus canvas';button.setAttribute('aria-pressed',enabled?'true':'false')}}
function toggleVisualFocus(){setVisualFocus(!$('ruleBrowserShell')?.classList.contains('visual-focus'))}

function restoreRuleLibraryState(){let collapsed=false;try{collapsed=localStorage.getItem(RULE_LIBRARY_COLLAPSED_KEY)==='1'}catch(_e){}applyRuleLibraryCollapsed(collapsed)}
const NAV_COLLAPSED_KEY='omega.deltascope.nav-collapsed.v1';
function applyNavigationCollapsed(collapsed){document.body.classList.toggle('nav-collapsed',!!collapsed);const b=$('navToggle');if(b)b.setAttribute('aria-expanded',collapsed?'false':'true');try{localStorage.setItem(NAV_COLLAPSED_KEY,collapsed?'1':'0')}catch(_e){}}
function toggleNavigation(){applyNavigationCollapsed(!document.body.classList.contains('nav-collapsed'))}
function restoreNavigationState(){let collapsed=false;try{collapsed=localStorage.getItem(NAV_COLLAPSED_KEY)==='1'}catch(_e){}applyNavigationCollapsed(collapsed)}
function toggleNotifications(force){const d=$('notificationDrawer'),open=force===undefined?d.hidden:!!force;if(open&&!$('pluginPickerDrawer').hidden)togglePluginPicker(false);d.hidden=!open;$('notificationButton').setAttribute('aria-expanded',open?'true':'false');if(open)renderNotifications()}
function toggleAppSwitcher(force){const d=$('appSwitcherDrawer'),open=force===undefined?d.hidden:!!force;if(open&&!$('notificationDrawer').hidden)toggleNotifications(false);if(open&&!$('pluginPickerDrawer').hidden)togglePluginPicker(false);d.hidden=!open;$('appSwitcherButton').setAttribute('aria-expanded',open?'true':'false')}
async function openAppSwitcherAction(action){toggleAppSwitcher(false);if(action==='github'){window.open('https://github.com/dalagab/omega','_blank','noopener,noreferrer');return}if(action==='support'){window.open('https://github.com/dalagab/omega/issues','_blank','noopener,noreferrer');return}if(action==='new-rule'){setPerspective('researcher',{navigate:false});setWorkbenchView('rules');await loadRuleCatalog();if(typeof newLocalRule==='function')newLocalRule();return}}
function renderPluginPicker(){const host=$('pluginPickerList');if(!host)return;const q=String(pluginPickerFilter||'').trim().toLowerCase(),currentId=Number(currentSubject?.variantId||0),rows=headerPluginRows.slice().sort((a,b)=>String(a.canonical_name||a.name||a.internal_name||'').localeCompare(String(b.canonical_name||b.name||b.internal_name||''),undefined,{sensitivity:'base'})).filter(r=>!q||[r.canonical_name,r.name,r.internal_name,r.author,r.assembly_version].some(v=>String(v||'').toLowerCase().includes(q))).slice(0,250);host.innerHTML=rows.length?rows.map(r=>{const id=Number(r.variant_id||0),name=r.canonical_name||r.name||r.internal_name||'Plugin';return `<button class="plugin-picker-item ${id===currentId?'active':''}" data-plugin-picker-id="${id}"><span><span class=plugin-picker-name>${esc(name)}</span><span class=plugin-picker-meta>${esc(r.author||r.internal_name||'')}${r.assembly_version?' · '+esc(r.assembly_version):''}</span></span><span class="plugin-picker-severity ${sev(r.highest_severity)}">${esc(r.highest_severity||'none')}</span></button>`}).join(''):'<div class=plugin-picker-empty>No plugins match this search.</div>';host.querySelectorAll('[data-plugin-picker-id]').forEach(x=>x.addEventListener('click',()=>selectHeaderPlugin(x.dataset.pluginPickerId)))}
function renderHeaderPluginSelect(){const select=$('headerPluginSelect');if(!select)return;const currentId=Number(currentSubject?.variantId||0),rows=headerPluginRows.slice().sort((a,b)=>String(a.canonical_name||a.name||a.internal_name||'').localeCompare(String(b.canonical_name||b.name||b.internal_name||''),undefined,{sensitivity:'base'}));let options='<option value="">Select a plugin…</option>';if(currentSubject&&currentId&&!rows.some(r=>Number(r.variant_id)===currentId))options+=`<option value="${currentId}">${esc(currentSubject.name)}${currentSubject.version?' · '+esc(currentSubject.version):''}</option>`;options+=rows.map(r=>`<option value="${Number(r.variant_id||0)}">${esc(r.canonical_name||r.name||r.internal_name||'Plugin')}${r.assembly_version?' · '+esc(r.assembly_version):''}</option>`).join('');select.innerHTML=options;select.value=currentId?String(currentId):'';const button=$('pluginPickerButton'),state=$('pluginPickerState'),title=$('pluginPickerTitle'),kicker=$('pluginPickerKicker');if(button)button.title=currentSubject?.name?`${currentPerspective==='developer'?'My plugin':'Selected plugin'}: ${currentSubject.name}`:'Select plugin';if(state)state.classList.toggle('active',!!currentId);if(title)title.textContent=currentSubject?.name?currentSubject.name:'Select a plugin';if(kicker)kicker.textContent=currentPerspective==='developer'?'MY PLUGIN':currentPerspective==='investigator'?'SUBJECT':'PLUGIN CONTEXT';renderPluginPicker()}
function togglePluginPicker(force){const d=$('pluginPickerDrawer'),open=force===undefined?d.hidden:!!force;if(open){if(!$('notificationDrawer').hidden)toggleNotifications(false);if(!$('appSwitcherDrawer').hidden)toggleAppSwitcher(false)}d.hidden=!open;$('pluginPickerButton').setAttribute('aria-expanded',open?'true':'false');if(open){pluginPickerFilter='';$('pluginPickerSearch').value='';renderPluginPicker();setTimeout(()=>$('pluginPickerSearch')?.focus(),0)}}
async function selectHeaderPlugin(id){const variantId=Number(id||0);togglePluginPicker(false);if(!variantId){clearSubject();return}await loadDetail(variantId,'overview');if(currentPerspective==='developer')setWorkbenchView('developer')}
function renderDashboardPlatformOverview(){const s=currentSourceStatus||{},sum=currentSummary||{},sys=currentSystemStatus||{},rev=sys.revisions||sum.revisions||sum.meta||{},checks=Array.isArray(sys.checks)?sys.checks:[],gated=checks.filter(x=>['gated','fail'].includes(String(x.status||'').toLowerCase()));const defs=rev.definitionsRevision||rev.definitionRevision||'—';const defsEl=$('dashboardDefinitions');if(defsEl)defsEl.textContent=String(defs);const auth=$('dashboardAuthority');if(auth)auth.textContent=gated.length?`${gated.length} gate${gated.length===1?'':'s'} active`:'Normal';const authDetail=$('dashboardAuthorityDetail');if(authDetail)authDetail.textContent=gated.length?gated.map(x=>x.label||x.code).join(' · '):'No failed or gated production checks in the current snapshot.';renderNotifications()}
function syncDefinitionsNotification(){const revision=currentSystemStatus?.revisions?.definitionsRevision;if(!revision)return;let previous='';try{previous=localStorage.getItem('deltascope.lastDefinitionsRevision.v1')||''}catch{}if(!previous){try{localStorage.setItem('deltascope.lastDefinitionsRevision.v1',String(revision))}catch{}return}if(previous!==String(revision))upsertNotification({id:`definitions:${revision}`,level:'info',rank:70,title:'Security Definitions updated',detail:`Definitions changed from ${previous} to ${revision}.`,meta:'Review the exact frozen Definitions and production gates in System health.',view:'system',time:String(revision)})}
function syncSystemNotifications(s){for(const c of (s?.checks||[])){const status=String(c.status||'').toLowerCase();if(status==='fail'||status==='gated')upsertNotification({id:`system:${c.code||c.label}:${status}:${c.detail||''}`,level:status==='fail'?'fail':'warn',rank:status==='fail'?95:75,title:status==='fail'?'Production safety check failed':'Production capability gated',detail:`${c.label||c.code||'System check'} — ${c.detail||status}.`,meta:'System health · read only',view:'system'})}syncDefinitionsNotification();renderDashboardPlatformOverview()}
function syncCriticalFindingNotifications(payload){latestFindingsPayload=payload;for(const f of (payload?.findings||[]).filter(x=>String(x.severity||'').toLowerCase()==='critical').slice(0,8)){const key=f.findingId||f.ruleId||f.title||'finding';upsertNotification({id:`critical:${f.variantId}:${key}:${f.occurredAtUtc||''}`,level:'critical',rank:100,title:`Critical finding · ${f.plugin||f.internalName||'plugin'}`,detail:f.title||f.findingId||'Critical security finding',meta:`${f.occurredAtUtc||''} · ${f.ruleId||f.findingId||''}`,variantId:Number(f.variantId||0),tab:'findings',time:f.occurredAtUtc||''})}}

const helpTopics={
 'source-attribution':{title:'Source attribution',body:'DeltaScope can associate public source material with a plugin using recorded provenance and confidence. Attribution does not automatically prove that the published binary was built from that source.'},
 'source-binary':{title:'Source ↔ artifact verification',body:'Source-to-artifact verification is stronger than attribution: it asks whether the installable artifact can be tied to the attributed source/build. “Not verified” is not the same as “mismatch”.'},
 'coverage':{title:'Review coverage',body:'Coverage describes what evidence was actually available and inspected: artifact, source, secondary engines, retained observations and optional deeper analysis. Coverage is separate from severity.'},
 'severity':{title:'Severity',body:'Severity describes the strongest current security finding. It is not a trust score and should be read together with coverage and the finding evidence.'},
 'finding':{title:'Security finding',body:'A finding is a deterministic conclusion produced from retained observations or scanner checks. Open its rule and evidence to see why it exists.'},
 'capability':{title:'Observed capability',body:'Capabilities describe behavior or access that static analysis can support from the plugin artifact/source. A capability can be legitimate; context determines risk.'},
 'endpoint':{title:'Endpoint evidence',body:'Static endpoint evidence means a URL/host was observed in analyzed material. It does not by itself prove the plugin contacted that destination at runtime.'},
 'srl':{title:'Stigma-1 / SRL',body:'Stigma-1 evaluates deterministic SRL rules over normalized retained evidence. Rules cannot silently promote themselves or bypass the GitHub review/Definitions boundary.'},
 'deep-scan':{title:'Deep analysis',body:'A reviewed rule can request a bounded approved analysis profile when normal evidence is insufficient. The request is evidence acquisition, not automatic production finding write-back.'},
 'rift':{title:'Rift runtime observation',body:'The Interdimensional Rift is the separate runtime-observation branch/environment. Runtime evidence is neutral input and does not replace SigmaScope static analysis.'},
 'yara':{title:'YARA',body:'Reviewed YARA rules are a secondary static signal over artifacts. A match requires interpretation; no match is not a guarantee that an artifact is safe.'},
 'clamav':{title:'ClamAV',body:'ClamAV is a secondary malware-signature signal. DeltaScope preserves its result alongside SigmaScope evidence rather than treating it as the only verdict.'},
 'observation':{title:'Retained observation',body:'Observations are rule-neutral facts collected during analysis. Keeping observations separate from conclusions allows deterministic replay when rules or intelligence change.'},
 'revision':{title:'Evidence revision',body:'Revision identifiers pin the exact published evidence, Definitions and rule projections used for reproducibility. They are technical provenance, not user-facing health scores.'}
};
function openHelp(topic){const h=helpTopics[topic]||{title:'DeltaScope help',body:'This view is read-only. Follow linked evidence and provenance to understand how a conclusion was produced.'};$('helpTitle').textContent=h.title;$('helpBody').innerHTML=`<p>${esc(h.body)}</p><div class=muted>Context help explains semantics; the immutable evidence and exact revisions remain available in the researcher view.</div>`;$('helpDrawer').hidden=false}
function wireContextHelp(root=document){root.querySelectorAll('[data-help-topic]').forEach(x=>{if(x.dataset.helpWired==='1')return;x.dataset.helpWired='1';x.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openHelp(x.dataset.helpTopic)})})}
const perspectiveConfig={
 developer:{label:'Plugin Developer',description:'What Omega found on your plugin and how to make its behavior, source and metadata easier to understand.',defaultView:'developer',note:'Developer context improves transparency and indexing. It cannot suppress findings, lower severity, or claim a plugin is safe.',groups:[
  {label:'Develop',items:[{label:'Overview',mark:'D',view:'developer'},{label:'My Plugin',mark:'P',view:'assets',tab:'overview'},{label:'Security Review',mark:'S',view:'assets',tab:'findings'},{label:'Journey',mark:'J',view:'assets',tab:'journey'},{label:'Changes',mark:'C',view:'assets',tab:'compare'},{label:'Omega Profile',mark:'Ω',view:'assets',tab:'profile'},{label:'Source & Build',mark:'B',view:'assets',tab:'supply'}]},
  {label:'Help',items:[{label:'Developer Guide',mark:'?',view:'docs',doc:'plugin-developers'}]}
 ]},
 investigator:{label:'Investigator',description:'Start from a suspicious or interesting plugin and follow findings, observations and relationships without losing the subject.',defaultView:'incidents',note:'Investigation views are derived from published evidence and remain read-only.',groups:[
  {label:'Investigate',items:[{label:'Cases',mark:'I',view:'incidents'},{label:'Plugins',mark:'P',view:'assets',tab:'overview'},{label:'Journey',mark:'J',view:'assets',tab:'journey'},{label:'Findings',mark:'F',view:'assets',tab:'findings'},{label:'Events',mark:'E',view:'events'},{label:'Relationships',mark:'R',view:'assets',tab:'relationships'},{label:'Intelligence',mark:'N',view:'intelligence'}]},
  {label:'Evidence',items:[{label:'Published Evidence',mark:'V',view:'assets',tab:'evidence'},{label:'Documentation',mark:'?',view:'docs'}]}
 ]},
 researcher:{label:'Security Researcher',description:'Study patterns across the ecosystem, inspect deterministic rules, compare variants and work directly with retained evidence.',defaultView:'dashboard',note:'System Rules and published evidence are read-only. My Rules stay local until normal GitHub review/CI.',groups:[
  {label:'Explore',items:[{label:'Overview',mark:'D',view:'dashboard'},{label:'Plugins',mark:'P',view:'assets',tab:'overview'},{label:'Findings',mark:'F',view:'incidents'},{label:'Intelligence',mark:'N',view:'intelligence'},{label:'Relationships',mark:'G',view:'assets',tab:'relationships'}]},
  {label:'Research',items:[{label:'Rules',mark:'R',view:'rules'},{label:'Compare',mark:'C',view:'assets',tab:'compare'},{label:'Reports',mark:'P',view:'reports'},{label:'Data',mark:'V',view:'system'}]},
  {label:'Reference',items:[{label:'Documentation',mark:'?',view:'docs'}]}
 ]},
 operations:{label:'Operations',description:'Watch coverage, queues, publication health, workflow activity and production authority gates.',defaultView:'dashboard',note:'Operations is inspection-only in DeltaScope. Production queues, gates and workflows are controlled outside this workbench.',groups:[
  {label:'Operate',items:[{label:'Overview',mark:'D',view:'dashboard'},{label:'Pipelines',mark:'E',view:'events'},{label:'Collectors',mark:'K',view:'collectors'},{label:'Scan Queue',mark:'Q',view:'reports'},{label:'Evidence',mark:'V',view:'system'},{label:'Definitions & Gates',mark:'S',view:'system'}]},
  {label:'Reference',items:[{label:'Reports',mark:'P',view:'reports'},{label:'Documentation',mark:'?',view:'docs'}]}
 ]}
};
function navIconSvg(label){const key=String(label||'').toLowerCase();const paths={
 'overview':'<rect x="3" y="3" width="5" height="5"/><rect x="12" y="3" width="5" height="5"/><rect x="3" y="12" width="5" height="5"/><rect x="12" y="12" width="5" height="5"/>',
 'my plugin':'<path d="M4 5h12v10H4z"/><path d="M7 2v3m6-3v3M7 15v3m6-3v3"/>',
 'plugins':'<path d="M4 5h12v10H4z"/><path d="M7 2v3m6-3v3M7 15v3m6-3v3"/>',
 'security review':'<path d="M10 2 16 4v5c0 4-2.4 7-6 9-3.6-2-6-5-6-9V4z"/><path d="m7 10 2 2 4-5"/>',
 'findings':'<path d="M10 2 18 17H2z"/><path d="M10 7v4m0 3v.1"/>',
 'journey':'<circle cx="4" cy="4" r="2"/><circle cx="16" cy="16" r="2"/><path d="M6 4h4a3 3 0 0 1 3 3v3a3 3 0 0 0 3 3"/>',
 'changes':'<path d="M3 6h11m-3-3 3 3-3 3M17 14H6m3-3-3 3 3 3"/>',
 'compare':'<path d="M3 6h11m-3-3 3 3-3 3M17 14H6m3-3-3 3 3 3"/>',
 'omega profile':'<path d="M5 2h7l3 3v13H5z"/><path d="M12 2v4h4M8 10h4m-4 3h5"/>',
 'source & build':'<circle cx="5" cy="4" r="2"/><circle cx="15" cy="16" r="2"/><circle cx="5" cy="16" r="2"/><path d="M5 6v8m2-8h3a5 5 0 0 1 5 5v3"/>',
 'developer guide':'<path d="M3 4h6a3 3 0 0 1 3 3v10a3 3 0 0 0-3-3H3z"/><path d="M17 4h-5a3 3 0 0 0-3 3v10a3 3 0 0 1 3-3h5z"/>',
 'documentation':'<path d="M3 4h6a3 3 0 0 1 3 3v10a3 3 0 0 0-3-3H3z"/><path d="M17 4h-5a3 3 0 0 0-3 3v10a3 3 0 0 1 3-3h5z"/>',
 'cases':'<path d="M3 5h14v11H3z"/><path d="M7 5V3h6v2m-3 3v4m0 2v.1"/>',
 'events':'<circle cx="10" cy="10" r="7"/><path d="M10 6v4l3 2"/>',
 'pipelines':'<circle cx="4" cy="4" r="2"/><circle cx="16" cy="10" r="2"/><circle cx="4" cy="16" r="2"/><path d="M6 4h3a3 3 0 0 1 3 3v0a3 3 0 0 0 2 3M6 16h3a3 3 0 0 0 3-3"/>',
 'collectors':'<path d="M3 4h5v5H3zM12 4h5v5h-5zM7.5 12h5v5h-5z"/><path d="M5.5 9v1.5h9V9m-4.5 1.5V12"/>',
 'relationships':'<circle cx="4" cy="10" r="2"/><circle cx="10" cy="4" r="2"/><circle cx="16" cy="10" r="2"/><circle cx="10" cy="16" r="2"/><path d="m5.5 8.5 3-3m3 0 3 3m0 3-3 3m-3 0-3-3"/>',
 'intelligence':'<path d="M7 15h6m-5 3h4"/><path d="M6 10a4 4 0 1 1 8 0c0 2-1 3-2 4H8c-1-1-2-2-2-4z"/>',
 'published evidence':'<ellipse cx="10" cy="5" rx="6" ry="3"/><path d="M4 5v5c0 1.7 2.7 3 6 3s6-1.3 6-3V5m-12 5v5c0 1.7 2.7 3 6 3s6-1.3 6-3v-5"/>',
 'evidence':'<ellipse cx="10" cy="5" rx="6" ry="3"/><path d="M4 5v5c0 1.7 2.7 3 6 3s6-1.3 6-3V5m-12 5v5c0 1.7 2.7 3 6 3s6-1.3 6-3v-5"/>',
 'rules':'<path d="M4 3h12v14H4z"/><path d="M7 7h6M7 10h6M7 13h4"/>',
 'reports':'<path d="M3 17V9m5 8V4m5 13v-6m5 6V7"/>',
 'data':'<ellipse cx="10" cy="5" rx="6" ry="3"/><path d="M4 5v5c0 1.7 2.7 3 6 3s6-1.3 6-3V5m-12 5v5c0 1.7 2.7 3 6 3s6-1.3 6-3v-5"/>',
 'scan queue':'<path d="M4 5h12M4 10h12M4 15h8"/><circle cx="16" cy="15" r="2"/>',
 'definitions & gates':'<path d="M10 2 16 4v5c0 4-2.4 7-6 9-3.6-2-6-5-6-9V4z"/><path d="M7 9h6m-3-3v6"/>'
};return `<svg viewBox="0 0 20 20" aria-hidden="true">${paths[key]||'<circle cx="10" cy="10" r="6"/>'}</svg>`}

function perspectiveRouteKey(item){return `${item.view||''}:${item.tab||item.doc||''}`}
function perspectiveSubjectButtons(){
 const commonSeverity='<span id="subjectSeverity" class="subject-severity"></span>';
 if(currentPerspective==='developer')return commonSeverity+'<button data-subject-tab="findings">Security Review</button><button data-subject-tab="journey">Journey</button><button data-subject-tab="compare">Changes</button><button data-subject-tab="profile">Omega Profile</button><button data-subject-tab="supply">Source & Build</button><button id="subjectAsk">Questions</button><button id="subjectClear">× Clear</button>';
 if(currentPerspective==='investigator')return commonSeverity+'<button data-subject-tab="overview">Overview</button><button data-subject-tab="journey">Journey</button><button data-subject-tab="findings">Findings</button><button data-subject-tab="network">Network</button><button data-subject-tab="relationships">Relationships</button><button id="subjectAsk">Questions</button><button id="subjectClear">× Clear</button>';
 if(currentPerspective==='researcher')return commonSeverity+'<button data-subject-tab="overview">Overview</button><button data-subject-tab="findings">Findings</button><button data-subject-tab="network">Network</button><button data-subject-tab="compare">Compare</button><button data-subject-tab="evidence">Evidence</button><button id="subjectAsk">Questions</button><button id="subjectClear">× Clear</button>';
 return commonSeverity+'<button data-subject-tab="overview">Plugin</button><button id="subjectClear">× Clear</button>';
}
function renderSubjectActions(){const box=$('subjectActions');if(!box)return;box.innerHTML=perspectiveSubjectButtons();const sevEl=$('subjectSeverity');if(sevEl&&currentSubject){sevEl.textContent=String(currentSubject.severity||'none').toUpperCase();sevEl.className='subject-severity '+sev(currentSubject.severity)}box.querySelectorAll('[data-subject-tab]').forEach(x=>x.addEventListener('click',()=>showSubjectTab(x.dataset.subjectTab)));$('subjectAsk')?.addEventListener('click',()=>$('subjectBar').classList.toggle('questions-open'));$('subjectClear')?.addEventListener('click',clearSubject)}
function updatePerspectiveNavActive(){document.querySelectorAll('[data-perspective-route]').forEach(x=>x.classList.toggle('active',x.dataset.perspectiveRoute===currentPerspectiveRoute))}
async function navigatePerspective(item){currentPerspectiveRoute=perspectiveRouteKey(item);updatePerspectiveNavActive();if(item.tab){if(!currentSubject?.variantId){if(currentPerspective==='developer'&&item.label==='My Plugin'){togglePluginPicker(true);toniSay('Choose your plugin from the plugin picker. You can type to filter the list.');return}setWorkbenchView('assets');toniSay(`Select a plugin first. ${item.label} is scoped to one plugin.`);return}await showSubjectTab(item.tab);return}setWorkbenchView(item.view);if(item.doc){await loadDocs();await loadDocument(item.doc)}}
function renderPerspectiveNav(){const cfg=perspectiveConfig[currentPerspective]||perspectiveConfig.developer,box=$('perspectiveNav');box.innerHTML=`<div class=perspective-nav-description>${esc(cfg.description)}</div>`+cfg.groups.map((g,idx)=>`<section class=nav-section data-nav-section="${idx}"><button type=button class=nav-section-toggle aria-expanded=true><span>${esc(g.label)}</span><svg viewBox="0 0 20 20" aria-hidden=true><path d="M5 7.5 10 12l5-4.5"/></svg></button><div class=nav-section-items>${g.items.map(item=>`<button data-perspective-route="${esc(perspectiveRouteKey(item))}"><span class=nav-icon>${navIconSvg(item.label)}</span><span>${esc(item.label)}</span></button>`).join('')}</div></section>`).join('');$('perspectiveSelect').title=cfg.description;box.querySelectorAll('.nav-section-toggle').forEach(btn=>btn.addEventListener('click',()=>{const section=btn.closest('.nav-section'),collapsed=section.classList.toggle('collapsed');btn.setAttribute('aria-expanded',collapsed?'false':'true')}));box.querySelectorAll('[data-perspective-route]').forEach((el)=>{const item=cfg.groups.flatMap(g=>g.items).find(x=>perspectiveRouteKey(x)===el.dataset.perspectiveRoute);el.addEventListener('click',()=>item&&navigatePerspective(item))});updatePerspectiveNavActive()}
function setPerspective(value,{navigate=true}={}){const perspective=['developer','investigator','researcher','operations'].includes(value)?value:'developer';currentPerspective=perspective;document.body.dataset.perspective=perspective;document.body.classList.remove('perspective-developer','perspective-investigator','perspective-researcher','perspective-operations','lens-explorer','lens-developer','lens-researcher');document.body.classList.add('perspective-'+perspective);$('perspectiveSelect').value=perspective;$('subjectBar').classList.toggle('perspective-hidden',perspective==='operations');renderPerspectiveNav();renderSubjectActions();renderHeaderPluginSelect();const cfg=perspectiveConfig[perspective];if(navigate){currentPerspectiveRoute=`${cfg.defaultView}:`;setWorkbenchView(cfg.defaultView);updatePerspectiveNavActive()}if(perspective==='developer')renderDeveloperHome(currentPluginDetail);toniSay(`${cfg.label} perspective: ${cfg.description}`)}
function developerPlatformContextHtml(){const s=currentSummary||{},src=currentSourceStatus||{},sys=currentSystemStatus||{},rev=sys.revisions||s.revisions||s.meta||{};return `<section class=panel><div class=panelhead><div><h2>Omega indexing context</h2><div class="muted small">The scanner/evidence context for the review you are looking at. These identifiers are informational, not a trust score.</div></div></div><div class=dashboard-platform-grid><div class=dashboard-platform-item><div class=label>SigmaScope</div><div class=value>${esc(s.sigmascopeVersion||s.scannerVersion||'—')}</div></div><div class=dashboard-platform-item><div class=label>Evidence</div><div class=value>${esc(src.currentRevision||rev.evidenceRevision||'—')}</div></div><div class=dashboard-platform-item><div class=label>Definitions</div><div class=value>${esc(rev.definitionsRevision||'—')}</div></div><div class=dashboard-platform-item><div class=label>Latest analysis</div><div class=value>${esc(s.latestScanUtc||'—')}</div></div></div></section>`}
function developerNeed(label,detail,tab,state='warn'){return `<div class="developer-need ${esc(state)}"><span class=developer-need-mark>${state==='good'?'✓':state==='bad'?'!':'→'}</span><div><b>${esc(label)}</b><div class="muted small">${esc(detail)}</div></div>${tab?`<button data-dev-tab="${esc(tab)}">Open</button>`:''}</div>`}
function renderDeveloperHome(d){const host=$('developerHomeContent');if(!host)return;if(!d){host.innerHTML=`<div class=developer-welcome><div class=developer-primary><div class=eyebrow>Developer workspace</div><h2>Start with your plugin</h2><p>Choose the plugin you maintain from <b>My plugin</b> in the header. DeltaScope will keep it selected while you review findings, explain expected behavior and build a validated Omega profile.</p><div class=developer-actions><button data-dev-focus-plugin>Choose my plugin</button><button data-dev-open-guide>Read the developer guide</button></div></div><div class=developer-health><div class=developer-status><div class=label>Security review</div><div class=value>Explain findings</div></div><div class=developer-status><div class=label>Omega profile</div><div class=value>Document expected behavior</div></div><div class=developer-status><div class=label>Source & build</div><div class=value>Improve attribution</div></div><div class=developer-status><div class=label>Changes</div><div class=value>Compare releases</div></div></div></div><section class=panel><div class=panelhead><div><h2>How Omega indexes a plugin</h2><div class="muted small">The developer perspective turns independent scanner evidence into an actionable author checklist.</div></div></div><div class=detail><div class=developer-needs>${developerNeed('1 · Select your plugin','Open the current published review for the plugin you maintain.','','good')}${developerNeed('2 · Review what Omega found','Inspect findings, capabilities, network destinations and the exact journey through SigmaScope.','','good')}${developerNeed('3 · Explain expected behavior','Build .omega/plugin.yaml so users can see why legitimate capabilities exist without suppressing independent findings.','','good')}${developerNeed('4 · Improve source/build context','Publish attributable source and release/build metadata so Omega can describe the source/artifact relationship more precisely.','','good')}</div></div></section>${developerPlatformContextHtml()}`;host.querySelector('[data-dev-focus-plugin]')?.addEventListener('click',()=>togglePluginPicker(true));host.querySelector('[data-dev-open-guide]')?.addEventListener('click',async()=>{setWorkbenchView('docs');await loadDocs();await loadDocument('plugin-developers')});return}const i=d.identity||{},r=d.researcher||{},cov=d.sourceCoverage||{},b=d.behaviorConsistency||{},bs=b.summary||{},obs=(d.sourceEvidence||{}).developerProfile||{},profileState=obs.status||'absent',profileAvailable=!!b.profileAvailable,observed=Number(bs.observedCapabilityCount||0),declared=Number(bs.declaredCapabilityCount||0),unexplained=Number(bs.observedUndeclaredCount||0),unexplainedDest=Number(bs.unexplainedDestinationCount||0),mismatch=Number(bs.notExpectedObservedCount||0),explainedObserved=Math.max(0,observed-unexplained),findings=(r.findings||[]).length,needs=[];if(!cov.sourceCodeAvailable)needs.push(developerNeed('Publish or expose attributable source','Omega currently has artifact evidence only. Public attributable source improves explanation and review coverage.','supply'));else if(!cov.sourceToBinaryVerified)needs.push(developerNeed('Improve source → artifact traceability','Omega found source, but cannot prove the distributed artifact was built from it. CI-published releases and reproducible build metadata can improve this.','supply'));else needs.push(developerNeed('Source relationship is strong','The retained source/artifact relationship is verified for this evidence snapshot.','supply','good'));if(profileState==='invalid')needs.push(developerNeed('Fix .omega/plugin.yaml',`Omega found the developer profile but rejected it: ${(obs.diagnostics||[])[0]?.message||'validation error'}.`,'profile','bad'));else if(!profileAvailable)needs.push(developerNeed('Create .omega/plugin.yaml',`${observed} observed capability${observed===1?'':'ies'} currently have no developer-authored explanation. The profile builder can create a validated starter document.`, 'profile'));else{if(unexplained)needs.push(developerNeed('Explain observed capabilities',`${unexplained} observed capability${unexplained===1?' is':'ies are'} not declared in the current developer profile.`,'profile'));if(unexplainedDest)needs.push(developerNeed('Explain network destinations',`${unexplainedDest} concrete observed destination${unexplainedDest===1?' is':'s are'} not covered by the current profile.`,'profile'));if(mismatch)needs.push(developerNeed('Review declaration mismatches',`${mismatch} capability${mismatch===1?' is':'ies are'} observed even though the profile says it is not expected.`,'profile','bad'));if(!unexplained&&!unexplainedDest&&!mismatch)needs.push(developerNeed('Developer explanations cover current observations','The current profile has no obvious observed/undeclared or destination mismatch in the compact evidence.','profile','good'))}host.innerHTML=`<div class=developer-welcome><div class=developer-primary><div class=eyebrow>Selected plugin</div><h2>${esc(i.canonical_name||i.name||i.internal_name||'Plugin')}</h2><p>${esc(pluginPlainSummary(d))}</p><div class=developer-actions><button data-dev-tab=findings>Explain my findings</button><button data-dev-tab=profile>Build Omega profile</button><button data-dev-tab=compare>What changed?</button></div></div><div class=developer-health><div class=developer-status><div class=label>Highest static result</div><div class="value ${sev(i.highest_severity)}">${esc(String(i.highest_severity||'none').toUpperCase())}</div></div><div class=developer-status><div class=label>Security findings</div><div class=value>${fmt(findings)}</div></div><div class=developer-status><div class=label>Profile coverage</div><div class=value>${profileAvailable?`${fmt(explainedObserved)}/${fmt(observed)} observed explained`:'No profile yet'}</div></div><div class=developer-status><div class=label>Source & build</div><div class=value>${cov.sourceToBinaryVerified?'Verified':cov.sourceCodeAvailable?'Source attributed':'Artifact only'}</div></div></div></div><section class=panel><div class=panelhead><div><h2>What Omega needs from you</h2><div class="muted small">Actionable gaps in explanation/indexing; these do not alter independent scanner evidence.</div></div><span class=muted>${fmt(declared)} declared capabilities</span></div><div class="detail developer-needs">${needs.join('')}</div></section>${developerPlatformContextHtml()}`;host.querySelectorAll('[data-dev-tab]').forEach(x=>x.addEventListener('click',()=>showSubjectTab(x.dataset.devTab)));host.querySelectorAll('[data-dev-open-guide]').forEach(x=>x.addEventListener('click',async()=>{setWorkbenchView('docs');await loadDocs();await loadDocument('plugin-developers')}))}

function updateSubject(d){const i=d?.identity||{},r=d?.researcher||{};const id=Number(i.variant_id||i.variantId||0);if(!id)return;currentSubject={variantId:id,name:i.canonical_name||i.name||i.internal_name||`Variant ${id}`,version:i.assembly_version||'',author:i.author||'',severity:i.highest_severity||'none',snapshotKind:d.snapshotKind||'current'};$('subjectBar').classList.add('active');renderSubjectActions();$('subjectName').textContent=currentSubject.name;$('subjectMeta').textContent=`variant ${id}${currentSubject.version?' · '+currentSubject.version:''}${currentSubject.author?' · '+currentSubject.author:''} · ${d.sourceCoverage?.sourceCodeAvailable?'artifact + source':'artifact evidence'} · ${(r.findings||[]).length||0} finding(s)`;const severity=$('subjectSeverity');if(severity){severity.textContent=String(currentSubject.severity||'none').toUpperCase();severity.className='subject-severity '+sev(currentSubject.severity)}$('pluginRows')?.querySelectorAll?.('[data-variant]').forEach(x=>x.classList.toggle('selected',Number(x.dataset.variant)===id));renderHeaderPluginSelect();renderDeveloperHome(d)}
function clearSubject(){currentSubject=null;currentPluginDetail=null;currentCompare=null;$('subjectBar').classList.remove('active');$('subjectQuestions').classList.remove('open');renderSubjectActions();renderHeaderPluginSelect();renderDeveloperHome(null);if(currentWorkbenchView==='assets'){$('detailTitle').textContent='Select a plugin to investigate';$('detailMeta').textContent='Overview → Journey → findings → relationships → immutable evidence';$('pluginDetail').innerHTML='<div class=empty>Choose a plugin. Its dossier will remain selected while you move through DeltaScope.</div>'}toniSay('Current subject cleared. Use Plugins or the global search box to select another plugin.')}
function activateResearchTab(tab){const detail=$('pluginDetail');const b=detail?.querySelector?.(`[data-research-tab="${tab}"]`);if(b){b.click();return true}return false}
async function showSubjectTab(tab){if(!currentSubject?.variantId)return;const cfg=perspectiveConfig[currentPerspective],routeItem=cfg?.groups?.flatMap(g=>g.items||[]).find(x=>x.view==='assets'&&x.tab===tab);if(routeItem){currentPerspectiveRoute=perspectiveRouteKey(routeItem);updatePerspectiveNavActive()}setWorkbenchView('assets');const id=currentSubject.variantId,currentId=Number(currentPluginDetail?.identity?.variant_id||0);if(currentId!==id){await loadDetail(id,tab);return}if(!activateResearchTab(tab))activateResearchTab('overview')}
async function runSubjectQuestion(kind){if(!currentSubject?.variantId)return;const d=currentPluginDetail;if(kind==='network'){await showSubjectTab('network');toniSay('Network shows every compact endpoint observation for the selected plugin. Static endpoint evidence is not automatically runtime contact.');return}if(kind==='changed'){await showSubjectTab('compare');toniSay('Compare shows security-semantic differences between the selected current variant and a retained prior snapshot.');return}if(kind==='why'){await showSubjectTab('overview');const sig=(d?.researcher?.signals||[]).slice(0,3).map(x=>x.label).join('; ');toniSay(`${currentSubject.name} is currently ${currentSubject.severity}. ${sig||'No elevated compact triage signal explains a higher severity; inspect Findings for the exact deterministic evidence.'}`);return}if(kind==='deep'){await showSubjectTab('journey');try{const j=await api('/api/workbench/journey?variant_id='+currentSubject.variantId),x=(j.stages||[]).find(s=>s.stageId==='deep-analysis');toniSay(x?`Deep analysis: ${x.summary} ${(x.details||[]).join(' · ')}`:'No deep-analysis stage is available.')}catch(e){toniSay(e.message)}return}if(kind==='missing'){await showSubjectTab('overview');const cov=d?.sourceCoverage||{},eng=d?.secondarySecurity?.engines||[],missing=[];if(!cov.sourceCodeAvailable)missing.push('attributable source code');if(cov.sourceCodeAvailable&&!cov.sourceToBinaryVerified)missing.push('verified source→artifact build equivalence');for(const e of eng){if(e.available===false||!['complete','ready'].includes(String(e.status||'').toLowerCase()))missing.push(`${e.engine||'secondary engine'} completion`)}toniSay(missing.length?`Evidence gaps for ${currentSubject.name}: ${missing.join('; ')}.`:`No obvious compact coverage gap is recorded. Open Immutable evidence for exact retained-dataset completeness.`)}}
function searchKindMark(kind){return ({plugin:'P',endpoint:'N',component:'C',advisory:'V',rule:'R'})[kind]||'?'}
function hideGlobalSearch(){const box=$('globalSearchResults');box.hidden=true;box.innerHTML=''}
function renderGlobalSearch(p){const box=$('globalSearchResults'),rows=p?.results||[];if(!rows.length){box.innerHTML='<div class=workspace-empty>No matching DeltaScope objects.</div>';box.hidden=false;return}let last='';box.innerHTML=rows.map((r,idx)=>{const g=r.group||'Results',head=g!==last?(last=g,`<div class=search-group>${esc(g)}</div>`):'';return head+`<button class=search-result data-search-index="${idx}"><span class=search-kind>${searchKindMark(r.kind)}</span><span><span class=search-result-title>${esc(r.label||'Result')}</span><span class=search-result-sub>${esc(r.subtitle||'')}</span></span>${r.severity?`<span class="${sev(r.severity)} small">${esc(r.severity)}</span>`:''}</button>`}).join('');box.hidden=false;box.querySelectorAll('[data-search-index]').forEach(x=>x.addEventListener('click',()=>openGlobalSearchResult(rows[Number(x.dataset.searchIndex)])))}
async function openGlobalSearchResult(r){hideGlobalSearch();$('globalSearch').value='';if(r.kind==='plugin'){setWorkbenchView('assets');await loadDetail(Number(r.variantId),'overview');return}if(['endpoint','component','advisory'].includes(r.kind)){setWorkbenchView('intelligence');await loadIntelligencePivot(r.pivotKind||r.kind,r.key);return}if(r.kind==='rule'){setWorkbenchView('rules');await loadRuleCatalog();if(r.packId&&r.ruleId)selectSystemRule(r.packId,r.ruleId);else{const hit=(currentRuleLibrary?.packs||[]).flatMap(p=>(p.rules||[]).map(x=>({p:p.packId,r:x}))).find(x=>x.r.ruleId===r.ruleId);if(hit)selectSystemRule(hit.p,hit.r.ruleId)}return}}
function scheduleGlobalSearch(){clearTimeout(globalSearchTimer);const q=$('globalSearch').value.trim();if(!q){hideGlobalSearch();return}globalSearchTimer=setTimeout(async()=>{try{renderGlobalSearch(await api('/api/workbench/search?q='+encodeURIComponent(q)+'&limit=50'))}catch(e){$('globalSearchResults').innerHTML=`<div class=research-error>${esc(e.message)}</div>`;$('globalSearchResults').hidden=false}},160)}

function toniSay(message){$('toniMessage').textContent=message}
function toniOverview(){const c=currentSummary?.counts||{};toniSay(`${fmt(c.variants)} variants currently have published results. ${fmt(c.unscannedVariantsPending)} active variants are still waiting for their first artifact scan; SigmaScope now prioritizes those before revisiting covered variants. ${fmt(c.reviewVariants)} current variants are high/critical review candidates.`)}
function toniQueue(){const c=currentSummary?.counts||{},b=currentSummary?.lastBatch||{};toniSay(`Coverage-first queue: ${fmt(c.unscannedVariantsPending)} never-scanned variants first, then retries for still-uncovered artifacts, then rescans/source follow-ups. Current queue: ${fmt(c.queuePending)} pending, ${fmt(c.queueRetry)} retry. Last batch selected ${fmt(b.selectedCount||0)} work items${b.scanElapsedSeconds?` in ${Number(b.scanElapsedSeconds).toFixed(1)} seconds`:''}.`)}
function toniSelection(){if(!currentPluginDetail){toniSay('Select a plugin. I’ll tell you first whether we have only the artifact or also attributable source code, then summarize the strongest triage signals.');return}const d=currentPluginDetail,i=d.identity||{},r=d.researcher||{},sec=d.secondarySecurity||{},cov=d.sourceCoverage||{};const engines=Array.isArray(sec.engines)?sec.engines:[];const bits=engines.map(e=>{const n=e.engine||e.name||'engine',m=(e.matches||[]).length,status=String(e.status||'unknown');return `${n}: ${m?m+' match'+(m===1?'':'es'):status==='complete'?'no matches':status}`});const signals=(r.signals||[]).slice(0,2).map(x=>x.label).filter(Boolean);const coverage=cov.sourceCodeAvailable?`artifact + source code (${cov.coverageLabel||cov.attributionConfidence+'/100 attribution'})`:'artifact only; no attributable source code is recorded';toniSay(`${i.canonical_name||i.name||i.internal_name||'This plugin'}: ${coverage}. ${bits.length?bits.join('; ')+'. ':''}${signals.length?'Main review signals: '+signals.join('; ')+'. ':''}Static severity is ${i.highest_severity||'unrated'}.`)}
function workbenchSeverityRank(value){return ({critical:4,high:3,caution:2,medium:2,moderate:2,informational:1,low:1,none:0})[String(value||'none').toLowerCase()]||0}
function setWorkbenchView(name){currentWorkbenchView=name;document.querySelectorAll('[data-workbench-view]').forEach(x=>x.classList.toggle('active',x.dataset.workbenchView===name));document.querySelectorAll('[data-workbench-nav]').forEach(x=>x.classList.toggle('active',x.dataset.workbenchNav===name));const messages={developer:'Plugin Developer keeps your selected plugin at the center: review findings, explain expected behavior, improve source/build context, and generate a validated Omega profile.',dashboard:'Dashboard summarizes current security activity and component health.',incidents:'Cases starts with concrete findings and composes the evidence around them.',events:'Events combines read-only workflow activity with normalized evidence events.',collectors:'Collectors shows what feeds Omega, how recent collection runs behaved, what data they processed, and what they produced.',intelligence:'Intelligence lets you pivot through shared endpoints, components and advisories.',assets:'Plugins is the object-centric dossier view. Select once, then follow the evidence without losing context.',rules:'Rules is the Stigma-1 workspace. System Rules remain read-only; My Rules are local and versioned.',reports:'Reports summarize coverage, queue and deterministic replay readiness.',docs:'Documentation is the deep reference; contextual explanations are also available beside evidence.',system:'System health answers whether evidence and components are healthy; exact revision IDs are advanced detail.'};toniSay(messages[name]||'DeltaScope remains read only.');if(name==='developer')renderDeveloperHome(currentPluginDetail);if(name==='rules')loadRuleCatalog();if(name==='reports')loadReports();if(name==='docs')loadDocs();if(name==='system'||name==='dashboard')loadSystemStatus();if(name==='dashboard'||name==='events')loadOperations(false);if(name==='collectors')loadCollectors(false);if(name==='incidents')loadLatestFindings();updatePerspectiveNavActive()}
function ruleOutputLabel(r){const e=r?.emit||{};return e.findingId?`finding · ${e.findingId}`:e.fact?`fact · ${e.fact}`:'—'}
function ruleReviewLabel(p){const r=p?.review||{};return r.reviewer?`${r.reviewer}${r.reviewedAtUtc?' · '+r.reviewedAtUtc:''}`:'—'}
function ruleLibraryPack(packId){return (currentRuleLibrary?.packs||[]).find(x=>x.packId===packId)}
function ruleLibraryRule(packId,ruleId){return (ruleLibraryPack(packId)?.rules||[]).find(x=>x.ruleId===ruleId)}
function activeRuleIds(){return new Set((currentRuleCatalog?.rules||[]).map(x=>String(x.ruleId||'')))}
function markRuleWorkspaceDirty(value=true){ruleWorkspaceDirty=!!value;const title=$('ruleWorkspaceTitle');if(title)title.classList.toggle('rule-dirty-dot',ruleWorkspaceDirty);const save=$('ruleSaveLocal');if(save)save.disabled=!(currentWorkspaceRule?.editable&&ruleWorkspaceDirty);const origin=$('ruleWorkspaceOrigin');if(origin&&ruleWorkspaceDirty){origin.classList.add('rule-workspace-origin-dirty')}else if(origin){origin.classList.remove('rule-workspace-origin-dirty')}}
function workspaceRuleOriginLabel(rule){if(!rule)return'NO RULE';if(rule.origin==='system')return activeRuleIds().has(rule.ruleId)?'SYSTEM · ACTIVE':'SYSTEM · SOURCE';if(rule.origin==='local')return`MY RULE · r${rule.revision||0}`;if(rule.origin==='new')return'MY RULE · UNSAVED';return'LOCAL'}
function updateRuleWorkspaceHeader(){const r=currentWorkspaceRule||{};$('ruleWorkspaceTitle').textContent=r.ruleId||'Select a rule';$('ruleWorkspaceKicker').textContent=r.origin==='system'?`Definition Pack · ${r.packId||''}`:r.origin==='local'||r.origin==='new'?'Versioned local authoring':'Stigma-1 · SRL Core';$('ruleWorkspaceMeta').textContent=r.origin==='system'?`${r.kind||''} · ${r.status||''} · read-only repository source`:r.origin==='local'?`${r.kind||''} · ${r.status||''} · revision ${r.revision||0} · ${r.updatedAtUtc||''}`:r.origin==='new'?'New local rule · not saved yet':'System rules are read-only; fork one or create a local rule to edit.';const o=$('ruleWorkspaceOrigin');o.textContent=workspaceRuleOriginLabel(r);o.className='pill '+(r.origin==='system'?'rule-workspace-origin-system':r.origin==='local'||r.origin==='new'?'rule-workspace-origin-local':'readonly-pill');$('ruleForkLocal').disabled=!(r.origin==='system'&&r.yaml);$('ruleSaveLocal').disabled=!(r.editable&&ruleWorkspaceDirty);$('ruleYaml').readOnly=!r.editable;$('ruleImport').disabled=!r.editable;$('ruleFormat').disabled=!r.editable;$('ruleExample').disabled=!r.editable;$('ruleVisualConnect').disabled=!r.editable;$('ruleVisualToYaml').disabled=!r.editable;document.querySelectorAll('[data-visual-add]').forEach(x=>{x.disabled=!r.editable;x.setAttribute('aria-disabled',String(!r.editable))});markRuleWorkspaceDirty(ruleWorkspaceDirty)}
function ruleWorkspaceSetEditor(yaml,rule){currentWorkspaceRule={...rule,yaml:yaml||''};currentVisualGraph=null;selectedVisualNode=null;visualConnectMode=false;visualConnectSource=null;setRuleEditorValue(yaml||'');markRuleWorkspaceDirty(false);updateRuleWorkspaceHeader();renderRuleTree();if(document.querySelector('[data-rule-workspace-tab="visual"]')?.classList.contains('active'))loadVisualGraphFromYaml();ruleCompileCandidate()}
function ruleWorkspaceSetTab(name){document.querySelectorAll('[data-rule-workspace-tab]').forEach(x=>x.classList.toggle('active',x.dataset.ruleWorkspaceTab===name));document.querySelectorAll('[data-rule-workspace-pane]').forEach(x=>x.classList.toggle('active',x.dataset.ruleWorkspacePane===name));if(name==='visual')loadVisualGraphFromYaml();else setVisualFocus(false);if(name==='explain')ruleCompileCandidate()}
async function selectSystemRule(packId,ruleId){const r=ruleLibraryRule(packId,ruleId);if(!r)return;currentRuleLibrarySelection={kind:'system',packId,key:ruleId};ruleWorkspaceSetEditor(r.candidateYaml||'',{origin:'system',editable:false,ruleId:r.ruleId,packId,kind:r.kind,status:r.status,sourcePath:r.sourcePath,ruleRevision:r.ruleRevision});toniSay(`Opened ${ruleId} from System Rules. It is read-only here. Fork it to My Rules if you want an editable, versioned local copy.`)}
async function selectLocalRule(ruleId){try{const r=await api('/api/rule-lab/local?rule_id='+encodeURIComponent(ruleId));currentRuleLibrarySelection={kind:'local',packId:'',key:ruleId};ruleWorkspaceSetEditor(r.yaml||'',{origin:'local',editable:true,ruleId:r.ruleId,kind:r.rule?.kind||'',status:r.rule?.status||'',revision:r.metadata?.revision||0,updatedAtUtc:r.metadata?.updatedAtUtc||'',expectedRuleId:r.ruleId});toniSay(`Opened ${ruleId} from My Rules at revision ${r.metadata?.revision||0}. Save creates another immutable local revision; it does not touch Definitions.`)}catch(e){$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`}}
async function newLocalRule(){let id=prompt('Local SRL rule ID','local.new-rule');if(id===null)return;id=String(id||'').trim();if(!id)return;try{const r=await api('/api/rule-lab/new',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ruleId:id,kind:'observation'})});currentRuleLibrarySelection={kind:'new',packId:'',key:id};ruleWorkspaceSetEditor(r.yaml||'',{origin:'new',editable:true,ruleId:id,kind:'observation',status:'experimental',revision:0,expectedRuleId:''});markRuleWorkspaceDirty(true);toniSay(`Created unsaved local rule ${id}. It exists only in this browser workspace until you press Save revision.`)}catch(e){alert(e.message)}}
async function forkCurrentRule(){if(currentWorkspaceRule?.origin!=='system')return;const base=String(currentWorkspaceRule.ruleId||'rule').split('.').pop()||'rule';let id=prompt('New local rule ID',`local.${base}`);if(id===null)return;id=String(id||'').trim();if(!id)return;try{const r=await api('/api/rule-lab/local/fork',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:$('ruleYaml').value,newRuleId:id})});await loadRuleWorkspace(true);await selectLocalRule(r.ruleId);toniSay(`Forked ${currentWorkspaceRule?.ruleId||id} into versioned My Rules. The System Rule was not modified.`)}catch(e){alert(e.message)}}
async function saveCurrentLocalRule(){if(!currentWorkspaceRule?.editable)return;try{const r=await api('/api/rule-lab/local/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:$('ruleYaml').value,expectedRuleId:currentWorkspaceRule.origin==='local'?currentWorkspaceRule.expectedRuleId||currentWorkspaceRule.ruleId:''})});await loadRuleWorkspace(true);await selectLocalRule(r.ruleId);$('ruleLabStatus').innerHTML=`<div class=pass>${r.unchanged?'No content change; existing revision retained.':`Saved local revision ${esc(r.revisionId||'')}.`}</div>`}catch(e){$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`;ruleWorkspaceSetTab('explain')}}
function renderRuleTree(){const root=$('ruleTree');if(!root||!currentRuleWorkspace)return;const q=String($('ruleLibrarySearch')?.value||'').trim().toLowerCase(),system=currentRuleWorkspace.system||{},local=currentRuleWorkspace.local||{},active=activeRuleIds();const packs=(system.packs||[]).map(p=>{const packMatch=!q||[p.packId,p.title,p.description].join(' ').toLowerCase().includes(q);const rules=(p.rules||[]).filter(r=>packMatch||[r.ruleId,r.title,r.kind,r.output].join(' ').toLowerCase().includes(q));if(q&&!packMatch&&!rules.length)return'';return `<details open><summary><span class=rule-tree-icon>P</span><span class=rule-tree-title>${esc(p.packId)}</span><span class=rule-tree-folder-meta>${fmt(rules.length)}</span></summary><div>${rules.map(r=>`<button class="rule-tree-row ${currentRuleLibrarySelection?.kind==='system'&&currentRuleLibrarySelection?.key===r.ruleId?'active':''}" data-system-rule="${esc(r.ruleId)}" data-system-pack="${esc(p.packId)}"><span class=rule-tree-icon>r</span><span class=rule-tree-title title="${esc(r.title||r.ruleId)}">${esc(r.ruleId)}</span><span class="rule-tree-meta ${active.has(r.ruleId)?'active-badge':''}">${active.has(r.ruleId)?'ACTIVE':esc(r.kind||'')}</span></button>`).join('')||'<div class=rule-empty-note>No matching System Rules.</div>'}</div></details>`}).join('');const locals=(local.rules||[]).filter(r=>!q||[r.ruleId,r.title,r.kind,r.status].join(' ').toLowerCase().includes(q));root.innerHTML=`<details class=rule-tree-pack open><summary><span class=rule-tree-icon>S</span><span class=rule-tree-title>System Rules</span><span class=rule-tree-folder-meta>${fmt(system.ruleCount||0)}</span></summary><div>${packs||'<div class=rule-empty-note>No matching System Rules.</div>'}</div></details><div class=rule-tree-divider></div><details class=rule-tree-pack open><summary><span class=rule-tree-icon>M</span><span class=rule-tree-title>My Rules</span><span class=rule-tree-folder-meta>${fmt(local.ruleCount||0)}</span></summary><div><button class="rule-tree-row rule-tree-new" id="ruleTreeNew"><span class=rule-tree-icon>+</span><span class=rule-tree-title>New Rule</span><span class=rule-tree-meta>local</span></button>${locals.map(r=>`<button class="rule-tree-row ${r.error?'invalid':''} ${currentRuleLibrarySelection?.kind==='local'&&currentRuleLibrarySelection?.key===r.ruleId?'active':''}" data-local-rule="${esc(r.ruleId)}"><span class=rule-tree-icon>r</span><span class=rule-tree-title title="${esc(r.error||r.title||r.ruleId)}">${esc(r.ruleId)}</span><span class=rule-tree-meta>${r.error?'INVALID':`r${fmt(r.revision||0)}`}</span></button>`).join('')||'<div class=rule-empty-note>No local rules yet.</div>'}</div></details>`;root.querySelectorAll('[data-system-rule]').forEach(x=>x.addEventListener('click',()=>selectSystemRule(x.dataset.systemPack,x.dataset.systemRule)));root.querySelectorAll('[data-local-rule]').forEach(x=>x.addEventListener('click',()=>selectLocalRule(x.dataset.localRule)));$('ruleTreeNew')?.addEventListener('click',newLocalRule);$('ruleLibraryCount').textContent=`${fmt(system.ruleCount||0)} system · ${fmt(local.ruleCount||0)} local`;$('ruleLocalHome').textContent=local.root||'~/.omega/deltascope/rules/v1'}
function renderRuleCatalogCards(){if(!$('ruleCatalogCards'))return;const s=currentRuleCatalog?.srl||{},parity=currentRuleCatalog?.migrationParity||{},w=currentRuleWorkspace||{},system=w.system||{},local=w.local||{};$('ruleCatalogCards').innerHTML=card('System rules',system.ruleCount||0,{},'Repository Definition rules')+card('My Rules',local.ruleCount||0,{},'Versioned local authoring')+card('Published active rules',s.activeRuleCount||0,{},'Frozen in selected Evidence snapshot')+card('Parity mismatches',(parity.primitiveMismatchCount||0)+(parity.compoundMismatchCount||0))+textCard('Rule engine','Stigma-1','SRL Core · shared compiler/evaluator')}
async function loadRuleWorkspace(refresh=false){if(currentRuleWorkspace&&!refresh)return currentRuleWorkspace;const w=await api('/api/workbench/rule-workspace');currentRuleWorkspace=w;currentRuleLibrary=w.system||{};renderRuleTree();renderRuleCatalogCards();return w}
function showRuleProvenance(kind,key){const panel=$('ruleProvenancePanel');if(!panel||!currentRuleCatalog)return;if(kind==='rule'){const r=(currentRuleCatalog.rules||[]).find(x=>x.ruleId===key);if(!r)return;panel.innerHTML=`<div class=case-projection-head><div><h2>${esc(r.ruleId||'Rule')}</h2><div class="muted small">${esc(r.kind||'')} · ${esc(r.status||'')} · ${esc(r.ruleRevision||'')}</div></div><span class="badge ro">ACTIVE · READ ONLY</span></div><div class=research-grid><div class=research-box><h4>Compiled semantics</h4>${evidence({requires:r.requires||[],selectors:r.selectors||[],condition:r.condition||{},emit:r.emit||{}})}</div><div class=research-box><h4>Source & review</h4>${evidence({packId:r.packId,sourcePath:r.sourcePath,sourceSha256:r.sourceSha256,license:r.license,provenance:r.provenance,review:r.review})}</div></div>`}else{const p=(currentRuleCatalog.packs||[]).find(x=>x.packId===key);if(!p)return;panel.innerHTML=`<div class=case-projection-head><div><h2>${esc(p.title||p.packId||'Definition Pack')}</h2><div class="muted small">${esc(p.packId||'')} · ${esc(p.packRevision||'')} · ${esc(p.trustTier||'')}</div></div><span class="badge ro">FROZEN · READ ONLY</span></div><div class=research-grid><div class=research-box><h4>Review & fixtures</h4>${evidence({review:p.review,fixtures:p.fixtures})}</div><div class=research-box><h4>Rules</h4>${evidence((p.rules||[]).map(r=>({ruleId:r.ruleId,active:r.active,ruleRevision:r.ruleRevision,sourcePath:r.sourcePath})))}</div></div>`}}
function renderRuleCatalog(c){currentRuleCatalog=c;const d=c?.definitions||{};$('rulePackCount').textContent=`${c.packs?.length||0} frozen pack(s)`;$('activeRuleCount').textContent=`${c.rules?.length||0} active rule(s)`;$('rulePackRows').innerHTML=(c.packs||[]).map(p=>`<tr class=click data-rule-pack="${esc(p.packId||'')}"><td><b>${esc(p.title||p.packId||'')}</b><div class="muted small">${esc(p.packRevision||'')}</div></td><td>${esc(p.trustTier||'')}</td><td>${esc(ruleReviewLabel(p))}</td><td>${fmt(p.fixturesPassed||0)}/${fmt(p.fixtureCount||0)}</td></tr>`).join('')||'<tr><td colspan=4 class=workspace-empty>No frozen rule provenance is published in this Evidence-v2 snapshot.</td></tr>';$('activeRuleRows').innerHTML=(c.rules||[]).map(r=>`<tr class=click data-active-rule="${esc(r.ruleId||'')}"><td><b>${esc(r.ruleId||'')}</b><div class="muted small">${esc(r.packId||'')}</div></td><td>${esc(r.kind||'')}</td><td>${esc(ruleOutputLabel(r))}</td><td>${esc(r.ruleRevision||'')}</td></tr>`).join('')||'<tr><td colspan=4 class=workspace-empty>No active SRL rules are published in this snapshot.</td></tr>';$('rulePackRows').querySelectorAll('[data-rule-pack]').forEach(x=>x.addEventListener('click',()=>showRuleProvenance('pack',x.dataset.rulePack)));$('activeRuleRows').querySelectorAll('[data-active-rule]').forEach(x=>x.addEventListener('click',()=>showRuleProvenance('rule',x.dataset.activeRule)));const pill=$('definitionsPill');if(pill&&d.definitionsRevision)pill.innerHTML=`<b>Defs</b> ${esc(d.definitionsRevision)}`;renderRuleTree();renderRuleCatalogCards()}
async function loadRuleCatalog(){try{await Promise.all([loadRuleWorkspace(false),currentRuleCatalog?Promise.resolve(currentRuleCatalog):api('/api/workbench/rules').then(renderRuleCatalog)]);renderRuleTree();renderRuleCatalogCards();if(!currentWorkspaceRule){const p=(currentRuleLibrary?.packs||[])[0],r=p?.rules?.[0];if(r)await selectSystemRule(p.packId,r.ruleId)}}catch(e){$('ruleTree').innerHTML=`<div class=rule-library-error><b>Could not load Stigma-1 rule workspace</b><div>${esc(e.message)}</div></div>`}}

function visualEditable(){return !!currentWorkspaceRule?.editable}
function visualNodeById(id){return (currentVisualGraph?.nodes||[]).find(n=>n.id===id)}
function visualNodeSummary(n){const c=n?.config||{};if(n?.type==='collection-selector'){const s=c.selector||{},w=s.where||{};return `${s.collection||'collection'}\n${Object.keys(w).slice(0,3).join(', ')||'no predicates'}`}if(n?.type==='fact-selector'){const f=c.selector?.facts||{};return `${Object.keys(f)[0]||'any'} · ${(Object.values(f)[0]||[]).join(', ')}`}if(n?.type==='logic'){return c.operator==='count'?`COUNT ${c.thresholdOperator||'gte'} ${c.thresholdValue??1}`:`${String(c.operator||'logic').toUpperCase()} inputs`}if(n?.type==='emit'){const e=c.emit||{};return e.findingId?`finding\n${e.findingId}`:`fact\n${e.fact||'output'}`}return n?.type||'node'}
function renderVisualEdges(){const svg=$('ruleVisualSvg');if(!svg||!currentVisualGraph)return;const nodes=new Map((currentVisualGraph.nodes||[]).map(n=>[n.id,n]));svg.innerHTML=(currentVisualGraph.edges||[]).map((e,i)=>{const a=nodes.get(e.from),b=nodes.get(e.to);if(!a||!b)return'';const ap=a.position||{},bp=b.position||{},x1=Number(ap.x||0)+190,y1=Number(ap.y||0)+42,x2=Number(bp.x||0),y2=Number(bp.y||0)+42,dx=Math.max(45,(x2-x1)/2);return `<path class="${visualConnectSource===e.from?'active':''}" d="M ${x1} ${y1} C ${x1+dx} ${y1}, ${x2-dx} ${y2}, ${x2} ${y2}" data-edge="${i}"/>`}).join('')}
function renderVisualGraph(){const holder=$('ruleVisualNodes'),empty=$('ruleVisualEmpty');if(!holder)return;if(!currentVisualGraph){holder.innerHTML='';if(empty)empty.style.display='grid';$('ruleVisualProperties').innerHTML='<div class=workspace-empty>Select or create a rule, then open Visual.</div>';return}if(empty)empty.style.display=(currentVisualGraph.nodes||[]).length?'none':'grid';holder.innerHTML=(currentVisualGraph.nodes||[]).map(n=>{const p=n.position||{x:30,y:30};return `<div class="visual-node ${selectedVisualNode===n.id?'selected':''} ${visualConnectSource===n.id?'connect-source':''}" data-visual-node="${esc(n.id)}" style="left:${Number(p.x||0)}px;top:${Number(p.y||0)}px"><div class=visual-node-head><span class=visual-node-title>${esc(n.label||n.id)}</span><span class=visual-port>→</span></div><div class=visual-node-body><span class=visual-node-type>${esc(String(n.type||'').toUpperCase())}</span>\n${esc(visualNodeSummary(n))}</div></div>`}).join('');holder.querySelectorAll('[data-visual-node]').forEach(el=>{el.addEventListener('click',e=>{e.stopPropagation();const id=el.dataset.visualNode;if(visualConnectMode){visualHandleConnect(id);return}selectedVisualNode=id;renderVisualGraph();renderVisualProperties()});const head=el.querySelector('.visual-node-head');head?.addEventListener('mousedown',e=>{if(e.button!==0)return;const node=visualNodeById(el.dataset.visualNode);if(!node)return;e.preventDefault();const startX=e.clientX,startY=e.clientY,p=node.position||(node.position={x:20,y:20}),ox=Number(p.x||0),oy=Number(p.y||0);const move=ev=>{p.x=Math.max(0,ox+ev.clientX-startX);p.y=Math.max(0,oy+ev.clientY-startY);el.style.left=p.x+'px';el.style.top=p.y+'px';renderVisualEdges()};const up=()=>{document.removeEventListener('mousemove',move);document.removeEventListener('mouseup',up)};document.addEventListener('mousemove',move);document.addEventListener('mouseup',up)})});renderVisualEdges();renderVisualProperties();$('ruleVisualDelete').disabled=!visualEditable()||!selectedVisualNode}
async function loadVisualGraphFromYaml(){if(!$('ruleYaml')?.value.trim()){currentVisualGraph=null;renderVisualGraph();return}try{$('ruleVisualStatus').textContent='Parsing YAML through SRL Core…';const r=await api('/api/rule-lab/graph',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:$('ruleYaml').value})});if(!r.ok){currentVisualGraph=null;$('ruleVisualStatus').textContent='YAML is not graphable';$('ruleVisualProperties').innerHTML=ruleDiagnostics(r.diagnostics);renderVisualGraph();return}currentVisualGraph=r.graph;selectedVisualNode=null;visualConnectMode=false;visualConnectSource=null;$('ruleVisualStatus').textContent=`${(currentVisualGraph.nodes||[]).length} nodes · SRL Core`;renderVisualGraph()}catch(e){currentVisualGraph=null;$('ruleVisualStatus').textContent='Visual parse failed';$('ruleVisualProperties').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`;renderVisualGraph()}}
function visualUniqueId(prefix){const existing=new Set((currentVisualGraph?.nodes||[]).map(n=>n.id));let i=1,id='';do{id=`${prefix}:${i++}`}while(existing.has(id));return id}
function visualAddFromPalette(kind,x=80,y=80){if(!visualEditable()){toniSay('System Rules are read-only. Fork the rule to My Rules before changing its graph.');return}if(!currentVisualGraph){toniSay('Open a valid SRL rule in Visual first.');return}if(kind==='emit'&&(currentVisualGraph.nodes||[]).some(n=>n.type==='emit')){selectedVisualNode=(currentVisualGraph.nodes||[]).find(n=>n.type==='emit')?.id||null;renderVisualGraph();return}let n=null;if(kind==='collection-selector'){const typed=ruleLabReference?.editor?.typedCollections||{},collection=typed.staticPatternMatches?'staticPatternMatches':Object.keys(typed)[0]||'staticPatternMatches',field=Object.keys(typed[collection]||{})[0]||'pattern';const id=visualUniqueId('selector');n={id,type:'collection-selector',label:`selector${(currentVisualGraph.nodes||[]).filter(x=>x.type?.includes('selector')).length+1}`,config:{name:`selector${(currentVisualGraph.nodes||[]).filter(x=>x.type?.includes('selector')).length+1}`,selector:{collection,where:{[field]:{exists:true}}}},position:{x,y}}}else if(kind==='fact-selector'){const id=visualUniqueId('selector');n={id,type:'fact-selector',label:`facts${(currentVisualGraph.nodes||[]).filter(x=>x.type?.includes('selector')).length+1}`,config:{name:`facts${(currentVisualGraph.nodes||[]).filter(x=>x.type?.includes('selector')).length+1}`,selector:{facts:{any:['example.fact']}}},position:{x,y}}}else if(['all','any','not','count'].includes(kind)){const id=visualUniqueId('logic');n={id,type:'logic',label:kind.toUpperCase(),config:{operator:kind,...(kind==='count'?{thresholdOperator:'gte',thresholdValue:1}:{})},position:{x,y}}}else if(kind==='emit'){const id='emit:result',ruleKind=currentVisualGraph.metadata?.kind||'observation';n={id,type:'emit',label:'EMIT',config:{emit:ruleKind==='correlation'?{findingId:`${currentVisualGraph.metadata?.id||'local.rule'}.finding`,title:'New finding',description:'Describe the relationship.',severity:'caution',category:'experimental'}:{fact:`${currentVisualGraph.metadata?.id||'local.rule'}.fact`,confidence:'medium',title:'New observation'}},position:{x,y}}}if(!n)return;currentVisualGraph.nodes.push(n);selectedVisualNode=n.id;markRuleWorkspaceDirty(true);renderVisualGraph();$('ruleVisualStatus').textContent='Graph changed · connect nodes, then apply to YAML'}
function visualHandleConnect(id){if(!visualEditable())return;if(!visualConnectSource){visualConnectSource=id;$('ruleVisualStatus').textContent=`Connect from ${id} → choose target`;renderVisualGraph();return}if(visualConnectSource===id){visualConnectSource=null;$('ruleVisualStatus').textContent='Connect cancelled';renderVisualGraph();return}const incoming=(currentVisualGraph.edges||[]).filter(e=>e.to===id).length;if(!(currentVisualGraph.edges||[]).some(e=>e.from===visualConnectSource&&e.to===id))currentVisualGraph.edges.push({from:visualConnectSource,to:id,order:incoming});visualConnectSource=null;visualConnectMode=false;$('ruleVisualConnect').textContent='Connect';markRuleWorkspaceDirty(true);renderVisualGraph();$('ruleVisualStatus').textContent='Edge added · apply graph to YAML when ready'}
function parseVisualOperand(op,value){if(op==='exists'||op==='missing')return true;if(op==='in'||op==='in-ci')return String(value||'').split(',').map(x=>x.trim()).filter(Boolean);if(['gt','gte','lt','lte'].includes(op)){const n=Number(value);return Number.isFinite(n)?n:value}if(op==='equals'&&/^-?\d+(?:\.\d+)?$/.test(String(value||'').trim()))return Number(value);return value}
function renderVisualProperties(){const box=$('ruleVisualProperties'),n=visualNodeById(selectedVisualNode);if(!box)return;if(!n){box.innerHTML='<div class=workspace-empty>Select a node to edit its SRL properties.</div>';return}const ro=visualEditable()?'':'disabled',meta=currentVisualGraph?.metadata||{},typed=ruleLabReference?.editor?.typedCollections||{};let body=`<div class=rule-intel-title>Rule metadata</div><div class=visual-properties-grid><label>Rule ID</label><input id=visualMetaId value="${esc(meta.id||'')}" ${ro}><label>Kind</label><select id=visualMetaKind ${ro}><option ${meta.kind==='observation'?'selected':''}>observation</option><option ${meta.kind==='classification'?'selected':''}>classification</option><option ${meta.kind==='correlation'?'selected':''}>correlation</option></select><label>Status</label><select id=visualMetaStatus ${ro}>${['experimental','reviewed','deprecated','disabled'].map(x=>`<option ${meta.status===x?'selected':''}>${x}</option>`).join('')}</select></div><div class=rule-intel-title style="margin-top:10px">Selected node · ${esc(n.type)}</div>`;if(n.type==='collection-selector'){const c=n.config||{},sel=c.selector||{},collection=sel.collection||Object.keys(typed)[0]||'',fields=typed[collection]||{},preds=Object.entries(sel.where||{});body+=`<div class=visual-properties-grid><label>Selector name</label><input id=visualSelectorName value="${esc(c.name||n.label||'')}" ${ro}><label>Collection</label><select id=visualCollection ${ro}>${Object.keys(typed).map(x=>`<option ${x===collection?'selected':''}>${esc(x)}</option>`).join('')}</select></div><div id=visualPredicates>${preds.map(([field,p],i)=>{const op=Object.keys(p||{})[0]||'equals',value=(p||{})[op],shown=Array.isArray(value)?value.join(', '):String(value??'');return `<div class=visual-predicate-row data-predicate="${i}"><select data-p-field ${ro}>${Object.keys(fields).map(x=>`<option ${x===field?'selected':''}>${esc(x)}</option>`).join('')}</select><select data-p-op ${ro}>${(ruleLabReference?.engine?.operators||[]).map(x=>`<option ${x===op?'selected':''}>${esc(x)}</option>`).join('')}</select><input data-p-value value="${esc(shown)}" ${ro}><button data-p-remove ${ro}>×</button></div>`}).join('')}</div><div class=visual-property-actions><button id=visualAddPredicate ${ro}>+ Predicate</button></div>`}else if(n.type==='fact-selector'){const c=n.config||{},f=c.selector?.facts||{},mode=Object.keys(f)[0]||'any',facts=Object.values(f)[0]||[];body+=`<div class=visual-properties-grid><label>Selector name</label><input id=visualSelectorName value="${esc(c.name||n.label||'')}" ${ro}><label>Mode</label><select id=visualFactMode ${ro}><option ${mode==='any'?'selected':''}>any</option><option ${mode==='all'?'selected':''}>all</option></select><label>Facts</label><input id=visualFacts value="${esc(facts.join(', '))}" ${ro}></div>`}else if(n.type==='logic'){const c=n.config||{};body+=`<div class=visual-properties-grid><label>Operator</label><select id=visualLogicOp ${ro}>${['all','any','not','count'].map(x=>`<option ${c.operator===x?'selected':''}>${x}</option>`).join('')}</select><label>Count threshold</label><div style="display:flex;gap:5px"><select id=visualThresholdOp ${ro}>${['gt','gte','lt','lte','equals'].map(x=>`<option ${c.thresholdOperator===x?'selected':''}>${x}</option>`).join('')}</select><input id=visualThresholdValue type=number min=0 value="${Number(c.thresholdValue??1)}" ${ro}></div></div>`}else if(n.type==='emit'){const e=n.config?.emit||{},kind=meta.kind||'observation',ar=n.config?.analysisRequest||{},profiles=ruleLabReference?.engine?.deepScanProfiles||{};if(kind==='correlation')body+=`<div class=visual-properties-grid><label>Finding ID</label><input id=visualEmitId value="${esc(e.findingId||'')}" ${ro}><label>Title</label><input id=visualEmitTitle value="${esc(e.title||'')}" ${ro}><label>Description</label><textarea id=visualEmitDescription ${ro}>${esc(e.description||'')}</textarea><label>Severity</label><input id=visualEmitSeverity value="${esc(e.severity||'caution')}" ${ro}><label>Category</label><input id=visualEmitCategory value="${esc(e.category||'experimental')}" ${ro}></div>`;else body+=`<div class=visual-properties-grid><label>Fact ID</label><input id=visualEmitId value="${esc(e.fact||'')}" ${ro}><label>Title</label><input id=visualEmitTitle value="${esc(e.title||'')}" ${ro}><label>Description</label><textarea id=visualEmitDescription ${ro}>${esc(e.description||'')}</textarea><label>Confidence</label><input id=visualEmitConfidence value="${esc(e.confidence||'medium')}" ${ro}><label>Category</label><input id=visualEmitCategory value="${esc(e.category||'')}" ${ro}></div>`;body+=`<div class=rule-intel-title style="margin-top:10px">Deep analysis outcome</div><div class=muted small style="margin-bottom:7px">A frozen production rule may request an approved SigmaScope deep-scan profile. Local rules only preview the queue request.</div><div class=visual-properties-grid><label>Profile</label><select id=visualDeepProfile ${ro}><option value="">None</option>${Object.entries(profiles).map(([name,p])=>`<option value="${esc(name)}" ${ar.profile===name?'selected':''}>${esc(name)}${p.available===false?' · unavailable':''}</option>`).join('')}</select><label>Scan depth</label><select id=visualDeepDepth ${ro}>${['standard','extended','exhaustive'].map(x=>`<option value="${x}" ${(ar.depth||'standard')===x?'selected':''}>${x}</option>`).join('')}</select><label>Compare with</label><select id=visualDeepCompare ${ro}><option value="stable-artifact-baseline" ${(!ar.compareWith||ar.compareWith==='stable-artifact-baseline')?'selected':''}>stable-artifact-baseline</option></select><label>Reason</label><input id=visualDeepReason value="${esc(ar.reason||'')}" placeholder="Why deeper evidence is required" ${ro}></div>`}body+=`<div class=visual-property-actions><button id=visualApplyProperties ${ro}>Apply node properties</button><span class="muted small">Graph semantics are recompiled by Stigma-1 before YAML is accepted.</span></div>`;box.innerHTML=body;$('visualApplyProperties')?.addEventListener('click',applyVisualProperties);$('visualAddPredicate')?.addEventListener('click',()=>{const col=$('visualCollection')?.value||Object.keys(typed)[0]||'',sel=n.config.selector||(n.config.selector={collection:col,where:{}});sel.where=sel.where||{};const field=Object.keys(typed[col]||{}).find(x=>!(x in sel.where));if(!field){$('ruleVisualStatus').textContent='All typed fields for this collection already have predicates';return}sel.where[field]={exists:true};renderVisualProperties();markRuleWorkspaceDirty(true)});box.querySelectorAll('[data-p-remove]').forEach(btn=>btn.addEventListener('click',()=>{const row=btn.closest('[data-predicate]'),idx=Number(row.dataset.predicate),keys=Object.keys(n.config?.selector?.where||{}),key=keys[idx];if(key)delete n.config.selector.where[key];renderVisualProperties();markRuleWorkspaceDirty(true)}));$('visualCollection')?.addEventListener('change',()=>{const sel=n.config.selector||(n.config.selector={where:{}});sel.collection=$('visualCollection').value;sel.where={};const field=Object.keys(typed[sel.collection]||{})[0];if(field)sel.where[field]={exists:true};renderVisualProperties();markRuleWorkspaceDirty(true)})}
function applyVisualProperties(){if(!visualEditable()||!currentVisualGraph)return;const n=visualNodeById(selectedVisualNode);if(!n)return;currentVisualGraph.metadata.id=$('visualMetaId')?.value.trim()||currentVisualGraph.metadata.id;currentVisualGraph.metadata.kind=$('visualMetaKind')?.value||currentVisualGraph.metadata.kind;currentVisualGraph.metadata.status=$('visualMetaStatus')?.value||currentVisualGraph.metadata.status;if(n.type==='collection-selector'){const name=$('visualSelectorName').value.trim(),collection=$('visualCollection').value,where={};$('visualPredicates').querySelectorAll('[data-predicate]').forEach(row=>{const field=row.querySelector('[data-p-field]').value,op=row.querySelector('[data-p-op]').value,val=row.querySelector('[data-p-value]').value;where[field]={[op]:parseVisualOperand(op,val)}});n.label=name;n.config={name,selector:{collection,where}}}else if(n.type==='fact-selector'){const name=$('visualSelectorName').value.trim(),mode=$('visualFactMode').value,facts=$('visualFacts').value.split(',').map(x=>x.trim()).filter(Boolean);n.label=name;n.config={name,selector:{facts:{[mode]:facts}}}}else if(n.type==='logic'){n.config.operator=$('visualLogicOp').value;n.label=n.config.operator.toUpperCase();if(n.config.operator==='count'){n.config.thresholdOperator=$('visualThresholdOp').value;n.config.thresholdValue=Math.max(0,Number($('visualThresholdValue').value||0))}}else if(n.type==='emit'){const kind=currentVisualGraph.metadata.kind,e={};if(kind==='correlation')e.findingId=$('visualEmitId').value.trim();else e.fact=$('visualEmitId').value.trim();e.title=$('visualEmitTitle').value.trim();const desc=$('visualEmitDescription').value.trim();if(desc)e.description=desc;if(kind==='correlation'){e.severity=$('visualEmitSeverity').value.trim();e.category=$('visualEmitCategory').value.trim()}else{const conf=$('visualEmitConfidence').value.trim(),cat=$('visualEmitCategory').value.trim();if(conf)e.confidence=conf;if(cat)e.category=cat}n.config.emit=e;const profile=$('visualDeepProfile')?.value||'';if(profile){n.config.analysisRequest={profile,depth:$('visualDeepDepth')?.value||'standard',compareWith:$('visualDeepCompare')?.value||'stable-artifact-baseline',reason:$('visualDeepReason')?.value.trim()||'deeper-evidence-required'}}else delete n.config.analysisRequest}markRuleWorkspaceDirty(true);renderVisualGraph();visualApplyToYaml(true)}
async function visualApplyToYaml(silent=false){if(!visualEditable()||!currentVisualGraph)return;try{$('ruleVisualStatus').textContent='Compiling visual graph through Stigma-1…';const r=await api('/api/rule-lab/graph-yaml',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({graph:currentVisualGraph})});if(!r.ok){$('ruleVisualStatus').textContent='Graph incomplete / invalid';if(!silent)$('ruleVisualProperties').insertAdjacentHTML('beforeend',ruleDiagnostics(r.diagnostics));return}setRuleEditorValue(r.yaml||'',true);currentWorkspaceRule.ruleId=currentVisualGraph.metadata?.id||currentWorkspaceRule.ruleId;currentWorkspaceRule.kind=currentVisualGraph.metadata?.kind||currentWorkspaceRule.kind;currentWorkspaceRule.status=currentVisualGraph.metadata?.status||currentWorkspaceRule.status;markRuleWorkspaceDirty(true);updateRuleWorkspaceHeader();$('ruleVisualStatus').textContent='Graph → YAML valid · unsaved local change';if(!silent)ruleCompileCandidate()}catch(e){$('ruleVisualStatus').textContent='Graph compile failed';if(!silent)alert(e.message)}}
function visualDeleteSelected(){if(!visualEditable()||!selectedVisualNode||!currentVisualGraph)return;currentVisualGraph.nodes=currentVisualGraph.nodes.filter(n=>n.id!==selectedVisualNode);currentVisualGraph.edges=(currentVisualGraph.edges||[]).filter(e=>e.from!==selectedVisualNode&&e.to!==selectedVisualNode);selectedVisualNode=null;markRuleWorkspaceDirty(true);renderVisualGraph();$('ruleVisualStatus').textContent='Node deleted · graph may be incomplete'}
function wireUnifiedRuleWorkspace(){document.querySelectorAll('[data-rule-workspace-tab]').forEach(x=>x.addEventListener('click',()=>ruleWorkspaceSetTab(x.dataset.ruleWorkspaceTab)));$('ruleNewLocal').addEventListener('click',newLocalRule);$('ruleForkLocal').addEventListener('click',forkCurrentRule);$('ruleSaveLocal').addEventListener('click',saveCurrentLocalRule);$('ruleVisualConnect').addEventListener('click',()=>{if(!visualEditable())return;visualConnectMode=!visualConnectMode;visualConnectSource=null;$('ruleVisualConnect').textContent=visualConnectMode?'Cancel connect':'Connect';$('ruleVisualStatus').textContent=visualConnectMode?'Choose source node, then target node':'Connect mode off';renderVisualGraph()});$('ruleVisualDelete').addEventListener('click',visualDeleteSelected);$('ruleVisualToYaml').addEventListener('click',()=>visualApplyToYaml(false));document.querySelectorAll('[data-visual-add]').forEach(x=>x.addEventListener('dragstart',e=>{e.dataTransfer.setData('text/x-srl-node',x.dataset.visualAdd);e.dataTransfer.effectAllowed='copy'}));const canvas=$('ruleVisualCanvas');canvas.addEventListener('dragover',e=>{if(visualEditable()){e.preventDefault();e.dataTransfer.dropEffect='copy'}});canvas.addEventListener('drop',e=>{if(!visualEditable())return;e.preventDefault();const kind=e.dataTransfer.getData('text/x-srl-node');if(!kind)return;const rect=canvas.getBoundingClientRect();visualAddFromPalette(kind,e.clientX-rect.left+canvas.scrollLeft-90,e.clientY-rect.top+canvas.scrollTop-30)});canvas.addEventListener('click',()=>{if(visualConnectMode&&visualConnectSource){visualConnectSource=null;renderVisualGraph()}else{selectedVisualNode=null;renderVisualGraph()}})}

function reportMetricLabel(value){return String(value||'').replace(/([a-z0-9])([A-Z])/g,'$1 $2').replace(/[_-]+/g,' ').replace(/^./,x=>x.toUpperCase())}
function reportStatusClass(value){const status=String(value||'').toLowerCase();return status==='ok'||status==='active'?'pass':status==='attention'||status==='gated'?'warn':status==='fail'?'fail':''}
function renderReports(r){currentReports=r;const reports=Array.isArray(r?.reports)?r.reports:[],attention=reports.filter(x=>['attention','fail'].includes(String(x?.status||'').toLowerCase())).length,gated=reports.filter(x=>String(x?.status||'').toLowerCase()==='gated').length;$('reportCards').innerHTML=card('Report groups',reports.length)+card('Needs attention',attention)+card('Gated',gated)+textCard('Evidence',String(r?.evidenceRevision||'—').slice(0,22));$('reportRevision').textContent=r?.projectionRevision?`projection ${String(r.projectionRevision).slice(0,22)}`:'';$('reportRows').innerHTML=reports.map(rep=>{const metrics=rep?.metrics&&typeof rep.metrics==='object'?Object.entries(rep.metrics):[],status=String(rep?.status||'unknown').toUpperCase(),provenance=[rep?.ruleSetRevision?`rule set ${rep.ruleSetRevision}`:'',rep?.projectionSetRevision?`projection set ${rep.projectionSetRevision}`:'',Object.prototype.hasOwnProperty.call(rep||{},'productionWriteBack')?`production write-back ${rep.productionWriteBack?'enabled':'disabled'}`:''].filter(Boolean).join(' · ');return `<section class=report-block><div class=report-block-head><div><b>${esc(rep?.title||rep?.reportId||'Report')}</b><div class="muted small">${esc(rep?.reportId||'derived report')}</div></div><span class="pill ${reportStatusClass(rep?.status)}">${esc(status)}</span></div><div class=report-metrics>${metrics.map(([key,value])=>`<div class=report-metric><div class=n>${esc(typeof value==='number'?fmt(value):String(value??'—'))}</div><div class="muted small">${esc(reportMetricLabel(key))}</div></div>`).join('')}</div>${provenance?`<div class=report-provenance>${esc(provenance)}</div>`:''}</section>`}).join('')||'<div class=workspace-empty>No operational reports are available for this evidence snapshot.</div>'}

async function loadReports(){if(currentReports)return;try{renderReports(await api('/api/workbench/reports'))}catch(e){$('reportRows').innerHTML=`<div class=research-error>${esc(e.message)}</div>`}}
function renderDashboardGate(s){const host=$('dashboardGate');if(!host)return;const checks=Array.isArray(s?.checks)?s.checks:[],blockers=checks.filter(c=>['gated','fail'].includes(String(c?.status||'').toLowerCase()));if(!blockers.length){host.innerHTML='';return}const failed=blockers.some(c=>String(c?.status||'').toLowerCase()==='fail');host.innerHTML=`<section class="dashboard-gate-shell ${failed?'fail':''}"><div class=dashboard-gate-head><div><div class=dashboard-gate-kicker>${failed?'Production safety check failed':'Production safety gate active'}</div><div class=dashboard-gate-title>${failed?'A production boundary needs attention':'A production capability is intentionally gated'}</div><div class="muted small">This is an intentional authority state, not a scanner failure. DeltaScope surfaces it here because it changes what production evaluation is allowed to do.</div></div><button data-open-system-health>Open System health</button></div><div class=dashboard-gate-items>${blockers.map(c=>`<div><span class="pill ${String(c.status).toLowerCase()==='fail'?'fail':'warn'}">${esc(String(c.status||'').toUpperCase())}</span> <b>${esc(c.label||c.code||'Gate')}</b><div class="muted small">${esc(c.detail||'')}</div></div>`).join('')}</div></section>`;host.querySelector('[data-open-system-health]')?.addEventListener('click',()=>setWorkbenchView('system'))}

function renderSystemStatus(s){currentSystemStatus=s;renderDashboardGate(s);const rev=s?.revisions||{},checks=s?.checks||[],by=code=>checks.find(x=>x.code===code)||{},ev=by('evidence.root'),defs=by('definitions.provenance'),srl=by('srl.production');const healthCard=(label,state,detail)=>`<div class="card system-health-card"><div class="system-health-state ${esc(state||'warn')}">${esc(detail||'UNKNOWN')}</div><div class=muted>${esc(label)}</div></div>`;$('systemCards').innerHTML=healthCard('Evidence',ev.status,ev.status==='pass'?'Current / valid':String(ev.status||'unknown').toUpperCase())+healthCard('Definitions',defs.status,defs.status==='pass'?'Provenance verified':String(defs.status||'unknown').toUpperCase())+healthCard('SigmaScope',ev.status,s?.engine?.version?`Healthy · ${s.engine.version}`:'Evidence pipeline available')+healthCard('Stigma-1',srl.status,srl.status==='active'?'Production evaluation active':'Production evaluation gated');$('systemChecks').innerHTML=checks.map(c=>`<div class="auditrow ${c.status==='pass'||c.status==='active'?'pass':c.status==='fail'?'fail':c.status==='gated'||c.status==='warn'?'warn':''}"><b>${esc(c.label||c.code||'Check')}</b> <span class=pill>${esc(String(c.status||'').toUpperCase())}</span><div class="muted small">${esc(c.detail||'')}</div></div>`).join('')||'<div class=workspace-empty>No system checks available.</div>';$('systemRevisions').innerHTML=`<div class=explain-card><b>Why these IDs exist</b><span class=plain-language>They pin the exact Evidence, Definitions and rule projections used for reproducibility. You normally only need them when comparing or auditing published state.</span> <button class=context-help data-help-topic=revision>?</button></div><div class=kv>${Object.entries(rev).map(([k,v])=>`<b>${esc(k)}</b><span>${esc(v||'—')}</span>`).join('')}</div>`;wireContextHelp($('workbench-system'));syncSystemNotifications(s);renderDashboardPlatformOverview()}
async function loadSystemStatus(){if(currentSystemStatus)return;try{renderSystemStatus(await api('/api/workbench/system'))}catch(e){$('systemChecks').innerHTML=`<div class=research-error>${esc(e.message)}</div>`}}
function openWorkbenchAsset(id){setWorkbenchView('assets');loadDetail(Number(id))}
function timelineKind(e){const t=String(e?.eventType||'');if(t==='observation')return'observation';if(t.includes('advisory'))return'intelligence';if(t.includes('reprojection')||t.includes('reanalysis'))return'reprojection';if(t.includes('finding'))return'finding';return''}
function workbenchCaseHtml(c){const a=c?.asset||{},inc=c?.incident||{},findings=Array.isArray(c?.contributingFindings)?c.contributingFindings:[],tl=Array.isArray(c?.timeline?.events)?c.timeline.events:[],rp=c?.ruleProjection||{},truncated=!!c?.timeline?.observationEventsTruncated;const reasons=(inc?.reasons||[]).map(r=>`<span class=pill>${esc(r.label||r.code||'')}</span>`).join('');const findHtml=findings.length?`<table><thead><tr><th>Severity</th><th>Finding</th><th>Rule</th></tr></thead><tbody>${findings.map(f=>`<tr><td class="${sev(f.severity)}">${esc(f.severity||'none')}</td><td><b>${esc(f.title||f.findingId||'')}</b><div class="muted small">${esc(f.category||'')}</div></td><td>${esc(f.ruleId||'')}</td></tr>`).join('')}</tbody></table>`:'<div class=empty>No contributing current findings.</div>';const timeline=tl.length?`<table><thead><tr><th>Time</th><th>Type</th><th>Event</th><th>Source</th></tr></thead><tbody>${tl.map(e=>`<tr class="timeline-row ${timelineKind(e)}"><td>${esc(e.occurredAtUtc||'—')}<div class="muted small">${esc(e.timeBasis||'')}</div></td><td><span class="incident-badge ${sev(e.severity)}">${esc(e.eventType||'event')}</span>${e.collection?`<div class="muted small">${esc(e.collection)}</div>`:''}</td><td><b>${esc(e.label||'Security event')}</b>${e.relationship?`<div class="muted small">${esc(e.relationship)}</div>`:''}</td><td><span class=timeline-source>${esc(e.source||'evidence')}</span></td></tr>`).join('')}</tbody></table>`:'<div class=empty>No normalized timeline events.</div>';return `<div class=case-projection-head><div><h2>${esc(a.name||a.internalName||'Asset investigation')}</h2><div class="muted small">variant ${esc(a.variantId||'—')} · case projection ${esc(c.caseProjectionId||'')}</div><div class=case-relations>${reasons||'<span class=pill>context-only case</span>'}</div></div><div><span class="badge ro">READ ONLY</span> <button data-open-case-asset="${esc(a.variantId||0)}">Open full asset</button></div></div><div class=cards>${card('Priority',String(inc.priority||'context').toUpperCase())}${card('Findings',findings.length)}${card('Timeline events',tl.length)}${card('SRL projection',rp.projection?'AVAILABLE':rp.reanalysisRequest?'NEEDS DATA':'NONE')}</div><div class=case-projection-grid><section><div class=panelhead><h3>Contributing findings</h3><span class=muted>${findings.length} projection(s)</span></div><div class=case-findings>${findHtml}</div>${(c.contributingSignals||[]).length?`<details><summary>Contributing signals</summary>${evidence(c.contributingSignals)}</details>`:''}${(c.advisories||[]).length?`<details><summary>Advisory intelligence</summary>${evidence(c.advisories)}</details>`:''}${rp.available?`<details><summary>SRL reprojection relationship</summary>${evidence(rp)}</details>`:''}</section><section><div class=panelhead><h3>Normalized security timeline</h3><span class=muted>${truncated?'bounded preview':'complete loaded preview'}</span></div><div class=timeline>${timeline}</div></section></div>`}
function wireWorkbenchCasePanel(panel){panel.querySelectorAll('[data-open-case-asset]').forEach(x=>x.addEventListener('click',()=>openWorkbenchAsset(Number(x.dataset.openCaseAsset))))}
async function loadWorkbenchCase(id,target='incidents'){const panel=$(target==='events'?'eventCasePanel':'incidentCasePanel');if(!panel)return;panel.innerHTML='<div class=workspace-empty>Loading retained evidence and composing the read-only case…</div>';try{const c=await api('/api/workbench/case?variant_id='+encodeURIComponent(id));currentWorkbenchCase=c;panel.innerHTML=workbenchCaseHtml(c);wireWorkbenchCasePanel(panel);panel.scrollIntoView({behavior:'smooth',block:'nearest'});toniSay(`Composed ${c.timeline?.events?.length||0} normalized events for ${c.asset?.name||'the selected asset'}. This case is derived only; GitHub remains the change boundary.`)}catch(e){panel.innerHTML=`<div class=research-error><b>Could not compose workbench case</b><div>${esc(e.message)}</div></div>`}}
function operationStateLabel(x){return String(x?.stateDetail||x?.state||'unknown').replaceAll('_',' ').toUpperCase()}
function renderOperations(o){currentOperations=o;const comp=$('dashboardComponentRows'),ev=$('operationEventRows'),count=$('operationEventCount');if(!o?.available){const msg=esc(o?.error||'GitHub Actions status is unavailable.');if(comp)comp.innerHTML=`<div class="workspace-empty"><b>GitHub status unavailable</b><div class="muted small">${msg}</div></div>`;if(ev)ev.innerHTML=`<tr><td colspan=5 class=workspace-empty>GitHub Actions unavailable: ${msg}</td></tr>`;if(count)count.textContent='unavailable';return}const components=Array.isArray(o.components)?o.components:[];const events=Array.isArray(o.events)?o.events:[];if(comp)comp.innerHTML=components.map(c=>{const r=c.activeRun||c.latestRun||{};return `<div class=component-status-row><div><b>${esc(c.component||c.componentId||'Component')}</b><div class="muted small">${esc(r.workflow||'')}</div></div><span class="component-state ${esc(c.state||'unknown')}">${esc(c.state||'unknown')}</span><div><b>${esc(r.title||'No run title')}</b><div class="muted small">${esc(r.branch||'—')} · #${fmt(r.runNumber||0)} · ${esc(r.createdAtUtc||'')}</div></div></div>`}).join('')||'<div class=workspace-empty>No GitHub workflow status rows returned.</div>';if(count)count.textContent=`${events.length} recent run(s) · ${fmt(o.actionsRunning||0)} running`;if(ev)ev.innerHTML=events.slice(0,40).map(e=>`<tr><td>${esc(e.createdAtUtc||'—')}</td><td><b>${esc(e.component||'')}</b><div class="muted small">${esc(e.workflow||'')}</div></td><td>${e.url?`<a class=operation-link href="${esc(e.url)}" target=_blank rel="noopener noreferrer">${esc(e.title||'Workflow run')}</a>`:esc(e.title||'Workflow run')}<div class="muted small">${esc(e.event||'')} · #${fmt(e.runNumber||0)}</div></td><td><span class="component-state ${esc(e.state||'unknown')}">${esc(operationStateLabel(e))}</span></td><td>${esc(e.branch||'—')}<div class="muted small">${esc(String(e.sha||'').slice(0,10))}</div></td></tr>`).join('')||'<tr><td colspan=5 class=workspace-empty>No recent workflow activity.</td></tr>'}
async function loadOperations(refresh=false){if(currentOperations&&!refresh){renderOperations(currentOperations);return currentOperations}try{const o=await api('/api/operations'+(refresh?'?refresh=1':''));renderOperations(o);return o}catch(e){renderOperations({available:false,error:e.message,components:[],events:[]});return null}}
function renderLatestFindings(p){const rows=Array.isArray(p?.findings)?p.findings:[];$('latestFindingCount').textContent=`${rows.length} newest`;$('latestFindingRows').innerHTML=rows.map(f=>`<tr class=click data-latest-finding-variant="${Number(f.variantId||0)}"><td>${esc(f.occurredAtUtc||'—')}</td><td><b>${esc(f.plugin||f.internalName||'')}</b><div class="muted small">${esc(f.version||'')} · ${esc(f.sourceName||'')}</div></td><td><b>${esc(f.title||f.findingId||'Security finding')}</b><div class="muted small">${esc(f.ruleId||f.findingId||'')}</div></td><td class="${sev(f.severity)}">${esc(f.severity||'none')}</td></tr>`).join('')||'<tr><td colspan=4 class=workspace-empty>No current findings are published.</td></tr>';$('latestFindingRows').querySelectorAll('[data-latest-finding-variant]').forEach(x=>x.addEventListener('click',()=>loadWorkbenchCase(Number(x.dataset.latestFindingVariant),'incidents')));syncCriticalFindingNotifications(p)}

function collectorStateClass(value){const s=String(value||'unknown').toLowerCase();return ['healthy','running','failed','warning','skipped'].includes(s)?s:'unknown'}
function collectorMetricValue(m){const v=m?.value;if(typeof v==='number')return fmt(v)+(m?.unit?` ${esc(m.unit)}`:'');if(typeof v==='boolean')return v?'Yes':'No';return esc(v??'—')+(m?.unit?` ${esc(m.unit)}`:'')}
function collectorList(items){const rows=Array.isArray(items)?items:[];return rows.length?`<ul>${rows.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`:'<div class="muted small">None declared</div>'}
function collectorHistoryTable(c){const rows=Array.isArray(c?.history)?c.history:[];if(!rows.length)return '<div class="workspace-empty">No recent matching runner history is available.</div>';return `<table><thead><tr><th>Run</th><th>Time</th><th>Collector step</th><th>Result</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${r.url?`<a href="${esc(r.url)}" target=_blank rel="noopener noreferrer">#${fmt(r.runNumber||r.runId||0)}</a>`:`#${fmt(r.runNumber||r.runId||0)}`}</td><td>${esc(r.createdAtUtc||'—')}</td><td>${r.stepObserved?'observed':'not found'}<div class="muted small">${esc(r.step||r.job||'')}</div></td><td><span class="collector-state ${collectorStateClass(r.state)}">${esc(String(r.state||'unknown'))}</span></td></tr>`).join('')}</tbody></table>`}
function renderCollectors(payload){
 currentCollectors=payload;const rows=Array.isArray(payload?.collectors)?payload.collectors:[];
 const healthy=rows.filter(x=>x.state==='healthy').length,failed=Number(payload?.failingCount||0),running=Number(payload?.runningCount||0),unknown=Number(payload?.unknownCount||0);
 $('collectorCards').innerHTML=card('Collectors',rows.length,{},'registered acquisition/projection stages')+card('Healthy',healthy,{},'latest matching runner step succeeded')+card('Running',running,{},'currently queued or in progress')+card('Failed',failed,{},'latest matching runner step failed')+card('Unknown / unavailable',unknown,{},'no recent matching runner evidence');
 const host=$('collectorRows');if(!host)return;
 host.innerHTML=rows.map(c=>{
   const metrics=Array.isArray(c.metrics)?c.metrics:[],latest=c.latest||{},rate=c.recentSuccessRate;
   return `<article class=collector-item><div class=collector-item-head><div><div class=collector-title>${esc(c.title||c.id||'Collector')}</div><div class=collector-purpose>${esc(c.purpose||'')}</div></div><span class="collector-state ${collectorStateClass(c.state)}">${esc(String(c.state||'unknown'))}</span></div><div class=collector-body>${c.error?`<div class=collector-error>${esc(c.error)}</div>`:''}<div class=collector-meta><b>Workflow</b><span>${esc(c.workflow||'—')}</span><b>Job</b><span>${esc(c.job||'—')}</span><b>Step</b><span>${esc(c.step||'—')}</span><b>Implementation</b><span>${esc(c.implementation||'—')}</span></div><div class=collector-io><div><h4>Consumes</h4>${collectorList(c.inputs)}</div><div><h4>Produces</h4>${collectorList(c.outputs)}</div></div>${metrics.length?`<div class=collector-metrics>${metrics.map(m=>`<div class=collector-metric><div class=collector-metric-value>${collectorMetricValue(m)}</div><div class=collector-metric-label>${esc(m.label||'Metric')}</div><div class=collector-metric-source>${esc(m.source||'')}</div></div>`).join('')}</div>`:'<div class="muted small">No parsed throughput/coverage metric is available for the latest retained runner history.</div>'}${Array.isArray(latest.artifacts)&&latest.artifacts.length?`<div><h4 style="margin:0 0 6px">Latest workflow artifacts</h4><div class=collector-artifacts>${latest.artifacts.map(a=>`<span class="collector-artifact ${a.expired?'expired':''}">${esc(a.name||'artifact')} · ${a.bytes?esc((Number(a.bytes)/1024).toFixed(1)+' KiB'):''}${a.expired?' · expired':''}</span>`).join('')}</div></div>`:''}<div class=collector-run-summary><span><strong>${fmt(c.recentObservedRuns||0)}</strong> recent observed run(s)</span><span><strong>${fmt(c.recentSuccesses||0)}</strong> succeeded</span><span><strong>${fmt(c.recentFailures||0)}</strong> failed</span><span><strong>${rate===null||rate===undefined?'—':esc(rate+'%')}</strong> success rate</span>${latest.createdAtUtc?`<span>latest ${esc(latest.createdAtUtc)}</span>`:''}</div><div class=collector-history>${collectorHistoryTable(c)}</div><div class=collector-actions><button data-collector-doc="${esc(c.docs||'collectors')}">How this collector works</button>${latest.url?`<button data-collector-run="${esc(latest.url)}">Open latest GitHub run</button>`:''}</div></div></article>`
 }).join('')||'<div class="workspace-empty">No collector definitions are registered.</div>';
 host.querySelectorAll('[data-collector-doc]').forEach(x=>x.addEventListener('click',async()=>{setWorkbenchView('docs');await loadDocs();await loadDocument(x.dataset.collectorDoc||'collectors')}));
 host.querySelectorAll('[data-collector-run]').forEach(x=>x.addEventListener('click',()=>window.open(x.dataset.collectorRun,'_blank','noopener,noreferrer')));
}
$('refreshCollectors')?.addEventListener('click',()=>loadCollectors(true));
async function loadCollectors(refresh=false){
 if(currentCollectors&&!refresh){renderCollectors(currentCollectors);return currentCollectors}
 const host=$('collectorRows');if(host)host.innerHTML='<div class="workspace-empty">Reading bounded recent GitHub Actions history and published evidence…</div>';
 try{const p=await api('/api/workbench/collectors'+(refresh?'?refresh=1':''));renderCollectors(p);return p}catch(e){if(host)host.innerHTML=`<div class=collector-error><b>Could not review collectors</b><div>${esc(e.message)}</div></div>`;return null}
}

async function loadLatestFindings(){try{renderLatestFindings(await api('/api/workbench/findings?limit=24'))}catch(e){$('latestFindingRows').innerHTML=`<tr><td colspan=4 class=workspace-empty>Could not load latest findings: ${esc(e.message)}</td></tr>`}}
function renderDocCatalog(c){currentDocs=c;const docs=Array.isArray(c?.documents)?c.documents:[];$('docCount').textContent=`${docs.length} document(s)`;const groups=[];for(const d of docs){let g=groups.find(x=>x.name===d.group);if(!g){g={name:d.group,docs:[]};groups.push(g)}g.docs.push(d)}$('docTree').innerHTML=groups.map(g=>`<div class=doc-group>${esc(g.name)}</div>${g.docs.map(d=>`<button class="doc-item ${currentDocId===d.id?'active':''}" data-doc-id="${esc(d.id)}"><b>${esc(d.title)}</b><span class=small>${esc(d.summary||d.path||'')}</span></button>`).join('')}`).join('')||'<div class=workspace-empty>No local documentation catalog.</div>';$('docTree').querySelectorAll('[data-doc-id]').forEach(x=>x.addEventListener('click',()=>loadDocument(x.dataset.docId)))}
function markdownInline(text){
 let s=esc(String(text||''));
 s=s.replace(/`([^`]+)`/g,'<code>$1</code>');
 s=s.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');
 s=s.replace(/__([^_]+)__/g,'<strong>$1</strong>');
 s=s.replace(/(^|[\s(])\*([^*\n]+)\*/g,'$1<em>$2</em>');
 s=s.replace(/(^|[\s(])_([^_\n]+)_/g,'$1<em>$2</em>');
 s=s.replace(/\[([^\]]+)\]\(([^)]+)\)/g,(_m,label,rawHref)=>{
   const href=String(rawHref||'').trim().replace(/^&lt;/,'').replace(/&gt;$/,'');
   const external=/^https?:\/\//i.test(href);
   const safe=external?href:(/^[A-Za-z0-9_./#-]+(?:\.md(?:#[A-Za-z0-9_.-]+)?)?$/.test(href)?href:'#');
   const attrs=external?' target="_blank" rel="noopener noreferrer"':` data-doc-link="${esc(safe)}"`;
   return `<a href="${esc(safe)}"${attrs}>${label}</a>`;
 });
 return s;
}
function markdownTable(lines){
 if(lines.length<2)return'';
 const split=line=>line.trim().replace(/^\||\|$/g,'').split('|').map(x=>x.trim());
 const head=split(lines[0]),body=lines.slice(2).map(split);
 return `<table><thead><tr>${head.map(x=>`<th>${markdownInline(x)}</th>`).join('')}</tr></thead><tbody>${body.map(row=>`<tr>${head.map((_h,i)=>`<td>${markdownInline(row[i]||'')}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}
function renderMarkdown(source){
 const lines=String(source||'').replace(/\r\n?/g,'\n').split('\n'),out=[];let i=0;
 const isTableSep=line=>/^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(line||'');
 while(i<lines.length){
   const line=lines[i];
   if(/^```/.test(line)){
     const lang=line.replace(/^```/,'').trim(),buf=[];i++;
     while(i<lines.length&&!/^```/.test(lines[i]))buf.push(lines[i++]);
     if(i<lines.length)i++;
     out.push(`<pre${lang?` data-language="${esc(lang)}"`:''}><code>${esc(buf.join('\n'))}</code></pre>`);continue;
   }
   if(i+1<lines.length&&line.includes('|')&&isTableSep(lines[i+1])){
     const table=[line,lines[i+1]];i+=2;while(i<lines.length&&lines[i].includes('|')&&lines[i].trim())table.push(lines[i++]);
     out.push(markdownTable(table));continue;
   }
   const h=/^(#{1,6})\s+(.+)$/.exec(line);if(h){const n=Math.min(4,h[1].length);out.push(`<h${n}>${markdownInline(h[2])}</h${n}>`);i++;continue}
   if(/^\s*([-*_])(?:\s*\1){2,}\s*$/.test(line)){out.push('<hr>');i++;continue}
   if(/^>\s?/.test(line)){const buf=[];while(i<lines.length&&/^>\s?/.test(lines[i]))buf.push(lines[i++].replace(/^>\s?/,''));out.push(`<blockquote>${markdownInline(buf.join(' '))}</blockquote>`);continue}
   if(/^\s*[-*+]\s+/.test(line)){
     const items=[];while(i<lines.length&&/^\s*[-*+]\s+/.test(lines[i])){let item=lines[i++].replace(/^\s*[-*+]\s+/,'');const task=/^\[([ xX])\]\s+/.exec(item);if(task){item=item.replace(/^\[[ xX]\]\s+/,'');items.push(`<li><span class=md-task><input type=checkbox disabled ${task[1].toLowerCase()==='x'?'checked':''}>${markdownInline(item)}</span></li>`)}else items.push(`<li>${markdownInline(item)}</li>`)}out.push(`<ul>${items.join('')}</ul>`);continue;
   }
   if(/^\s*\d+\.\s+/.test(line)){
     const items=[];while(i<lines.length&&/^\s*\d+\.\s+/.test(lines[i]))items.push(`<li>${markdownInline(lines[i++].replace(/^\s*\d+\.\s+/,''))}</li>`);out.push(`<ol>${items.join('')}</ol>`);continue;
   }
   if(!line.trim()){i++;continue}
   const para=[line.trim()];i++;while(i<lines.length&&lines[i].trim()&&!/^(#{1,6})\s+/.test(lines[i])&&!/^```/.test(lines[i])&&!/^>\s?/.test(lines[i])&&!/^\s*[-*+]\s+/.test(lines[i])&&!/^\s*\d+\.\s+/.test(lines[i])&&!(i+1<lines.length&&lines[i].includes('|')&&isTableSep(lines[i+1])))para.push(lines[i++].trim());
   out.push(`<p>${markdownInline(para.join(' '))}</p>`);
 }
 return out.join('');
}
function wireMarkdownLinks(root){
 root.querySelectorAll('[data-doc-link]').forEach(a=>a.addEventListener('click',async e=>{
   e.preventDefault();const href=a.dataset.docLink||'',path=href.split('#')[0],anchor=href.includes('#')?href.split('#').slice(1).join('#'):'';
   const docs=Array.isArray(currentDocs?.documents)?currentDocs.documents:[],target=docs.find(d=>d.path===path||String(d.path||'').endsWith('/'+path)||d.id===path.replace(/\.md$/i,''));
   if(target){await loadDocument(target.id);if(anchor){const node=[...$('docContent').querySelectorAll('h1,h2,h3,h4')].find(x=>x.textContent.trim().toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')===anchor.toLowerCase());node?.scrollIntoView({block:'start'})}}
 }));
}
async function loadDocument(id){try{const d=await api('/api/doc?id='+encodeURIComponent(id));currentDocId=d.id;$('docTitle').textContent=d.title||d.path||id;$('docMeta').textContent=`${d.path||''} · ${d.group||''}`;$('docContent').innerHTML=renderMarkdown(d.content||'');wireMarkdownLinks($('docContent'));if(currentDocs)renderDocCatalog(currentDocs)}catch(e){$('docTitle').textContent='Documentation unavailable';$('docMeta').textContent=e.message;$('docContent').innerHTML=`<p class=fail>${esc(e.message)}</p>`}}
async function loadDocs(){if(currentDocs){renderDocCatalog(currentDocs);if(!currentDocId)loadDocument('platform');return}try{const c=await api('/api/docs');renderDocCatalog(c);const first=(c.documents||[]).find(d=>d.id==='platform')||(c.documents||[])[0];if(first)await loadDocument(first.id)}catch(e){$('docTree').innerHTML=`<div class=workspace-empty>Could not load documentation: ${esc(e.message)}</div>`}}
function renderWorkbenchCollections(payload){const incidents=Array.isArray(payload?.incidents)?payload.incidents:[];const events=Array.isArray(payload?.events)?payload.events:[];const intel=Array.isArray(payload?.intelligence)?payload.intelligence:[];$('incidentCount').textContent=`${incidents.length} current cases`;$('incidentRows').innerHTML=incidents.map(i=>{const a=i.asset||{};return `<tr class=click data-workbench-case="${a.variantId||0}" data-workbench-case-target="incidents"><td><b>${esc(a.name||a.internalName||'')}</b><div class="muted small">${esc(a.internalName||'')} · ${esc(a.version||'')}</div></td><td><span class="incident-badge ${sev(i.severity)}">${esc(String(i.priority||'watch').toUpperCase())}</span></td><td>${fmt(i.findingCount||0)}<div class="muted small">${esc(i.severity||'none')}</div></td><td>${fmt(i.advisoryCount||0)} advisory</td><td>${esc(i.lastEvidenceUtc||'unscanned')}</td></tr>`}).join('')||'<tr><td colspan=5 class=workspace-empty>No elevated current cases.</td></tr>';$('eventCount').textContent=`${events.length} current asset events`;$('eventRows').innerHTML=events.map(e=>{const a=e.asset||{};return `<tr class=click data-workbench-case="${a.variantId||0}" data-workbench-case-target="events"><td>${esc(e.occurredAtUtc||'—')}</td><td><b>${esc(a.name||a.internalName||'')}</b><div class="muted small">variant ${esc(a.variantId||'')}</div></td><td>${esc(e.label||e.eventType||'Security event')}</td><td class="${sev(e.severity)}">${esc(e.severity||'none')}</td><td>${esc(a.sourceName||'')}</td></tr>`}).join('')||'<tr><td colspan=5 class=workspace-empty>No current security events.</td></tr>';$('intelligenceCount').textContent=`${intel.length} affected assets`;$('intelligenceRows').innerHTML=intel.map(i=>{const a=i.asset||{};return `<tr class=click data-workbench-variant="${a.variantId||0}"><td><b>${esc(a.name||a.internalName||'')}</b></td><td>${fmt(i.advisoryCount||0)}</td><td class="${sev(i.highestSeverity)}">${esc(i.highestSeverity||'none')}</td><td class="${sev(i.staticSeverity)}">${esc(i.staticSeverity||'none')}</td><td>${esc(a.sourceName||'')}</td></tr>`}).join('')||'<tr><td colspan=5 class=workspace-empty>No advisory-bearing assets in the current view.</td></tr>';const c=currentSummary?.counts||{};$('intelligenceCards').innerHTML=card('Known advisories',c.advisories||0)+card('Dependency components',c.dependencyComponents||0)+card('IPC providers',c.ipcProviders||0)+card('Affected assets',intel.length);const top=incidents.slice(0,8);$('dashboardActivityRows').innerHTML=top.length?`<table><thead><tr><th>Asset</th><th>Priority</th><th>Reason</th><th>Intelligence</th></tr></thead><tbody>${top.map(i=>{const a=i.asset||{};const reason=(i.reasons||[])[0]?.label||'';return `<tr class=click data-workbench-variant="${a.variantId||0}"><td><b>${esc(a.name||a.internalName||'')}</b></td><td class="${sev(i.severity)}">${esc(String(i.priority||'watch').toUpperCase())}</td><td>${esc(reason)}</td><td>${fmt(i.advisoryCount||0)} advisory</td></tr>`}).join('')}</tbody></table>`:'<div class=workspace-empty>No elevated current activity.</div>';document.querySelectorAll('[data-workbench-case]').forEach(x=>x.addEventListener('click',()=>loadWorkbenchCase(Number(x.dataset.workbenchCase),x.dataset.workbenchCaseTarget||'incidents')));document.querySelectorAll('[data-workbench-variant]').forEach(x=>x.addEventListener('click',()=>openWorkbenchAsset(Number(x.dataset.workbenchVariant))))}
let currentRelationshipCatalog=null;
function wireIntelligenceLinks(root=document){root.querySelectorAll('[data-intel-kind][data-intel-key]').forEach(x=>x.addEventListener('click',()=>loadIntelligencePivot(x.dataset.intelKind,x.dataset.intelKey)));root.querySelectorAll('[data-intel-variant]').forEach(x=>x.addEventListener('click',()=>openWorkbenchAsset(Number(x.dataset.intelVariant))))}
function intelligencePivotHtml(p){const r=p?.relationship||{},assets=Array.isArray(p?.assets)?p.assets:[];const summary=r.kind==='endpoint'?`${r.pluginCount||assets.length} plugin(s) · ${r.observations||0} observations`:r.kind==='component'?`${r.pluginCount||assets.length} plugin(s) · ${(r.versions||[]).length} version(s)`:r.kind==='advisory'?`${assets.length} affected asset(s) · fixed ${r.fixedVersion||'unknown'}`:'';return `<div class=case-projection-head><div><h2>${esc(r.label||r.key||'Intelligence pivot')}</h2><div class="muted small">${esc(r.kind||'relationship')} · ${esc(p.relationshipRevision||'')}</div></div><span class="badge ro">READ ONLY</span></div><div class=cards>${card('Affected assets',assets.length)}${card('Relationship',String(r.kind||'').toUpperCase())}${r.severity?card('Severity',String(r.severity).toUpperCase()):''}</div><div class=readonly-boundary>${esc(summary)}. This relationship is investigation context only and cannot rewrite findings or policy.</div>${assets.length?`<table><thead><tr><th>Plugin asset</th><th>Version</th><th>Source</th></tr></thead><tbody>${assets.map(a=>`<tr class=click data-intel-variant="${a.variantId||0}"><td><b>${esc(a.name||a.internalName||'')}</b><div class="muted small">variant ${esc(a.variantId||'')}</div></td><td>${esc(a.version||'')}</td><td>${esc(a.sourceName||a.sourceUrl||'')}</td></tr>`).join('')}</tbody></table>`:'<div class=workspace-empty>No current assets resolve to this relationship.</div>'}<details><summary>Relationship evidence</summary>${evidence(r)}</details>`}
async function loadIntelligencePivot(kind,key){const panel=$('intelligencePivotPanel');if(!panel)return;panel.innerHTML='<div class=workspace-empty>Resolving affected assets from the published relationship index…</div>';try{const p=await api('/api/workbench/pivot?kind='+encodeURIComponent(kind)+'&key='+encodeURIComponent(key));panel.innerHTML=intelligencePivotHtml(p);wireIntelligenceLinks(panel);panel.scrollIntoView({behavior:'smooth',block:'nearest'});toniSay(`Pivoted ${p.assets?.length||0} current assets through ${p.relationship?.label||key}. This is read-only intelligence context.`)}catch(e){panel.innerHTML=`<div class=research-error><b>Could not resolve intelligence pivot</b><div>${esc(e.message)}</div></div>`}}
function renderRelationshipCatalog(c){currentRelationshipCatalog=c;const endpoints=Array.isArray(c?.endpoints)?c.endpoints:[],components=Array.isArray(c?.components)?c.components:[],advisories=Array.isArray(c?.advisories)?c.advisories:[];$('endpointIntelCount').textContent=`${endpoints.length} endpoint(s)`;$('componentIntelCount').textContent=`${components.length} component(s)`;$('advisoryIntelCount').textContent=`${advisories.length} advisory match(es)`;$('endpointIntelRows').innerHTML=endpoints.map(x=>`<tr class=click data-intel-kind=endpoint data-intel-key="${esc(x.key||'')}"><td><b>${esc(x.label||x.key||'')}</b><div class="muted small">${esc((x.purposes||[]).join(', '))}</div></td><td>${fmt(x.variantCount||0)}</td><td>${esc((x.classifications||[]).join(', ')||'unclassified')}</td></tr>`).join('')||'<tr><td colspan=3 class=workspace-empty>No published endpoint relationships yet.</td></tr>';$('componentIntelRows').innerHTML=components.map(x=>`<tr class=click data-intel-kind=component data-intel-key="${esc(x.key||'')}"><td><b>${esc(x.label||x.key||'')}</b><div class="muted small">${esc(x.componentKind||'')}</div></td><td>${fmt(x.variantCount||0)}</td><td>${esc(x.versionDivergence||'none')}</td></tr>`).join('')||'<tr><td colspan=3 class=workspace-empty>No published component relationships yet.</td></tr>';$('advisoryIntelRows').innerHTML=advisories.map(x=>`<tr class=click data-intel-kind=advisory data-intel-key="${esc(x.key||'')}"><td><b>${esc(x.advisoryId||x.label||'')}</b><div class="muted small">${esc(x.label||'')}</div></td><td>${esc(x.componentName||x.componentKey||'')}</td><td>${fmt(x.variantCount||0)}</td><td class="${sev(x.severity)}">${esc(x.severity||'none')}</td><td>${esc(x.fixedVersion||'—')}</td></tr>`).join('')||'<tr><td colspan=5 class=workspace-empty>No published advisory relationships yet.</td></tr>';wireIntelligenceLinks($('workbench-intelligence'))}
async function loadRelationshipCatalog(){try{const c=await api('/api/workbench/relationships?limit=1000');renderRelationshipCatalog(c);const counts=c.counts||{};const cards=$('intelligenceCards');if(cards)cards.innerHTML=card('Observed endpoints',counts.endpoints||0)+card('Shared components',counts.components||0)+card('Advisory matches',counts.advisories||0)+card('Relationship revision',(c.relationshipRevision||'none').slice(0,18))}catch(e){console.warn('Relationship intelligence unavailable',e);const panel=$('intelligencePivotPanel');if(panel)panel.innerHTML=`<div class="workspace-empty">This Evidence-v2 snapshot has no compatible relationship index yet: ${esc(e.message)}</div>`}}
function relationGraphPositions(g,filter='all'){const nodes=(g?.nodes||[]).filter(n=>filter==='all'||['plugin','variant','source','artifact'].includes(n.kind)||n.kind===filter),kinds=['plugin','variant','artifact','source','component','endpoint','advisory'],cols={plugin:85,variant:245,artifact:420,source:420,component:610,endpoint:610,advisory:800},groups={};for(const n of nodes)(groups[n.kind]||(groups[n.kind]=[])).push(n);const max=Math.max(1,...Object.values(groups).map(x=>x.length)),height=Math.max(380,120+max*78),pos={};for(const kind of kinds){const a=groups[kind]||[];a.forEach((n,idx)=>{const y=a.length===1?height/2:70+idx*((height-140)/(a.length-1));pos[n.nodeId]={x:cols[kind]||610,y}})}return{nodes,pos,height,width:900}}
function renderAssetRelationGraph(g,filter='all'){const target=$('assetRelationGraph');if(!target)return;const layout=relationGraphPositions(g,filter),visible=new Set(layout.nodes.map(n=>n.nodeId)),edges=(g?.edges||[]).filter(e=>visible.has(e.from)&&visible.has(e.to));const svg=`<svg viewBox="0 0 ${layout.width} ${layout.height}" preserveAspectRatio="none" aria-hidden="true">${edges.map(e=>{const a=layout.pos[e.from],b=layout.pos[e.to];if(!a||!b)return'';const mx=(a.x+b.x)/2,my=(a.y+b.y)/2;return `<path class=relation-edge d="M ${a.x+70} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x-70} ${b.y}"/><text class=relation-edge-label x="${mx}" y="${my-4}" text-anchor="middle">${esc(e.relationship||'')}</text>`}).join('')}</svg>`;target.innerHTML=`<div class=relation-graph-inner style="min-height:${layout.height}px;min-width:${layout.width}px">${svg}${layout.nodes.map(n=>{const p=layout.pos[n.nodeId];return `<div class="relation-node ${esc(n.kind||'')}" style="left:${p.x}px;top:${p.y}px"><span class="muted small">${esc(String(n.kind||'').toUpperCase())}</span><b>${esc(n.label||n.nodeId||'')}</b></div>`}).join('')}</div>`}
function assetRelationshipsHtml(r){currentAssetRelationGraph=r?.graph||{};const endpoints=r?.endpoints||[],components=r?.components||[],advisories=r?.advisories||[],g=r?.graph||{};const links=(kind,rows)=>rows.length?rows.map(x=>`<button class=linkbutton data-intel-kind="${kind}" data-intel-key="${esc(x.key||'')}">${esc(x.label||x.key||'')}</button>`).join(' '):'<span class=muted>none</span>';return `<h4>Relationship graph</h4><div class=cards>${card('Endpoints',endpoints.length)}${card('Components',components.length)}${card('Advisories',advisories.length)}${card('Graph edges',(g.edges||[]).length)}</div><div class=relation-filterbar><button class=active data-rel-filter=all>All relationships</button><button data-rel-filter=endpoint>Endpoints</button><button data-rel-filter=component>Components</button><button data-rel-filter=advisory>Advisories</button></div><div id=assetRelationGraph class=relation-graph><div class=workspace-empty>Rendering relationship graph…</div></div><div class=research-grid style="margin-top:9px"><div class=research-box><h4>Network endpoints <button class=context-help data-help-topic=endpoint>?</button></h4>${links('endpoint',endpoints)}</div><div class=research-box><h4>Components</h4>${links('component',components)}</div><div class=research-box><h4>Advisories</h4>${links('advisory',advisories)}</div><div class="research-box technical-detail"><h4>Raw graph edges</h4>${evidence(g.edges||[])}</div></div>`}
async function loadAssetRelationships(id,pane){const target=pane?.querySelector?.('[data-asset-relationships]');if(!target||target.dataset.loaded==='1')return;target.innerHTML='<span class=muted>Loading published ecosystem relationships…</span>';try{const r=await api('/api/workbench/asset-relations?variant_id='+encodeURIComponent(id));target.dataset.loaded='1';target.innerHTML=assetRelationshipsHtml(r);renderAssetRelationGraph(r.graph||{},'all');target.querySelectorAll('[data-rel-filter]').forEach(x=>x.addEventListener('click',()=>{target.querySelectorAll('[data-rel-filter]').forEach(b=>b.classList.remove('active'));x.classList.add('active');renderAssetRelationGraph(r.graph||{},x.dataset.relFilter||'all')}));target.querySelectorAll('[data-intel-kind]').forEach(x=>x.addEventListener('click',()=>{setWorkbenchView('intelligence');loadIntelligencePivot(x.dataset.intelKind,x.dataset.intelKey)}));wireContextHelp(target)}catch(e){target.innerHTML=`<div class=research-error>${esc(e.message)}</div>`}}
async function init(){
 currentRuleCatalog=null;currentReports=null;currentSystemStatus=null;currentOperations=null;
 const [s,t,source]=await Promise.all([api('/api/summary'),api('/api/tables'),api('/api/source')]);tables=t;currentSummary=s;applySourceStatus(source);
 $('scannerBadge').textContent=`SigmaScope ${s.sigmascopeVersion||s.scannerVersion||'?'}`;$('latestBadge').textContent=s.latestScanUtc||'No completed analysis timestamp';
 const c=s.counts||{},r=s.revisions||s.meta||{},v2=source.mode==='online'||s.format==='security-evidence-v2';if(Number(c.criticalFindings||0)>0)upsertNotification({id:`critical-summary:${source.currentRevision||r.evidenceRevision||'current'}:${c.criticalFindings}`,level:'critical',rank:98,title:`${fmt(c.criticalFindings)} critical finding${Number(c.criticalFindings)===1?'':'s'} in current evidence`,detail:'Current published evidence contains critical findings that deserve review.',meta:'Open Cases to inspect the affected plugins.',view:'incidents'});
 const definitionsPill=$('definitionsPill');if(definitionsPill)definitionsPill.innerHTML=`<b>Defs</b> ${esc(r.definitionsRevision||'—')}`;
 const focus=v2?[
  ['Results available',c.variants,{table:'v2_current_variants'},'current variants with published evidence'],
  ['Never scanned',c.unscannedVariantsPending,{table:'v2_unscanned_queue'},'coverage-first queue lane'],
  ['Needs review',c.reviewVariants,{table:'v2_review_variants'},'current high/critical variants'],
  ['Queue retry',c.queueRetry,{table:'v2_queue_items',column:'state',value:'retry'},'failed work waiting for retry']
 ]:[
  ['Current analyses',c.currentScans,{table:'plugin_security_current'}],['Failed analyses',c.failedScans,{table:'plugin_security_current'}],['High',c.highFindings,{table:'plugin_security_findings',column:'severity',value:'high'}],['Critical',c.criticalFindings,{table:'plugin_security_findings',column:'severity',value:'critical'}]
 ];
 const all=v2?[
  ['Current variants',c.variants,{table:'v2_current_variants'},'one row per active variant'],['Retired',c.terminalVariants,{table:'v2_terminal_variants'},'retained terminal snapshots'],['Superseded',c.historicalSnapshots,{table:'v2_historical_snapshots'},'retained historical snapshots'],
  ['Artifact groups',c.artifactGroups,{table:'v2_artifacts'},'grouped by exact artifact SHA-256'],['Immutable analyses',c.analyses,{table:'v2_analyses'},'one row per immutable analysis'],['Findings',c.findings,{table:'v2_finding_breakdown',metric:'finding_count'},'sum of finding_count'],['High findings',c.highFindings,{table:'v2_finding_breakdown',column:'high_count',value:'__positive__',metric:'high_count'},'sum of high_count'],['Critical findings',c.criticalFindings,{table:'v2_finding_breakdown',column:'critical_count',value:'__positive__',metric:'critical_count'},'sum of critical_count'],
  ['Dependency components',c.dependencyComponents,{table:'v2_dependency_components'},'normalized component records'],['NuGet versions',c.observedNugetVersions,{table:'v2_nuget_packages'},'exact package/version pairs'],['OSV matches',c.advisories,{table:'v2_advisories'},'frozen advisory records'],['IPC providers',c.ipcProviders,{table:'v2_ipc_providers'},'observed provider registry'],
  ['Queue pending',c.queuePending,{table:'v2_queue_items',column:'state',value:'pending'},'all pending work items'],['Never scanned',c.unscannedVariantsPending,{table:'v2_unscanned_queue'},'uncovered artifact work'],['Queue retry',c.queueRetry,{table:'v2_queue_items',column:'state',value:'retry'},'retry work'],['Queue complete',c.queueComplete,{table:'v2_queue_recent_completed'},'recent completed work']
 ]:focus;
 $('summaryCards').innerHTML=focus.map(x=>card(...x)).join('');wireMetricCards($('summaryCards'));
 $('allMetricCards').innerHTML=all.map(x=>card(...x)).join('');wireMetricCards($('allMetricCards'));
 toniOverview();if(v2)$('advancedSql').style.display='none';renderTableList();await loadPlugins();renderHeaderPluginSelect();await loadRelationshipCatalog();loadLatestFindings();loadOperations(false);loadSystemStatus();renderDashboardPlatformOverview()
}
function applySourceStatus(s){currentSourceStatus=s||{};const source=$('sourceBadge'),revision=$('revisionBadge');if(source){source.textContent=s.mode==='online'?'Online · raw GitHub':String(s.mode||'Local');source.title=s.baseUrl||s.cacheDirectory||''}if(revision)revision.textContent=s.currentRevision||'—';const b=$('refreshEvidence');if(b){b.style.display=s.updateAvailable?'inline-block':'none';if(s.updateAvailable)b.textContent=`Refresh to ${String(s.remoteRevision||'new evidence').slice(0,28)}`}if(s.updateAvailable)upsertNotification({id:`evidence-update:${s.remoteRevision||'remote'}`,level:'info',rank:80,title:'New security evidence is available',detail:`Published evidence ${s.remoteRevision||''} is newer than the loaded snapshot.`,meta:'Refresh when you are ready to move the workbench to the new immutable snapshot.',action:'refresh-evidence'});if(s.error)upsertNotification({id:`source-error:${s.error}`,level:'fail',rank:90,title:'Evidence source problem',detail:s.error,meta:s.baseUrl||s.cacheDirectory||''});renderDashboardPlatformOverview()}
async function checkEvidenceRevision(){try{const s=await api('/api/source?check=1');applySourceStatus(s)}catch(e){console.warn('Evidence revision check failed',e)}}
async function refreshEvidence(){const b=$('refreshEvidence');b.disabled=true;try{const s=await api('/api/refresh',{method:'POST'});applySourceStatus(s);await init()}finally{b.disabled=false}}
function debouncedLoad(){clearTimeout(timer);timer=setTimeout(loadPlugins,220)}
async function loadPlugins(){const q=$('pluginQuery').value,severity=$('severityFilter').value,status=$('scanStatusFilter').value,known=$('knownRiskFilter').checked;const u='/api/workbench?limit=2000&q='+encodeURIComponent(q)+'&severity='+encodeURIComponent(severity)+'&status='+encodeURIComponent(status)+(known?'&known_risk=1':'');const payload=await api(u),rows=Array.isArray(payload?.assets)?payload.assets:[];currentAssetRows=rows;if(!q&&!severity&&!status&&!known)headerPluginRows=rows.slice();renderHeaderPluginSelect();$('pluginRowCount').textContent=`${rows.length} shown`;$('pluginRows').innerHTML=rows.map(r=>{const conf=r.source_attribution_confidence??'—',hasSource=!!r.source_code_available,mode=hasSource?'SOURCE CODE':'ARTIFACT ONLY',coverage=r.source_coverage_label||'',modeClass=hasSource?'ok':'warn';return `<tr class="click triage-row ${currentSubject?.variantId===Number(r.variant_id)?'selected':''}" data-variant="${r.variant_id}"><td><b>${esc(r.canonical_name||r.name||r.internal_name)}</b><div class="muted small">${esc(r.internal_name)} · ${esc(r.author)}</div><div class="muted small">${esc(r.assembly_version||'')}</div></td><td class="${sev(r.highest_severity)}">${esc(r.highest_severity||'none')}</td><td>${esc(r.automation_level||'none')}</td><td class=source-cell><span class="source-state ${modeClass}"><span class=source-mode>${mode}</span></span><div class="small">${hasSource?`attribution ${esc(conf)}/100`:''}</div><div class=coverage-label>${esc(coverage||r.source_name||'')}</div></td><td>${esc(r.scan_status)}<div class="muted small">${esc(r.scanned_at_utc||'')}</div></td></tr>`}).join('')||'<tr><td colspan=5 class=empty>No current variants match these filters.</td></tr>';$('pluginRows').querySelectorAll('[data-variant]').forEach(x=>x.addEventListener('click',()=>loadDetail(Number(x.dataset.variant))));renderWorkbenchCollections(payload)}
function renderDataset(name,rows){if(name==='findings')return rows.map(f=>`<div class=finding><h4 class="${sev(f.severity)}">${esc(f.severity)} · ${esc(f.title)}</h4><div>${esc(f.description)}</div><div class="muted small">${esc(f.rule_id)} · ${esc(f.category)}</div>${evidence(f.evidence_json)}</div>`).join('')||'<span class=muted>No findings.</span>';if(name==='dependencies')return `<div style="overflow:auto"><table><thead><tr><th>Kind</th><th>Name</th><th>Version</th><th>Requirement</th><th>Relationship</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${esc(x.kind)}</td><td>${esc(x.name)}</td><td>${esc(x.resolved_version||x.version)}</td><td>${esc(x.requirement)}</td><td>${esc(x.relationship)}</td></tr>`).join('')}</tbody></table></div>`;if(name==='ipc')return `<div style="overflow:auto"><table><thead><tr><th>Role</th><th>Channel</th><th>Relationship</th><th>Confidence</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${esc(x.role)}</td><td>${esc(x.channel)}</td><td>${esc(x.relationship)}</td><td>${esc(x.relationship_confidence)}</td></tr>`).join('')}</tbody></table></div>`;if(name==='permissions')return rows.map(x=>`<div class=finding><b>${esc(x.permission_id)}</b> <span class=pill>${esc(x.risk)}</span> <span class=pill>${esc(x.confidence)}</span><div>${esc(x.reason)}</div>${evidence(x.evidence_json)}</div>`).join('')||'<span class=muted>No permission candidates.</span>';if(name==='automation')return rows.map(x=>`<div class=finding><b>${esc(x.label||x.capability_id)}</b> <span class=pill>${esc(x.automation_level)}</span> <span class=pill>${esc(x.confidence)}</span><div>${esc(x.reason)}</div>${evidence(x.evidence_json)}</div>`).join('')||'<span class=muted>No automation capabilities.</span>';return evidence(rows)}
async function loadDataset(id,name,body){body.innerHTML='<span class=muted>Loading published evidence shard…</span>';try{const rows=await api('/api/dataset?variant_id='+id+'&name='+encodeURIComponent(name));body.innerHTML=renderDataset(name,rows)}catch(e){body.innerHTML=`<span class=fail>${esc(e.message)}</span>`}}
function contractPills(d){const c=d.contracts||{};const items=Object.entries(c).filter(([,v])=>v!==null&&v!==undefined&&v!=='');return items.length?items.map(([k,v])=>`<span class=pill>${esc(k)} v${esc(v)}</span>`).join(''):'<span class=muted>No explicit modern contracts on this historical scan.</span>'}
function renderSecondary(sec){
 if(!sec||!Object.keys(sec).length)return '<div class="finding"><h4>Secondary security not recorded</h4><div class="muted small">This scan predates the current secondary-security contract or did not complete artifact analysis. No ClamAV/YARA verdict is implied.</div></div>';
 const engines=sec.engines||sec.results||[],intro=`<div class="muted small">Supplemental evidence only · ClamAV/YARA results do not silently alter SigmaScope severity or source-review coverage.</div>`;
 if(!Array.isArray(engines)||!engines.length)return intro+evidence(sec);
 const engineCard=e=>{const name=String(e.engine||e.name||'secondary engine'),matches=e.matches||[],complete=String(e.status||e.result||'unknown').toLowerCase(),label=name.toLowerCase()==='clamav'?'ClamAV antivirus':name.toLowerCase()==='yara'?'YARA rules':name;let verdict=matches.length?`${matches.length} MATCH${matches.length===1?'':'ES'}`:(complete==='complete'||complete==='ready')?'NO MATCHES':complete.toUpperCase();return `<div class=card><div class="n ${matches.length?'fail':'pass'}">${esc(verdict)}</div><div><b>${esc(label)}</b></div><div class="muted small">${esc(e.version||e.engineVersion||'')} ${e.verified===true?'· identity verified':''}${e.available===false?' · unavailable':''}</div></div>`};
 const cards=`<div class=cards style="margin:8px 0">${engines.map(engineCard).join('')}</div>`;
 const details=engines.map(e=>{const matches=e.matches||[],scope=e.scanScope||e.scope||{};return `<div class=finding><h4>${esc(e.engine||e.name||'secondary engine')} · ${esc(e.status||e.result||'unknown')}</h4><div class="small muted">${esc(e.version||e.engineVersion||'')} ${e.available===false?'· unavailable':''} ${e.verified===true?'· identity verified':''}</div>${matches.length?`<div><b>Matches (${matches.length})</b>${matches.map(m=>`<div class=finding><b>${esc(m.rule||m.ruleName||m.signature||'match')}</b> <span class=pill>${esc(m.ruleClass||m.class||'')}</span> <span class=pill>${esc(m.confidence||'')}</span><div class="small muted">${esc(m.target?.path||m.targetPath||m.memberPath||m.target||'artifact container')} ${(m.target?.sha256||m.memberSha256)?'· '+esc(m.target?.sha256||m.memberSha256):''}</div><div>${esc(m.scope||m.reviewNotes||m.description||'')}</div></div>`).join('')}</div>`:'<div class="pass small">No signatures/rules matched this artifact.</div>'}${Object.keys(scope).length?`<details><summary>Scan scope</summary><div>${evidence(scope)}</div></details>`:''}<details><summary>Raw engine evidence</summary><div>${evidence(e)}</div></details></div>`}).join('');
 return intro+cards+details
}
function renderEndpoints(d){const s=d.endpointSummary||{},rows=d.networkEndpoints||[];return `<div class=explain-card><b>What this means <button class=context-help data-help-topic=endpoint>?</button></b><span class=plain-language>SigmaScope found these URL/host values in static evidence. Their presence can explain a plugin's services or dependencies, but does not by itself prove runtime communication.</span></div>${Object.keys(s).length?`<div class="technical-detail">${evidence(s)}</div>`:''}${rows.length?`<div style="overflow:auto"><table><thead><tr><th>URL / host</th><th>Class</th><th>Purpose</th><th>Origin</th><th>Confidence</th></tr></thead><tbody>${rows.map(x=>`<tr><td><b>${esc(x.url||x.host||'')}</b><div class="muted small">${esc(x.host||'')}</div></td><td>${esc(x.classification||'')}</td><td>${esc(x.purpose||'')}</td><td>${esc(x.originType||x.endpointOrigin||'')}</td><td>${esc(x.confidence||'')}</td></tr>`).join('')}</tbody></table></div>`:'<span class=muted>No endpoint literals in the compact report.</span>'}` }
function renderComponents(d){const c=d.componentSummary||{};if(!Object.keys(c).length)return '<span class=muted>No component summary on this scan.</span>';return `<div class="muted small">Derived presentation over the authoritative normalized dependency/call evidence. Native/PInvoke relationships are static evidence, not proof a runtime branch executes.</div>${evidence(c)}`}
function datasetSections(d,id){const catalog=d.datasetCatalog||[];if(!catalog.length){const counts=d.datasetCounts||{};return [['findings','Static findings'],['dependencies','Dependencies'],['ipc','IPC endpoints'],['permissions','Permission candidates'],['automation','Automation evidence']].map(([n,l],ix)=>legacyDatasetSection(d,id,n,l,ix===0)).join('')}return catalog.map(ds=>{const n=ds.name||ds.dataset||'',label=ds.label||n,records=ds.records??ds.count??0;const heavy=['calls','symbols','reachability','imports'].includes(n);const open=n==='findings';return `<details data-lazy-dataset="${esc(n)}" ${open?'open':''}><summary>${esc(label)} (${fmt(records)})${heavy?' · forensic':''}</summary><div data-lazy-body><span class=muted>${open?'Loading published evidence shard…':'Open to fetch this immutable dataset.'}</span></div></details>`}).join('')}
function legacyDatasetSection(d,id,name,label,open=false){const inline=d[name]||[];if(!d.lazyDatasets)return `<details ${open?'open':''}><summary>${esc(label)} (${inline.length})</summary><div>${renderDataset(name,inline)}</div></details>`;const n=(d.datasetCounts||{})[name]??0;return `<details data-lazy-dataset="${esc(name)}" ${open?'open':''}><summary>${esc(label)} (${n})</summary><div data-lazy-body><span class=muted>${open?'Loading published evidence shard…':'Open to fetch this evidence from GitHub.'}</span></div></details>`}
function renderSignals(d){const rows=d.researcher?.signals||[];if(!rows.length)return '<div class="signal informational"><span class=signal-dot></span><div><b>No elevated review signals in the compact case summary</b><div class="muted small">This is not a clean verdict; inspect findings and immutable evidence as needed.</div></div></div>';return `<div class=signal-list>${rows.map(x=>`<div class="signal ${esc(x.level||'informational')}"><span class=signal-dot></span><div><b>${esc(x.label||x.kind)}</b><div class="muted small">${esc(x.kind||'static evidence')} · ${esc(x.level||'')}</div></div></div>`).join('')}</div>`}
function humanFindingExplanation(f){const text=`${f?.ruleId||f?.rule_id||''} ${f?.category||''} ${f?.title||''}`.toLowerCase();if(text.includes('credential'))return'Credential-related APIs deserve review because they can expose authentication material or cached credentials.';if(text.includes('network')&&text.includes('exec'))return'This combines network access with code/process execution. Each can be legitimate, but together they create a stronger abuse path and therefore warrant closer review.';if(text.includes('process')||text.includes('exec'))return'The plugin can start or influence processes/code execution. This expands impact beyond ordinary in-process plugin behavior.';if(text.includes('network')||text.includes('endpoint'))return'The plugin contains network-related behavior or destinations. Review what service is contacted, why, and what data can leave the machine.';if(text.includes('native')||text.includes('pinvoke'))return'Native code or platform APIs bypass some managed-code visibility and therefore receive extra scrutiny.';if(text.includes('filesystem')||text.includes('file'))return'Filesystem access can be normal for configuration or caching; external or sensitive paths deserve closer inspection.';if(text.includes('registry'))return'Registry access can affect machine/user configuration outside the game process and is therefore surfaced explicitly.';if(text.includes('dependency')||text.includes('advisory'))return'This finding is tied to a software component or known advisory. The affected version and reachable use matter more than the package name alone.';return'This is a deterministic security signal, not a malware verdict. Review the evidence and rule to understand exactly why it matched.'}
function renderFindingCards(rows){if(!rows?.length)return '<span class=muted>No static findings recorded in the compact current scan.</span>';return rows.map(f=>`<div class=finding><h4 class="${sev(f.severity)}">${esc(f.severity)} · ${esc(f.title||f.findingId||'Security finding')} <button class=context-help data-help-topic=finding>?</button></h4><div>${esc(f.description||'')}</div><div class=explain-card><b>Why this matters</b><span class=plain-language>${esc(humanFindingExplanation(f))}</span><div class=explain-actions>${f.ruleId||f.rule_id?`<button data-open-rule="${esc(f.ruleId||f.rule_id)}">View rule</button>`:''}<button data-open-tab=evidence>View immutable evidence</button><button class=developer-only data-open-tab=profile>Explain expected behavior</button></div></div><div class="muted small technical-detail">${esc(f.ruleId||f.rule_id||'')} · ${esc(f.category||'')}</div>${f.evidence?.length?`<div class=technical-detail>${evidence(f.evidence)}</div>`:''}</div>`).join('')}
function renderCapabilitiesList(rows){if(!rows?.length)return '<span class=muted>None recorded.</span>';return `<div class=cap-list>${rows.map(x=>{const label=typeof x==='string'?x:(x.label||x.capabilityId||x.capability_id||JSON.stringify(x));return `<span class=pill title="Observed static capability">${esc(label)}</span>`}).join('')} <button class=context-help data-help-topic=capability>?</button></div>`}
function developerSourceGuidance(d){const cov=d?.sourceCoverage||{},attr=d?.sourceAttribution||{},verified=!!cov.sourceToBinaryVerified,hasSource=!!cov.sourceCodeAvailable;let state='Artifact-only review',body='Omega does not currently have attributable public source for this plugin. Publishing source and linking it consistently from the plugin manifest/project page gives reviewers a second evidence stream without replacing artifact analysis.',actions=['Publish a public source repository','Keep plugin/version identity consistent between source and releases','Link documentation/support/security policy from .omega/plugin.yaml'];if(hasSource&&!verified){state='Source attributed · build equivalence not proven';body='Omega found source that appears attributable to this plugin, but it cannot prove the distributed artifact was built from that source. This is a provenance gap, not a finding of malicious behavior.';actions=['Publish release artifacts from CI','Record the source commit/tag used for the release','Keep deterministic version/build metadata','Document build instructions for reviewers']}else if(verified){state='Source ↔ artifact relationship verified';body='This evidence snapshot contains a verified source-to-artifact relationship. Keep the same release/build process so future versions can retain this strong provenance.';actions=['Keep CI/release provenance stable','Review changes in Compare before publishing new versions']}return `<div class="developer-only profile-builder-intro" style="margin-bottom:10px"><b>Developer view · ${esc(state)}</b><p>${esc(body)}</p><div class=developer-actions>${actions.map(x=>`<span class=pill>${esc(x)}</span>`).join('')}</div>${attr?.reason?`<div class="muted small" style="margin-top:6px">Current attribution note: ${esc(attr.reason)}</div>`:''}</div>`}
function renderBehaviorConsistency(d){const b=d.behaviorConsistency||{},s=b.summary||{},rows=Array.isArray(b.capabilities)?b.capabilities:[],dest=b.destinations||{};if(!b.profileAvailable){return `<div class="muted small">No valid developer profile is available for comparison. ${fmt(s.observedCapabilityCount||0)} canonical capability observations remain independent SigmaScope evidence.</div>`}const stateLabel=x=>({"expected-observed":"declared + observed","observed-undeclared":"observed · undeclared","expected-not-observed":"declared · not observed","not-expected-observed":"observed · developer says not expected","not-expected-not-observed":"not expected · not observed","observed-no-profile":"observed · no profile"}[x]||x);const stateClass=x=>x==="expected-observed"||x==="not-expected-not-observed"?'pass':x==="not-expected-observed"||x==="observed-undeclared"?'warn':'';const capRows=rows.length?rows.map(x=>`<div class=finding><b>${esc(x.label||x.id)}</b> <span class="pill ${stateClass(x.state)}">${esc(stateLabel(x.state))}</span><div class="muted small">${esc(x.id||'')}</div>${x.developerReason?`<div><b>Developer explanation:</b> ${esc(x.developerReason)}</div>`:''}</div>`).join(''):'<span class=muted>No comparable capability rows.</span>';const unexplained=Array.isArray(dest.unexplained)?dest.unexplained:[],explained=Array.isArray(dest.explained)?dest.explained:[],declaredMissing=Array.isArray(dest.declaredNotObserved)?dest.declaredNotObserved:[];return `<div class=kv><b>Declared + observed</b><span>${fmt(s.expectedObservedCount||0)}</span><b>Observed, undeclared</b><span>${fmt(s.observedUndeclaredCount||0)}</span><b>Developer says not expected, but observed</b><span>${fmt(s.notExpectedObservedCount||0)}</span><b>Declared expected, not observed</b><span>${fmt(s.expectedNotObservedCount||0)}</span><b>Explained destinations</b><span>${fmt(s.explainedDestinationCount||0)}</span><b>Unexplained destinations</b><span>${fmt(s.unexplainedDestinationCount||0)}</span></div>${capRows}${unexplained.length?`<details open><summary>Observed destinations not covered by the profile (${unexplained.length})</summary>${evidence(unexplained)}</details>`:''}${explained.length?`<details><summary>Observed destinations covered by the profile (${explained.length})</summary>${evidence(explained)}</details>`:''}${declaredMissing.length?`<details><summary>Declared destinations not observed (${declaredMissing.length})</summary>${evidence(declaredMissing)}</details>`:''}<div class="muted small">This is a comparison only. Developer claims do not suppress, downgrade, or prove SigmaScope observations.</div>`}
function renderDeveloperProfile(d){const obs=(d.sourceEvidence||{}).developerProfile||{},p=obs.profile||{},meta=p.profile||{},caps=Array.isArray(p.capabilities)?p.capabilities:[],services=Array.isArray(p.services)?p.services:[];if(!obs.path&&obs.status!=='invalid')return '<span class=muted>No .omega/plugin.yaml developer profile was recorded.</span>';if(obs.status==='invalid')return `<div class=research-error><b>Developer profile invalid</b><div class=muted>${esc(obs.path||'.omega/plugin.yaml')}</div>${evidence(obs.diagnostics||[])}</div>`;const capHtml=caps.length?caps.map(c=>`<div class=finding><b>${esc(c.label||c.id)}</b> <span class="pill ${c.expected?'pass':'warn'}">${c.expected?'expected':'not expected'}</span>${c.required?'<span class=pill>required</span>':''}<div>${esc(c.reason||'')}</div>${c.destinations?.length?`<div class="muted small">Declared destinations: ${esc(c.destinations.join(', '))}</div>`:''}<div class="muted small">Developer-provided explanation · ${esc(c.id||'')}</div></div>`).join(''):'<span class=muted>No capability declarations.</span>';const serviceHtml=services.length?`<details><summary>Declared external services (${services.length})</summary>${evidence(services)}</details>`:'';return `<div class=kv><b>Profile</b><span>${esc(obs.path||'.omega/plugin.yaml')}</span><b>SHA-256</b><span>${esc(obs.sha256||'—')}</span><b>Tagline</b><span>${esc(meta.tagline||'—')}</span></div>${meta.description?`<p>${esc(meta.description)}</p>`:''}<h4>Developer-declared capabilities</h4>${capHtml}${serviceHtml}<div class="muted small">Developer declarations are context only. They do not suppress or downgrade SigmaScope evidence.</div>`}
function journeyStatusLabel(status){const labels={complete:'complete',current:'current view',failed:'failed',partial:'partial',requested:'deep scan requested','needs-evidence':'needs evidence',skipped:'skipped','not-requested':'not requested','not-recorded':'not recorded','not-run':'not run',unknown:'unknown'};return labels[status]||status||'unknown'}
function journeyTarget(stage){return ({'catalog-discovery':'overview','artifact-acquisition':'code','package-inspection':'supply','source-attribution':'supply','sigmascope-static':'findings','secondary-engines':'malware','evidence-normalization':'evidence','deep-analysis':'evidence','evidence-publication':'evidence','deltascope-view':'overview'})[stage]||''}
function journeyExplanationHtml(stage){const produced=Array.isArray(stage?.produced)?stage.produced:[],actions=(Array.isArray(stage?.actions)?stage.actions:[]).filter(a=>a?.target!=='profile'||currentPerspective==='developer'),details=Array.isArray(stage?.details)?stage.details:[];return `<div class=journey-explanation-head><div><div class=eyebrow>Selected journey step</div><h4>${esc(stage?.title||stage?.stageId||'Stage')}</h4><div class="muted small">${esc(journeyStatusLabel(String(stage?.status||'unknown').toLowerCase()))}</div></div><span class="journey-status">${esc(String(stage?.status||'unknown').toUpperCase())}</span></div><div class=journey-explanation-grid><div class=journey-explanation-block><b>What this step is for</b><div>${esc(stage?.purpose||'This stage contributes retained evidence to the plugin security path.')}</div></div><div class=journey-explanation-block><b>What happened for this plugin</b><div>${esc(stage?.summary||'No stage result is retained.')}</div></div><div class=journey-explanation-block><b>Why DeltaScope shows this state</b><div>${esc(stage?.whyStatus||'The status comes from retained evidence for this plugin variant.')}</div></div><div class=journey-explanation-block><b>What this step produced</b>${produced.length?`<div class=journey-produced>${produced.map(x=>`<span class=pill>${esc(x)}</span>`).join('')}</div>`:'<div class=muted>No retained output is claimed for this stage.</div>'}</div></div><div class=journey-explanation-block style="margin-top:8px"><b>What happens next</b><div>${esc(stage?.nextStep||'Continue following the retained evidence path.')}</div></div>${actions.length?`<div class=journey-actionbar>${actions.map(a=>`<button data-journey-action="${esc(a.target||'')}">${esc(a.label||'Open')}</button>`).join('')}</div>`:''}<details class=journey-technical><summary>Exact retained details for this step</summary><div><div class=kv><b>Evidence source</b><span>${esc(stage?.evidence||'—')}</span><b>Stage ID</b><span>${esc(stage?.stageId||'—')}</span></div>${details.length?evidence(details):'<span class=muted>No additional compact details retained.</span>'}</div></details>`}
function wireJourneyExplanation(root,j,stage,index){root.querySelectorAll('.journey-node').forEach(n=>n.classList.toggle('selected',Number(n.dataset.journeyIndex)===index));const panel=root.querySelector('[data-journey-explanation]');if(!panel)return;panel.innerHTML=journeyExplanationHtml(stage);panel.querySelectorAll('[data-journey-action]').forEach(btn=>btn.addEventListener('click',()=>{const t=btn.dataset.journeyAction;if(t==='rules'){setWorkbenchView('rules');loadRuleCatalog();toniSay(`Opened Stigma-1 from ${stage.title}. The selected plugin remains the current subject.`);return}activateResearchTab(t||journeyTarget(stage.stageId)||'overview')}));wireContextHelp(panel);panel.scrollIntoView({behavior:'smooth',block:'nearest'})}
function assetJourneyHtml(j){const stages=Array.isArray(j?.stages)?j.stages:[];if(!stages.length)return '<div class=workspace-empty>No evidence-backed journey could be reconstructed for this asset.</div>';const nodes=stages.map((x,idx)=>{const status=String(x.status||'unknown').toLowerCase(),details=(x.details||[]).map(v=>`<span class=journey-detail>${esc(v)}</span>`).join('');return `<div class="journey-stage ${esc(status)}"><div class=journey-marker>${idx+1}</div><div class="journey-node click" data-journey-index="${idx}" data-stage-id="${esc(x.stageId||'')}"><div class=journey-node-head><div class=journey-node-title>${esc(x.title||x.stageId||'Stage')}</div><span class=journey-status>${esc(journeyStatusLabel(status))}</span></div><div class=journey-summary>${esc(x.summary||'')}</div>${details?`<div class=journey-details>${details}</div>`:''}${x.evidence?`<div class=journey-evidence>evidence · ${esc(x.evidence)}</div>`:''}<div class="muted small" style="margin-top:7px">Explain this step →</div></div></div>`}).join('');return `<div class=journey-intro><div><h3>Plugin journey</h3><div class="muted small">Evidence-backed reconstruction of the actual recorded path for this variant. Select a step to see what it did, what happened for this plugin, why it has this state, what it produced and where to inspect the exact evidence.</div></div><div class=journey-legend><span class="pill pass">complete</span><span class="pill warn">partial / requested</span><span class="pill muted">skipped / not recorded</span></div></div><div class=journey-flow>${nodes}</div><div data-journey-explanation class=journey-explanation><div class="workspace-empty">Select a journey step to explain that exact stage for this plugin.</div></div><div class=journey-note><b>Read-only reconstruction.</b> DeltaScope derives this diagram from retained artifact, source, scan, observation and rule-projection evidence. It does not claim a step happened when the corresponding evidence is absent.</div>`}
async function loadAssetJourney(id,pane){const target=pane?.querySelector?.('[data-asset-journey]');if(!target||target.dataset.loaded==='1')return;target.innerHTML='<span class=muted>Reconstructing the evidence path for this plugin…</span>';try{const j=await api('/api/workbench/journey?variant_id='+encodeURIComponent(id));target.dataset.loaded='1';target.innerHTML=assetJourneyHtml(j);target.querySelectorAll('[data-journey-index]').forEach(x=>x.addEventListener('click',()=>{const idx=Number(x.dataset.journeyIndex),stage=(j.stages||[])[idx];if(stage)wireJourneyExplanation(target,j,stage,idx)}));const first=(j.stages||[]).findIndex(x=>['requested','needs-evidence','failed','partial'].includes(String(x.status||'').toLowerCase()));const initial=first>=0?first:Math.max(0,(j.stages||[]).findIndex(x=>x.stageId==='sigmascope-static'));if((j.stages||[])[initial])wireJourneyExplanation(target,j,j.stages[initial],initial)}catch(e){target.innerHTML=`<div class=research-error><b>Could not reconstruct plugin journey</b><div>${esc(e.message)}</div></div>`}}

function snapshotOptionLabel(s){const m=s?.summary||{},version=m.assembly_version||m.version||'',kind=s?.snapshotKind||'snapshot',scan=s?.scanId||m.scan_id||'';return `${version?version+' · ':''}${kind}${scan?' · scan '+scan:''}`}
function versionCompareHtml(c){if(!c?.available){const opts=(c?.snapshots||[]).filter(s=>s.snapshotKind!=='current');return `<div class=explain-card><b>No prior comparable snapshot</b><span class=plain-language>${esc(c?.reason||'DeltaScope has no retained prior snapshot for this variant.')}</span></div>${opts.length?evidence(opts):''}`};const choices=(c.snapshots||[]).filter(s=>s.snapshotKind!=='current'&&s.variantPath),changes=c.changes||[],diffs=c.diffs||{};return `<div class=compare-toolbar><label>Compare current with</label><select data-compare-select>${choices.map(s=>`<option value="${esc(s.variantPath||'')}" ${s.variantPath===c.selectedPath?'selected':''}>${esc(snapshotOptionLabel(s))}</option>`).join('')}</select><span class="muted small">Security-semantic diff; not a source-code diff.</span></div><div class=cards>${textCard('Before',c.before?.version||c.before?.snapshotKind||'snapshot')}${textCard('Current',c.after?.version||'current')}${card('Security changes',c.changeCount||0)}${textCard('Mutation authority','NONE')}</div>${changes.length?`<div class=research-box style="margin-top:10px"><h4>What changed</h4>${changes.map(x=>`<div class=compare-change><span class="compare-direction ${esc(x.direction||'changed')}">${esc(x.direction||'changed')}</span><div><b>${esc(x.label||'Change')}</b>${x.detail?`<div class="muted small">${esc(x.detail)}</div>`:''}</div></div>`).join('')}</div>`:'<div class="explain-card pass"><b>No semantic security change detected in the compact retained evidence.</b><span class=plain-language>The artifact may still differ; this view only reports the security-relevant dimensions DeltaScope can compare from retained evidence.</span></div>'}<div class="compare-grid technical-detail" style="margin-top:10px"><div class=research-box><h4>Findings</h4>${evidence(diffs.findings||{})}</div><div class=research-box><h4>Capabilities</h4>${evidence(diffs.capabilities||{})}</div><div class=research-box><h4>Endpoints</h4>${evidence(diffs.endpoints||{})}</div><div class=research-box><h4>Advisories</h4>${evidence(diffs.advisories||{})}</div></div>`}
async function loadVersionCompare(id,pane,path=''){const target=pane?.querySelector?.('[data-version-compare]');if(!target)return;target.innerHTML='<span class=muted>Comparing current security semantics with retained history…</span>';try{const q='/api/workbench/compare?variant_id='+encodeURIComponent(id)+(path?'&path='+encodeURIComponent(path):''),c=await api(q);currentCompare=c;target.innerHTML=versionCompareHtml(c);target.querySelector('[data-compare-select]')?.addEventListener('change',e=>loadVersionCompare(id,pane,e.target.value))}catch(e){target.innerHTML=`<div class=research-error><b>Could not compare retained versions</b><div>${esc(e.message)}</div></div>`}}
function profileTextList(value){return Array.isArray(value)?value.join(', '):String(value||'')}
function profileCleanList(value){return String(value||'').split(/[\n,]+/).map(x=>x.trim()).filter(Boolean)}
function profileObservedHosts(d){const dest=d?.behaviorConsistency?.destinations||{},sets=[dest.observed,dest.unexplained,dest.explained],out=[];for(const rows of sets){for(const x of (Array.isArray(rows)?rows:[])){const host=String(x?.host||'').trim();if(host&&!out.includes(host))out.push(host)}}return out}
function profileBuilderHtml(d){const obs=(d?.sourceEvidence||{}).developerProfile||{},existing=obs?.profile&&typeof obs.profile==='object'?obs.profile:{},meta=existing.profile||{},behavior=d?.behaviorConsistency||{},rows=Array.isArray(behavior.capabilities)?behavior.capabilities:[],fallback=(d?.researcher?.capabilityIds||[]).map(id=>({id,label:id,observed:true,declared:false,expected:null,required:false,developerReason:'',declaredDestinations:[]})),caps=rows.length?rows:fallback,observedHosts=profileObservedHosts(d),declared=caps.filter(x=>x.declared).length,observed=caps.filter(x=>x.observed).length,explained=caps.filter(x=>x.observed&&x.declared&&x.developerReason).length,gaps=Math.max(0,observed-explained);currentProfileBuilderBase=JSON.parse(JSON.stringify(existing||{}));const capHtml=caps.length?caps.map((c,index)=>{const include=!!c.declared,network=String(c.id||'').startsWith('network.'),state=String(c.state||''),suggestion=network&&observedHosts.length?`<div class=profile-destination-suggestion>Observed host suggestions: ${esc(observedHosts.slice(0,8).join(', '))}. Add only destinations you intentionally expect.</div>`:'';return `<div class=profile-capability data-profile-cap-index="${index}"><div class=profile-capability-head><div><b>${esc(c.label||c.id||'Capability')}</b><div class=profile-capability-id>${esc(c.id||'')}</div><div class="muted small">${esc(state||((c.observed?'observed':'not observed')+(c.declared?' · declared':'')))}</div></div><div class=profile-capability-controls><label><input type=checkbox data-profile-include ${include?'checked':''}> Explain in profile</label><label><input type=checkbox data-profile-expected ${c.expected!==false?'checked':''}> Expected</label><label><input type=checkbox data-profile-required ${c.required?'checked':''}> Required</label></div></div><textarea data-profile-reason placeholder="Why does your plugin need this capability?">${esc(c.developerReason||'')}</textarea>${network?`<input data-profile-destinations value="${esc(profileTextList(c.declaredDestinations||[]))}" placeholder="Expected hostnames, comma-separated · example: api.example.com">${suggestion}`:''}</div>`}).join(''):'<div class=workspace-empty>No canonical capability observations are available for this snapshot. You can still fill in the descriptive profile fields.</div>';return `<div class=profile-builder-shell><div class=profile-builder-intro><b>Build .omega/plugin.yaml from what Omega actually observed</b><p>This file is developer-provided context. It can explain expected capabilities, destinations and project links, but it can never mark the plugin safe, suppress a finding, lower severity, or claim source/artifact verification.</p></div><div class=profile-progress>${card('Observed capabilities',observed)}${card('Already declared',declared)}${card('Explained observations',explained)}${card('Explanation gaps',gaps)}</div>${obs.path?`<div class=profile-existing><b>Existing profile:</b> ${esc(obs.path)} · ${esc(obs.status||'unknown')}${obs.sha256?` · ${esc(String(obs.sha256).slice(0,16))}…`:''}</div>`:'<div class=profile-existing>No existing .omega/plugin.yaml was retained. This builder creates a starter document; it does not write to your repository.</div>'}<section class=research-box><h4>How Omega should describe your plugin</h4><div class=profile-form-grid><div class=profile-field><label>Tagline</label><input data-profile-meta=tagline maxlength=180 value="${esc(meta.tagline||'')}" placeholder="Short description shown with the plugin"></div><div class=profile-field><label>License</label><input data-profile-meta=license maxlength=128 value="${esc(meta.license||'')}" placeholder="MIT, GPL-3.0, custom…"></div><div class="profile-field wide"><label>Description</label><textarea data-profile-meta=description maxlength=8000 placeholder="What does the plugin do, in your own words?">${esc(meta.description||'')}</textarea></div><div class=profile-field><label>Categories</label><input data-profile-meta=categories value="${esc(profileTextList(meta.categories||[]))}" placeholder="utility, social, crafting"></div><div class=profile-field><label>Tags</label><input data-profile-meta=tags value="${esc(profileTextList(meta.tags||[]))}" placeholder="comma-separated"></div><div class=profile-field><label>Homepage</label><input data-profile-meta=homepage value="${esc(meta.homepage||'')}" placeholder="https://…"></div><div class=profile-field><label>Documentation</label><input data-profile-meta=documentation value="${esc(meta.documentation||'')}" placeholder="https://…"></div><div class=profile-field><label>Support</label><input data-profile-meta=support value="${esc(meta.support||'')}" placeholder="https://…"></div><div class=profile-field><label>Source</label><input data-profile-meta=source value="${esc(meta.source||'')}" placeholder="https://… · explanatory link, not verification"></div><div class=profile-field><label>Security policy</label><input data-profile-meta=securityPolicy value="${esc(meta.securityPolicy||'')}" placeholder="https://…"></div><div class=profile-field><label>Vulnerability reporting</label><input data-profile-meta=vulnerabilityReporting value="${esc(meta.vulnerabilityReporting||'')}" placeholder="https://…"></div></div></section><section class=research-box><div class=panelhead style="padding:0 0 9px;border:0"><div><h4>Observed capabilities and your explanation</h4><div class="muted small">Check “Explain in profile” only for capabilities you intentionally want to declare. A reason is required by the Omega profile schema.</div></div><button data-profile-add-observed>Add all observed</button></div><div class=profile-capability-list>${capHtml}</div></section><section class=research-box><div class=profile-builder-actions><button class=primary data-profile-preview>Validate & rebuild YAML</button><button data-profile-copy disabled>Copy YAML</button><button data-profile-download disabled>Download .omega/plugin.yaml</button><button data-profile-guide>Profile guide</button></div><div data-profile-validation class=profile-validation>Make changes, then validate. DeltaScope uses the same bounded profile validator as SigmaScope.</div><textarea data-profile-preview-text class=profile-preview spellcheck=false placeholder="Validated YAML will appear here"></textarea></section></div>`}
function collectProfileBuilderDocument(root){const base=JSON.parse(JSON.stringify(currentProfileBuilderBase||{})),meta={};root.querySelectorAll('[data-profile-meta]').forEach(el=>{const key=el.dataset.profileMeta,value=String(el.value||'').trim();if(!value)return;if(key==='categories'||key==='tags')meta[key]=profileCleanList(value);else meta[key]=value});const capabilities=[];root.querySelectorAll('[data-profile-cap-index]').forEach(row=>{if(!row.querySelector('[data-profile-include]')?.checked)return;const idx=Number(row.dataset.profileCapIndex),src=(currentProfileBuilderCapabilities||[])[idx]||{},reason=String(row.querySelector('[data-profile-reason]')?.value||'').trim(),cap={id:String(src.id||''),expected:!!row.querySelector('[data-profile-expected]')?.checked,required:!!row.querySelector('[data-profile-required]')?.checked,reason};const dest=profileCleanList(row.querySelector('[data-profile-destinations]')?.value||'');if(dest.length)cap.destinations=dest;capabilities.push(cap)});const doc={schema:'omega.plugin-profile.v1'};if(Object.keys(meta).length)doc.profile=meta;if(capabilities.length)doc.capabilities=capabilities;for(const key of ['services','nativeComponents','ipc','media']){const value=base[key];if(value&&(!(Array.isArray(value))||value.length)&&(!(typeof value==='object')||Array.isArray(value)||Object.keys(value).length))doc[key]=value}return doc}
function renderProfileValidation(root,result){const box=root.querySelector('[data-profile-validation]'),preview=root.querySelector('[data-profile-preview-text]'),copy=root.querySelector('[data-profile-copy]'),download=root.querySelector('[data-profile-download]'),validation=result?.validation||{},ok=!!result?.ok;currentProfileYaml=String(result?.yaml||preview?.value||'');if(preview&&result?.yaml!==undefined)preview.value=currentProfileYaml;box.className='profile-validation '+(ok?'pass':'fail');box.innerHTML=ok?`<b>Valid Omega profile</b><div class="muted small">${esc(validation.path||'.omega/plugin.yaml')} · ${fmt(validation.bytes||currentProfileYaml.length)} bytes · SHA-256 ${esc(String(validation.sha256||'').slice(0,18))}…</div><div class="muted small">This is developer context only; independent SigmaScope findings remain unchanged.</div>`:`<b>Profile needs changes</b>${(validation.diagnostics||[]).length?`<div class="muted small">${(validation.diagnostics||[]).map(x=>esc(`${x.path||'$'}: ${x.message||x.code||'validation error'}`)).join('<br>')}</div>`:'<div class="muted small">The profile validator rejected this candidate.</div>'}`;if(copy)copy.disabled=!ok;if(download)download.disabled=!ok}
async function previewProfileBuilder(root){try{const doc=collectProfileBuilderDocument(root),result=await api('/api/developer-profile/render',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profile:doc})});renderProfileValidation(root,result)}catch(e){const box=root.querySelector('[data-profile-validation]');box.className='profile-validation fail';box.innerHTML=`<b>Could not validate profile</b><div class="muted small">${esc(e.message)}</div>`}}
function downloadProfileYaml(){if(!currentProfileYaml)return;const blob=new Blob([currentProfileYaml],{type:'text/yaml;charset=utf-8'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='plugin.yaml';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),0)}
function wireProfileBuilder(d,pane){const root=pane?.querySelector?.('[data-profile-builder]');if(!root||root.dataset.loaded==='1')return;root.dataset.loaded='1';const behavior=d?.behaviorConsistency||{},rows=Array.isArray(behavior.capabilities)?behavior.capabilities:[],fallback=(d?.researcher?.capabilityIds||[]).map(id=>({id,label:id,observed:true,declared:false,expected:null,required:false,developerReason:'',declaredDestinations:[]}));currentProfileBuilderCapabilities=rows.length?rows:fallback;root.innerHTML=profileBuilderHtml(d);root.querySelector('[data-profile-add-observed]')?.addEventListener('click',()=>{root.querySelectorAll('[data-profile-cap-index]').forEach(row=>{const idx=Number(row.dataset.profileCapIndex),src=currentProfileBuilderCapabilities[idx]||{};if(src.observed)row.querySelector('[data-profile-include]').checked=true});toniSay('Added every currently observed canonical capability to the profile draft. Add a concrete reason for each one before validation.')});root.querySelector('[data-profile-preview]')?.addEventListener('click',()=>previewProfileBuilder(root));root.querySelector('[data-profile-copy]')?.addEventListener('click',async()=>{if(!currentProfileYaml)return;try{await navigator.clipboard.writeText(currentProfileYaml);toniSay('Copied validated .omega/plugin.yaml to the clipboard.')}catch(_e){root.querySelector('[data-profile-preview-text]')?.select();toniSay('Clipboard access was unavailable. The YAML is selected so you can copy it manually.')}});root.querySelector('[data-profile-download]')?.addEventListener('click',downloadProfileYaml);root.querySelector('[data-profile-guide]')?.addEventListener('click',async()=>{setWorkbenchView('docs');await loadDocs();await loadDocument('plugin-developers')});const existing=(d?.sourceEvidence||{}).developerProfile||{};if(existing.status==='valid')previewProfileBuilder(root)}

function wireResearchTabs(id){const detail=$('pluginDetail');detail.querySelectorAll('[data-research-tab]').forEach(b=>b.addEventListener('click',()=>{detail.querySelectorAll('[data-research-tab]').forEach(x=>x.classList.remove('active'));detail.querySelectorAll('[data-research-pane]').forEach(x=>x.classList.remove('active'));b.classList.add('active');const pane=detail.querySelector(`[data-research-pane="${b.dataset.researchTab}"]`);if(pane){pane.classList.add('active');if(b.dataset.researchTab==='journey')loadAssetJourney(id,pane);if(b.dataset.researchTab==='relationships')loadAssetRelationships(id,pane);if(b.dataset.researchTab==='compare')loadVersionCompare(id,pane);if(b.dataset.researchTab==='profile')wireProfileBuilder(currentPluginDetail,pane)}}));detail.querySelectorAll('[data-open-tab]').forEach(b=>b.addEventListener('click',()=>activateResearchTab(b.dataset.openTab)));detail.querySelectorAll('[data-open-rule]').forEach(b=>b.addEventListener('click',()=>openRuleFromFinding(b.dataset.openRule)));detail.querySelectorAll('[data-load-dataset]').forEach(b=>b.addEventListener('click',async()=>{const target=detail.querySelector(`[data-dataset-output="${b.dataset.loadDataset}"]`);b.disabled=true;try{await loadDataset(id,b.dataset.loadDataset,target)}finally{b.disabled=false}}));const callButton=detail.querySelector('[data-search-calls]');if(callButton)callButton.addEventListener('click',()=>loadCalls(id));wireContextHelp(detail)}
function pluginPlainSummary(d){const i=d.identity||{},r=d.researcher||{},cov=d.sourceCoverage||{},findings=r.findings||[],endpoints=d.networkEndpoints||[],sevName=i.highest_severity||'none';if(sevName==='none'&&!findings.length)return `${i.canonical_name||i.name||i.internal_name||'This plugin'} has no elevated static finding in the compact current evidence. That is not a safety guarantee: review coverage still matters. ${cov.sourceCodeAvailable?'Attributed source is available.':'Analysis is artifact-only because no attributable source is recorded.'}`;const top=(r.signals||[])[0]?.label||findings[0]?.title||`${findings.length} security finding(s)`;return `${i.canonical_name||i.name||i.internal_name||'This plugin'} is currently ${sevName} because the strongest retained evidence includes: ${top}. ${endpoints.length?`${endpoints.length} endpoint observation(s) are recorded. `:''}${cov.sourceCodeAvailable?'Artifact and attributable source evidence are available.':'No attributable source code is recorded, so source review coverage is limited.'}`}
function coverageItem(label,value,state=''){return `<div class=coverage-item><div class=label>${esc(label)}</div><div class="value ${esc(state)}">${esc(value)}</div></div>`}
function versionHistoryHtml(d){const rows=Array.isArray(d?.versionHistory)?d.versionHistory:[];if(!rows.length)return '';const current=rows.find(x=>x.isCurrent),archives=rows.filter(x=>!x.isCurrent);const render=row=>{const version=row.version||'unknown version',kind=row.isCurrent?'CURRENT':'ARCHIVE',counts=[];if(Number(row.criticalCount||0))counts.push(`${fmt(row.criticalCount)} critical`);if(Number(row.highCount||0))counts.push(`${fmt(row.highCount)} high`);if(!counts.length&&Number(row.findingCount||0))counts.push(`${fmt(row.findingCount)} finding(s)`);if(!counts.length)counts.push('no elevated findings');return `<div class="version-row ${row.isCurrent?'current':'archive'}"><div><b>${esc(version)}</b><div class=version-note>scan ${fmt(row.scanId||0)}</div></div><div><span class=version-badge>${kind}</span></div><div class="version-security ${sev(row.highestSeverity)}"><b>${esc(row.highestSeverity||'none')}</b><span>${esc(counts.join(' · '))}</span></div><div><div>${esc(row.scannedAtUtc||'date not recorded')}</div><div class=version-note>${row.isCurrent?'Included in dashboard/security totals':'Archive evidence only · excluded from current totals'}</div></div></div>`};return `<section class=version-history><div class=version-history-head><div><h4>Plugin versions</h4><div class="muted small">Current security results come only from the active version. Older scans stay visible for investigation and comparison.</div></div>${archives.length?`<button data-open-tab=compare>Compare versions</button>`:''}</div><div class=version-history-list>${current?render(current):''}${archives.map(render).join('')}</div></section>`}
function dossierOverviewHtml(d,id){const i=d.identity||{},r=d.researcher||{},cov=d.sourceCoverage||{},sec=d.secondarySecurity||{},eng=sec.engines||[],deep='See Journey',source=cov.sourceCodeAvailable?(cov.sourceToBinaryVerified?'Attributed + verified':'Attributed · build not verified'):'Artifact only',secondary=eng.length?`${eng.filter(e=>['complete','ready'].includes(String(e.status||'').toLowerCase())).length}/${eng.length} complete`:'Not recorded';return `<div class=dossier-overview><div class=dossier-hero><div class=dossier-summary><h3>What DeltaScope knows</h3><p class=plain-language>${esc(pluginPlainSummary(d))}</p><div class=case-summary><span class="pill ${sev(i.highest_severity)}"><b>${esc(i.highest_severity||'none')}</b> severity <button class=context-help data-help-topic=severity>?</button></span><span class=pill>${fmt((r.findings||[]).length)} findings</span><span class=pill>${fmt((d.networkEndpoints||[]).length)} endpoints</span><span class=pill>${fmt((r.capabilities||[]).length)} capabilities</span></div></div><div class=coverage-matrix>${coverageItem('Artifact',cov.artifactAvailable?'Inspected':'Not recorded',cov.artifactAvailable?'pass':'warn')}${coverageItem('Source',source,cov.sourceCodeAvailable?'pass':'warn')}${coverageItem('ClamAV / YARA',secondary,eng.length?'pass':'muted')}${coverageItem('Deep analysis',deep,'muted')}</div></div>${versionHistoryHtml(d)}<div class=research-box><h4>What stands out</h4>${renderSignals(d)}</div><div class=research-grid><div class="research-box developer-emphasis"><h4>Evidence coverage <button class=context-help data-help-topic=coverage>?</button></h4><div class=kv><b>Repository</b><span>${esc(cov.repository||'—')}</span><b>Commit/ref</b><span>${esc(cov.commit||cov.selectedRef||'—')}</span><b>Attribution</b><span>${cov.sourceCodeAvailable?`${esc(cov.attributionConfidence||0)}/100`:'not available'}</span><b>Source→artifact</b><span>${cov.sourceToBinaryVerified?'verified':cov.sourceCodeAvailable?'not verified':'not available'} <button class=context-help data-help-topic=source-binary>?</button></span></div></div><div class=research-box><h4>Observed capabilities <button class=context-help data-help-topic=capability>?</button></h4>${renderCapabilitiesList(r.capabilities||[])}</div></div><div class=explain-card><b>Useful next questions</b><div class=explain-actions><button data-question-local=why>Why this severity?</button><button data-open-tab=journey>How did it get here?</button><button data-open-tab=network>What connects to the internet?</button><button data-open-tab=compare>What changed?</button><button data-open-tab=relationships>What is it connected to?</button></div></div></div>`}
function researchCaseHtml(d,id){const i=d.identity||{},r=d.researcher||{},attr=d.sourceAttribution||{},sec=d.secondarySecurity||{},life=d.lifecycle||{},counts=r.findingCounts||{},priority=r.priority||'routine',cov=d.sourceCoverage||{};const matchCount=r.secondaryMatchCount??0,automation=r.automationLevel||i.automation_level||'none',hasSource=!!cov.sourceCodeAvailable,hasArtifact=!!cov.artifactAvailable;const reusable=r.artifactAnalysisReused?`reused artifact analysis · representative scan ${r.artifactAnalysisRepresentativeScanId||'?'}`:'fresh artifact analysis';const coverage=`<div class=case-coverage><span class="source-state ${hasArtifact?'ok':'warn'}"><b>ARTIFACT</b> ${hasArtifact?'scanned':'not recorded'}</span><span class="source-state ${hasSource?'ok':'warn'}"><b>SOURCE CODE</b> ${hasSource?'found':'not found'} <button class=context-help data-help-topic=source-attribution>?</button></span><span class="source-state ${hasSource?'muted':'warn'}"><b>SOURCE ↔ ARTIFACT</b> ${hasSource?(cov.sourceToBinaryVerified?'verified':`${esc(cov.attributionConfidence||0)}/100 · not verified`):'not available'}</span>${hasSource&&cov.coverageLabel?`<span class="source-state muted">${esc(cov.coverageLabel)}</span>`:''}</div>`;const quick=`<div class=case-summary><span class=pill><b class="priority priority-${esc(priority)}">${esc(priority)}</b> review</span><span class="pill ${sev(i.highest_severity)}"><b>${esc(i.highest_severity||'none')}</b> static</span><span class="pill ${matchCount?'fail':'pass'}"><b>${fmt(matchCount)}</b> AV/YARA matches</span><span class=pill>${esc(automation)} automation</span><span class=pill>${esc(life.state||i.lifecycle_state||'active')}</span></div>`;return `${coverage}${quick}<div class=research-tabs><button class="research-tab active" data-research-tab=overview>Overview</button><button class=research-tab data-research-tab=journey>Journey</button><button class=research-tab data-research-tab=findings>Findings</button><button class=research-tab data-research-tab=network>Network</button><button class=research-tab data-research-tab=code>Code & native</button><button class=research-tab data-research-tab=supply>Supply chain</button><button class=research-tab data-research-tab=relationships>Relationships</button><button class=research-tab data-research-tab=compare>Compare</button><button class="research-tab developer-only" data-research-tab=profile>Omega Profile</button><button class=research-tab data-research-tab=malware>Malware</button><button class="research-tab technical-detail" data-research-tab=triage>Technical details</button><button class="research-tab technical-detail" data-research-tab=evidence>Immutable evidence</button></div><section class="research-pane active" data-research-pane=overview>${dossierOverviewHtml(d,id)}</section><section class=research-pane data-research-pane=journey><div data-asset-journey="${esc(id)}"><span class=muted>Open Journey to reconstruct the evidence path for this plugin.</span></div></section><section class=research-pane data-research-pane=findings><h3>Security findings <button class=context-help data-help-topic=finding>?</button></h3><div class="muted small">Each finding includes a plain-language explanation and direct pivots to its rule/evidence.</div>${renderFindingCards(r.findings||[])}<div class=dataset-actions><button data-load-dataset=findings>Load immutable findings</button></div><div data-dataset-output=findings></div></section><section class=research-pane data-research-pane=network><h3>Network / endpoint evidence <button class=context-help data-help-topic=endpoint>?</button></h3>${renderEndpoints(d)}</section><section class=research-pane data-research-pane=code><h3>Code, native and automation behavior</h3><div class=research-grid><div class=research-box><h4>Component/native summary</h4>${renderComponents(d)}</div><div class=research-box><h4>Capabilities</h4>${renderCapabilitiesList(r.capabilities||[])}</div></div><div class=dataset-actions><button data-load-dataset=permissions>Permission evidence</button><button data-load-dataset=automation>Automation evidence</button><button data-load-dataset=imports>Imports / PInvoke</button><button data-load-dataset=reachability>Reachability</button></div><div data-dataset-output=permissions></div><div data-dataset-output=automation></div><div data-dataset-output=imports></div><div data-dataset-output=reachability></div><div class=research-box style="margin-top:10px"><h4>Managed-call search</h4><div class=toolbar style="margin:0"><input id=callQuery placeholder="Search calls: Process.Start, HttpClient, VirtualProtect…"><button data-search-calls>Search calls</button></div><div id=callsOutput class=small></div></div></section><section class=research-pane data-research-pane=supply>${developerSourceGuidance(d)}<h3>Supply chain & provenance <button class=context-help data-help-topic=source-attribution>?</button></h3><div class=research-grid><div class=research-box><h4>Evidence coverage</h4>${evidence(cov)}</div><div class=research-box><h4>Artifact identity</h4>${evidence(d.artifactIdentity||{})}</div><div class=research-box><h4>Source attribution</h4>${evidence(attr)}</div><div class=research-box><h4>Source provenance</h4>${evidence(d.sourceProvenance||{})}</div><div class=research-box><h4>Manifest observation</h4>${evidence(d.manifestObservation||{})}</div></div><h4>Source ↔ artifact comparison</h4>${Object.keys(d.sourceArtifactComparison||{}).length?evidence(d.sourceArtifactComparison):'<span class=muted>No explicit source↔artifact comparison record on this scan.</span>'}<h4>Package / extraction summary</h4>${evidence(d.package||{})}<h4>Known advisories (${d.advisories?.length||0})</h4>${d.advisories?.length?evidence(d.advisories):'<span class=muted>No frozen OSV matches on this variant.</span>'}</section><section class=research-pane data-research-pane=relationships><h3>Relationships</h3><div class="muted small">Graph the selected plugin outward to its artifact/source, components, endpoints and advisories; click relationship labels to pivot globally.</div><div data-asset-relationships="${esc(id)}" class=detail><span class=muted>Open this tab to load ecosystem relationships.</span></div></section><section class=research-pane data-research-pane=compare><h3>Version-to-version security comparison</h3><div data-version-compare="${esc(id)}"><span class=muted>Open Compare to load retained history.</span></div></section><section class="research-pane developer-only" data-research-pane=profile><div data-profile-builder></div></section><section class=research-pane data-research-pane=malware><h3>ClamAV & YARA <button class=context-help data-help-topic=yara>?</button></h3>${renderSecondary(sec)}</section><section class="research-pane technical-detail" data-research-pane=triage><h3>Technical case details</h3>${renderSignals(d)}<div class=research-grid><div class=research-box><h4>Evidence coverage</h4><div class=kv><b>Artifact</b><span>${hasArtifact?'Downloaded and statically analyzed':'Not recorded'}</span><b>Source code</b><span>${hasSource?'Available':'Not attributable / not found'}</span><b>Repository</b><span>${esc(cov.repository||'—')}</span><b>Commit</b><span>${esc(cov.commit||'—')}</span><b>Attribution</b><span>${hasSource?`${esc(cov.attributionConfidence||0)}/100 · ${esc(cov.coverageLabel||'')}`:'—'}</span><b>Source→binary</b><span>${cov.sourceToBinaryVerified?'verified':hasSource?'not verified':'not available'}</span></div></div><div class=research-box><h4>Artifact</h4>${kv(i,[['assembly_version','Version'],['artifact_sha256','SHA-256'],['artifact_url','Artifact URL'],['scanned_at_utc','Analyzed'],['scanner_version','SigmaScope'],['definitions_revision','Definitions'],['scan_queue_reason','Queue reason']])}<div class="muted small">${esc(reusable)}</div></div><div class=research-box><h4>Observed capabilities</h4>${renderCapabilitiesList(r.capabilities||[])}${r.capabilityIds?.length?`<div class="muted small">Canonical IDs (${esc(r.capabilityRegistryRevision||'registry unknown')}): ${esc(r.capabilityIds.join(', '))}</div>`:''}<h4 style="margin-top:10px">Automation capabilities</h4>${renderCapabilitiesList(r.automationCapabilities||[])}</div><div class=research-box><h4>Finding counts</h4>${evidence(counts)}</div><div class=research-box style="grid-column:1/-1"><h4>Behavior consistency · observed ↔ developer-declared</h4>${renderBehaviorConsistency(d)}</div><div class=research-box style="grid-column:1/-1"><h4>Developer profile · .omega/plugin.yaml</h4>${renderDeveloperProfile(d)}</div></div></section><section class="research-pane technical-detail" data-research-pane=evidence><h3>Immutable evidence <button class=context-help data-help-topic=observation>?</button></h3>${d.datasetError?`<div class="research-error"><b>Dataset manifest temporarily unavailable</b><div class="muted small">${esc(d.datasetError)}. Compact scan evidence remains valid; retry after refreshing Evidence-v2.</div></div>`:''}<h4>Analysis reference</h4>${evidence(d.analysis||{})}<h4>Observation contract</h4>${Object.keys(d.observations||{}).length?evidence(d.observations):'<span class=muted>Legacy evidence has no explicit observation contract yet.</span>'}<h4>Projection contract</h4>${Object.keys(d.projection||{}).length?evidence(d.projection):'<span class=muted>No explicit projection contract retained.</span>'}<h4>Dataset catalog</h4>${datasetSections(d,id)}<details><summary>Frozen scan provenance</summary><div>${evidence(d.scanProvenance||{})}</div></details><details><summary>Lifecycle history (${d.lifecycleHistory?.length||0})</summary><div>${evidence(d.lifecycleHistory||[])}</div></details><details><summary>Full source evidence</summary><div>${evidence(d.sourceEvidence||{})}</div></details></section>`}
async function loadDetail(id,openTab='overview'){$('detailTitle').textContent=`Variant ${id}`;$('detailMeta').textContent='loading plugin dossier…';$('pluginDetail').innerHTML='<span class=muted>Loading integrity-checked Evidence-v2 dossier…</span>';try{const d=await api('/api/plugin?variant_id='+id),i=d.identity||{};currentPluginDetail=d;updateSubject(d);$('detailTitle').textContent=i.canonical_name||i.name||i.internal_name||`Variant ${id}`;$('detailMeta').textContent=`variant ${id} · ${esc(d.snapshotKind||'current')} · scan ${i.scan_id||'none'}${d.onlineSnapshotRefreshed?' · evidence snapshot refreshed':''}`;$('pluginDetail').innerHTML=researchCaseHtml(d,id);wireResearchTabs(id);wireContextHelp($('pluginDetail'));activateResearchTab(openTab||'overview');$('pluginDetail').querySelectorAll('[data-question-local]').forEach(x=>x.addEventListener('click',()=>runSubjectQuestion(x.dataset.questionLocal)));toniSelection();if(d.onlineSnapshotRefreshed){try{applySourceStatus(await api('/api/source'));await loadPlugins()}catch(e){console.warn('post-refresh list update failed',e)}}}catch(e){$('pluginDetail').innerHTML=`<div class=research-error><b>Could not open plugin dossier</b><div style="margin-top:6px">${esc(e.message)}</div><div class="muted small" style="margin-top:8px">DeltaScope kept the integrity check fail-closed. If Evidence-v2 published while you were browsing, press New evidence · Refresh and retry.</div></div>`;$('detailMeta').textContent='dossier load failed';toniSay(`I could not open variant ${id}: ${e.message}. DeltaScope did not bypass the evidence hash check.`)}}
async function loadCalls(id){const q=$('callQuery')?.value||'';const rows=await api('/api/calls?variant_id='+id+'&q='+encodeURIComponent(q));$('callsOutput').innerHTML=`<div class=muted>${rows.length} rows</div>`+evidence(rows)}
async function runAudit(){toniSay('I’m recomputing the read-only consistency audit. This verifies that published conclusions reproduce from their evidence; it does not modify the evidence.');$('detailTitle').textContent='Global consistency audit';$('detailMeta').textContent='running…';$('pluginDetail').innerHTML='<span class=muted>Recomputing current conclusions…</span>';try{const a=await api('/api/audit');$('detailMeta').textContent=`${a.counts.fail} fail · ${a.counts.warn} warn`;$('pluginDetail').innerHTML=`<div class=cards><div class=card><div class="n fail">${a.counts.fail}</div><div class=muted>Failures</div></div><div class=card><div class="n warn">${a.counts.warn}</div><div class=muted>Warnings</div></div><div class=card><div class="n pass">${a.counts.pass}</div><div class=muted>Passed global checks</div></div></div>`+a.items.map(x=>`<div class="auditrow ${x.status}"><b>${esc(x.status.toUpperCase())} · ${esc(x.title)}</b><div class=small>${esc(x.code)} ${x.plugin?'· '+esc(x.plugin):''}</div><div class=muted>${esc(x.detail)}</div></div>`).join('')}catch(e){$('pluginDetail').innerHTML=`<span class=fail>${esc(e.message)}</span>`}}
function renderTableList(){const needle=$('tableSearch').value.trim().toLowerCase();let last='';$('tableList').innerHTML=tables.map((t,i)=>({t,i})).filter(x=>!needle||x.t.name.toLowerCase().includes(needle)||x.t.label.toLowerCase().includes(needle)||x.t.category.toLowerCase().includes(needle)).map(({t,i})=>{let h='';if(t.category!==last){last=t.category;h=`<div class=table-group>${esc(t.category)}</div>`}return h+`<button class="table-button ${currentTable?.name===t.name?'active':''}" data-table-index="${i}">${esc(t.label)}<div class="muted small">${esc(t.name)} · ${t.columnCount} columns</div></button>`}).join('');$('tableList').querySelectorAll('[data-table-index]').forEach(x=>x.addEventListener('click',()=>openTable(tables[Number(x.dataset.tableIndex)].name)))}
async function openTable(name,filterColumn='',filterValue='',offset=0,metric=''){$('rawEvidence').open=true;const params=new URLSearchParams({name,limit:'100',offset:String(offset)});if(filterColumn){params.set('column',filterColumn);params.set('value',String(filterValue))}if(metric)currentMetric={...(currentMetric||{}),metric};else if(offset===0)currentMetric=null;currentTable=await api('/api/table?'+params.toString());currentRows=currentTable.rows;currentFkLinks=[];$('tableTitle').textContent=currentTable.label;const range=currentRows.length?`rows ${currentTable.offset+1}–${currentTable.offset+currentRows.length}`:'0 rows';const metricText=currentMetric?.metric?` · headline total = sum of ${currentMetric.metric}`:'';$('tableSubtitle').textContent=`${currentTable.name} · ${range}${currentTable.hasMore?' · more available':''}${metricText}`;$('tablePrev').disabled=currentTable.offset<=0;$('tableNext').disabled=!currentTable.hasMore;$('rowTitle').textContent='Row inspector';$('rowDetail').innerHTML='<span class=muted>Click a row to inspect raw fields and follow evidence relationships.</span>';renderTableList();renderTableFilter();renderTableGrid();$('tableTitle').scrollIntoView({behavior:'smooth',block:'nearest'})}
function renderTableFilter(){if(!currentTable?.filter){$('tableFilterBar').style.display='none';$('tableFilterBar').innerHTML='';return}$('tableFilterBar').style.display='block';const value=currentTable.filter.value==='__positive__'?'> 0':'= '+currentTable.filter.value;$('tableFilterBar').innerHTML=`<span class=table-filter><span class=pill>${esc(currentTable.filter.column)} ${esc(value)}</span><button id="clearTableFilter">Clear filter</button></span>`;$('clearTableFilter').addEventListener('click',()=>openTable(currentTable.name))}
function renderTableGrid(){if(!currentTable)return;const cols=currentTable.columns.map(c=>c.name);if(!currentRows.length){$('tableGrid').innerHTML='<div class=empty>No rows in this page.</div>';return}$('tableGrid').innerHTML=`<table><thead><tr>${cols.map(c=>`<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${currentRows.map((r,i)=>`<tr class=click data-row-index="${i}">${cols.map(c=>`<td title="${esc(r[c])}">${esc(formatCell(r[c]))}</td>`).join('')}</tr>`).join('')}</tbody></table>`;$('tableGrid').querySelectorAll('[data-row-index]').forEach(x=>x.addEventListener('click',()=>inspectRow(Number(x.dataset.rowIndex))))}
function formatCell(v){if(v==null)return'';const s=typeof v==='object'?JSON.stringify(v):String(v);return s.length>180?s.slice(0,177)+'…':s}
function inspectRow(index){const row=currentRows[index];if(!row)return;const fkMap={};(currentTable.foreignKeys||[]).forEach(f=>{fkMap[f.from]=f});currentFkLinks=[];const variant=Number(row.variant_id||row.source_variant_id||row.variantId||0);const snapshotPath=String(row.variantPath||'');const manifestPath=String(row.manifestPath||'');const top=(variant?`<button id="openRowPlugin">Open research case for variant ${variant}</button>`:'')+(snapshotPath?` <button id="openRowSnapshot">Open this snapshot</button>`:'')+(manifestPath?` <button id="openAnalysisManifest">Open analysis manifest</button>`:'');const body=Object.entries(row).map(([k,v])=>{const fk=fkMap[k];if(fk&&v!=null){const linkIndex=currentFkLinks.push({table:fk.table,column:fk.to,value:v})-1;return `<b>${esc(k)}</b><span><button class=linkbutton data-fk-link="${linkIndex}">${esc(formatCell(v))} → ${esc(fk.table)}.${esc(fk.to)}</button></span>`}return `<b>${esc(k)}</b><span>${typeof v==='object'?evidence(v):looksJson(v)?evidenceJsonInline(v):esc(formatCell(v))}</span>`}).join('');$('rowTitle').textContent=`${currentTable.label} · row ${currentTable.offset+index+1}`;$('rowDetail').innerHTML=top+`<div class=kv>${body}</div>`;$('rowDetail').querySelectorAll('[data-fk-link]').forEach(x=>x.addEventListener('click',()=>{const f=currentFkLinks[Number(x.dataset.fkLink)];openTable(f.table,f.column,f.value)}));const b=$('openRowPlugin');if(b)b.addEventListener('click',()=>loadDetail(variant));const sb=$('openRowSnapshot');if(sb)sb.addEventListener('click',()=>loadSnapshot(snapshotPath));const ab=$('openAnalysisManifest');if(ab)ab.addEventListener('click',()=>loadAnalysisManifest(manifestPath,row))}
async function loadAnalysisManifest(path,row={}){const d=await api('/api/analysis-manifest?path='+encodeURIComponent(path));$('rowTitle').textContent='Immutable analysis manifest';$('rowDetail').innerHTML=`<div class=metric-note><span class=pill>${esc(row.analysisId||d.analysisId||'analysis')}</span><span class=pill>${esc(row.artifactSha256||d.artifactSha256||'')}</span></div><div class=analysis-manifest>${evidence(d)}</div>`;toniSay(`Opened immutable analysis ${(row.analysisId||d.analysisId||'').slice(0,12)}. Its manifest enumerates the exact evidence datasets and hashes stored for artifact ${(row.artifactSha256||d.artifactSha256||'').slice(0,12)}. This record is read-only.`)}
async function loadSnapshot(path){try{const d=await api('/api/snapshot?path='+encodeURIComponent(path));const i=d.identity||{},id=Number(i.variant_id||0);currentPluginDetail=d;updateSubject(d);$('detailTitle').textContent=(i.canonical_name||i.name||i.internal_name||'Snapshot')+' · '+(d.snapshotKind||'snapshot');$('detailMeta').textContent=`variant ${id||'—'} · retained read-only snapshot${d.onlineSnapshotRefreshed?' · evidence snapshot refreshed':''}`;$('pluginDetail').innerHTML=researchCaseHtml(d,id);wireResearchTabs(id);wireContextHelp($('pluginDetail'));toniSelection()}catch(e){$('pluginDetail').innerHTML=`<div class=research-error><b>Could not open retained snapshot</b><div>${esc(e.message)}</div></div>`}}
function looksJson(v){if(typeof v!=='string')return false;const s=v.trim();return (s.startsWith('{')&&s.endsWith('}'))||(s.startsWith('[')&&s.endsWith(']'))}
function evidenceJsonInline(v){try{return `<span class=code style="display:block;max-height:180px">${esc(JSON.stringify(JSON.parse(v),null,2))}</span>`}catch{return esc(formatCell(v))}}
async function runSql(){try{const r=await api('/api/sql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:$('sqlText').value})});$('sqlOutput').innerHTML=`<table><thead><tr>${r.columns.map(c=>`<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${r.rows.map(row=>`<tr>${row.map(v=>`<td>${esc(typeof v==='object'?JSON.stringify(v):v)}</td>`).join('')}</tr>`).join('')}</tbody></table>`}catch(e){$('sqlOutput').innerHTML=`<span class=fail>${esc(e.message)}</span>`}}

let ruleLabReference=null;
let ruleEditorIntelligence=null,ruleEditorTimer=null,ruleEditorRequest=0,ruleCompletionItems=[],ruleCompletionIndex=0;
function ruleEditorCursor(){const el=$('ruleYaml'),pos=el.selectionStart||0,before=el.value.slice(0,pos),parts=before.split('\n');return{line:parts.length,column:(parts[parts.length-1]||'').length+1,offset:pos}}
function ruleEditorGoto(line,column=1){const el=$('ruleYaml'),lines=el.value.split('\n');line=Math.max(1,Math.min(lines.length,line||1));column=Math.max(1,Math.min((lines[line-1]||'').length+1,column||1));let pos=0;for(let i=0;i<line-1;i++)pos+=lines[i].length+1;pos+=column-1;el.focus();el.setSelectionRange(pos,pos);renderRuleEditorCursor();scheduleRuleIntelligence(false,0)}
function yamlCommentIndex(raw){let quote='',escp=false;for(let i=0;i<raw.length;i++){const ch=raw[i];if(escp){escp=false;continue}if(ch==='\\'&&quote==='"'){escp=true;continue}if((ch==='"'||ch==="'")&&!quote){quote=ch;continue}if(ch===quote){quote='';continue}if(ch==='#'&&!quote)return i}return-1}
function ruleYamlValueHtml(value,key=''){const lead=(value.match(/^\s*/)||[''])[0],body=value.slice(lead.length);if(!body)return esc(value);let cls='yaml-string';if(key==='schema'||body.startsWith('omega.sigmascope.'))cls='yaml-schema';else if(/^(true|false|null)(\s|$)/i.test(body))cls='yaml-bool';else if(/^-?\d+(?:\.\d+)?(\s|$)/.test(body))cls='yaml-number';else if(/^[\[\]{},]/.test(body))cls='yaml-punct';return esc(lead)+`<span class="${cls}">${esc(body)}</span>`}
function ruleYamlLineHtml(raw){const ci=yamlCommentIndex(raw),code=ci>=0?raw.slice(0,ci):raw,comment=ci>=0?raw.slice(ci):'',m=code.match(/^(\s*(?:-\s*)?)([A-Za-z0-9_.\[\]-]+)(\s*:)(.*)$/);let out='';if(m){const operators=new Set([...(ruleLabReference?.engine?.operators||[]),...(ruleLabReference?.engine?.conditionOperators||[])]),cls=operators.has(m[2])?'yaml-operator':'yaml-key';out=esc(m[1])+`<span class="${cls}">${esc(m[2])}</span><span class="yaml-punct">${esc(m[3])}</span>`+ruleYamlValueHtml(m[4],m[2])}else out=esc(code);if(comment)out+=`<span class="yaml-comment">${esc(comment)}</span>`;return out||' '}
function renderRuleEditorText(){const el=$('ruleYaml'),lines=el.value.split('\n'),bad=new Map();for(const d of ruleEditorIntelligence?.diagnostics||[]){if((d.severity||'')==='error')bad.set(Number(d.line||1),'diag-line');else if((d.severity||'')==='warning')bad.set(Number(d.line||1),'warn-line')}$('ruleHighlight').innerHTML=lines.map(ruleYamlLineHtml).join('\n')+'\n';$('ruleGutter').innerHTML=lines.map((_,i)=>`<span class="${bad.get(i+1)||''}">${i+1}</span>`).join('\n');syncRuleEditorScroll();renderRuleEditorCursor()}
function syncRuleEditorScroll(){const el=$('ruleYaml');$('ruleHighlight').scrollTop=el.scrollTop;$('ruleHighlight').scrollLeft=el.scrollLeft;$('ruleGutter').scrollTop=el.scrollTop}
function renderRuleEditorCursor(){const c=ruleEditorCursor();$('ruleCursor').textContent=`Ln ${c.line}, Col ${c.column}`}
function hideRuleCompletions(){$('ruleCompletionPopup').hidden=true;ruleCompletionItems=[];ruleCompletionIndex=0}
function positionRuleCompletions(){const popup=$('ruleCompletionPopup'),el=$('ruleYaml'),c=ruleEditorCursor(),wrap=popup.parentElement,lineH=20.15,charW=7.82;let top=(c.line-1)*lineH-el.scrollTop+35,left=(c.column-1)*charW-el.scrollLeft+15;top=Math.max(8,Math.min((wrap.clientHeight||430)-160,top));left=Math.max(8,Math.min((wrap.clientWidth||600)-330,left));popup.style.top=top+'px';popup.style.left=left+'px'}
function renderRuleCompletionPopup(items){ruleCompletionItems=items||[];ruleCompletionIndex=Math.min(ruleCompletionIndex,Math.max(0,ruleCompletionItems.length-1));const p=$('ruleCompletionPopup');if(!ruleCompletionItems.length){hideRuleCompletions();return}p.innerHTML=ruleCompletionItems.slice(0,40).map((x,i)=>`<div class="rule-completion-item ${i===ruleCompletionIndex?'active':''}" data-rule-completion="${i}"><div class=rule-completion-label>${esc(x.label)}</div><div class=rule-completion-kind>${esc(x.kind||'value')}</div>${x.detail?`<div class=rule-completion-detail>${esc(x.detail)}</div>`:''}</div>`).join('');p.hidden=false;positionRuleCompletions();p.querySelectorAll('[data-rule-completion]').forEach(x=>x.addEventListener('mousedown',e=>{e.preventDefault();applyRuleCompletion(Number(x.dataset.ruleCompletion))}))}
function applyRuleCompletion(index=ruleCompletionIndex){const item=ruleCompletionItems[index];if(!item)return;const el=$('ruleYaml'),intel=ruleEditorIntelligence,c=intel?.cursor||ruleEditorCursor(),lines=el.value.split('\n'),line=Math.max(1,Math.min(lines.length,c.line||1)),lineStart=lines.slice(0,line-1).reduce((n,x)=>n+x.length+1,0),start=lineStart+Math.max(0,(c.replaceStartColumn||c.column||1)-1),end=lineStart+Math.max(0,(c.replaceEndColumn||c.column||1)-1),baseIndent=(lines[line-1].match(/^\s*/)||[''])[0];let insert=String(item.insertText??item.label??'');insert=insert.replace(/\n/g,'\n'+baseIndent);captureRuleEditorHistory();el.value=el.value.slice(0,start)+insert+el.value.slice(end);ruleHistoryCurrent=el.value;const pos=start+insert.length;el.setSelectionRange(pos,pos);hideRuleCompletions();renderRuleEditorText();scheduleRuleIntelligence(false,0);ruleEditorUserChanged();el.focus()}
function applyRuleLintSuggestion(d){if(!d?.suggestion)return;const el=$('ruleYaml'),lines=el.value.split('\n'),idx=Math.max(0,Math.min(lines.length-1,Number(d.line||1)-1)),raw=lines[idx],msg=String(d.message||'');if(/unknown operator|unknown field/.test(msg))lines[idx]=raw.replace(/^(\s*)([^:#]+)(\s*:)/,(_,a,_b,c)=>a+d.suggestion+c);else if(/collection/.test(msg))lines[idx]=raw.replace(/(collection\s*:\s*)([^#\s]+)/,(_,a)=>a+d.suggestion);else return;captureRuleEditorHistory();el.value=lines.join('\n');ruleHistoryCurrent=el.value;renderRuleEditorText();scheduleRuleIntelligence(false,0);ruleEditorUserChanged();ruleEditorGoto(idx+1,Math.min(lines[idx].length+1,Number(d.column||1)))}
function ruleSymbolButton(item,kind){return `<button class=rule-symbol data-rule-line="${Number(item.line||1)}" title="${esc(kind)}">${esc(item.name||'?')}</button>`}
function renderRuleEditorIntelligence(r){ruleEditorIntelligence=r;const errors=(r.diagnostics||[]).filter(x=>x.severity==='error'),health=$('ruleEditorHealth');health.className='editor-chip '+(errors.length?'error':'clean');health.textContent=errors.length?`${errors.length} ERROR${errors.length===1?'':'S'}`:'CLEAN';const m=r.metrics||{};$('ruleEditorMetrics').textContent=`${fmt(m.bytes||0)} B · ${fmt(m.lines||1)} lines · ${fmt(m.rules||0)} rules · ${fmt(m.selectors||0)} selectors`;$('ruleEditorRevision').textContent=r.compile?.ruleSetRevision||'not compiled';const h=r.hover||{},help=h.documentation?`<span class=rule-context-token>${esc(h.token||h.kind||'context')}</span> · ${esc(h.documentation)}`:`<span class=rule-editor-hint>SRL understands registered collections, typed fields, selectors, facts, conditions and emitted findings. Ctrl/Cmd+Space asks for context-aware completion.</span>`;$('ruleContextHelp').innerHTML=help;const suggestions=(r.completions||[]).slice(0,10);$('ruleSuggestions').innerHTML=suggestions.map((x,i)=>`<button class=rule-suggestion-chip data-rule-suggest="${i}" title="${esc(x.documentation||x.detail||'')}">${esc(x.label)} <span class=muted>${esc(x.kind||'')}</span></button>`).join('');$('ruleSuggestions').querySelectorAll('[data-rule-suggest]').forEach(x=>x.addEventListener('click',()=>{ruleCompletionItems=suggestions;applyRuleCompletion(Number(x.dataset.ruleSuggest))}));const s=r.symbols||{},outline=[...(s.rules||[]).map(x=>[x,'rule']),...(s.selectors||[]).map(x=>[x,'selector']),...(s.facts||[]).map(x=>[x,'fact']),...(s.findings||[]).map(x=>[x,'finding'])];$('ruleOutline').innerHTML=outline.length?outline.map(([x,k])=>ruleSymbolButton(x,k)).join(''):'<span class=rule-editor-hint>Symbols appear as the document becomes structurally valid.</span>';$('ruleOutline').querySelectorAll('[data-rule-line]').forEach(x=>x.addEventListener('click',()=>ruleEditorGoto(Number(x.dataset.ruleLine),1)));const edges=r.graph?.edges||[];$('ruleFlow').innerHTML=edges.length?edges.map(e=>`<span class=rule-flow-edge><span>${esc(e.from)}</span><span class=rule-flow-arrow>→</span><span>${esc(e.to)}</span><span class=muted>${esc(e.kind||'')}</span></span>`).join(''):'<span class=rule-editor-hint>No semantic edges yet.</span>';$('ruleInlineDiagnostics').innerHTML=(r.diagnostics||[]).slice(0,8).map((d,i)=>`<div class="rule-inline-diagnostic ${esc(d.severity||'info')}" data-rule-diag-line="${Number(d.line||1)}"><span class=where>L${Number(d.line||1)}:${Number(d.column||1)}</span><span><b>${esc((d.stage||'lint').toUpperCase())}</b> · ${esc(d.message||'')}${d.suggestion?` <button class=rule-suggestion-chip data-rule-fix="${i}">Use ${esc(d.suggestion)}</button>`:''}</span></div>`).join('');$('ruleInlineDiagnostics').querySelectorAll('[data-rule-diag-line]').forEach(x=>x.addEventListener('click',e=>{if(e.target.closest('[data-rule-fix]'))return;ruleEditorGoto(Number(x.dataset.ruleDiagLine),1)}));$('ruleInlineDiagnostics').querySelectorAll('[data-rule-fix]').forEach(x=>x.addEventListener('click',e=>{e.stopPropagation();const d=(r.diagnostics||[])[Number(x.dataset.ruleFix)];applyRuleLintSuggestion(d)}));renderRuleEditorText()}
async function refreshRuleIntelligence(showCompletion=false){const seq=++ruleEditorRequest,c=ruleEditorCursor(),health=$('ruleEditorHealth');health.className='editor-chip busy';health.textContent='ANALYZING';try{const r=await api('/api/rule-lab/intelligence',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:$('ruleYaml').value,line:c.line,column:c.column})});if(seq!==ruleEditorRequest)return;renderRuleEditorIntelligence(r);if(showCompletion)renderRuleCompletionPopup(r.completions||[])}catch(e){if(seq!==ruleEditorRequest)return;health.className='editor-chip error';health.textContent='LINT OFFLINE';$('ruleInlineDiagnostics').innerHTML=`<div class="rule-inline-diagnostic error"><span class=where>API</span><span>${esc(e.message)}</span></div>`}}
function scheduleRuleIntelligence(showCompletion=false,delay=220){clearTimeout(ruleEditorTimer);ruleEditorTimer=setTimeout(()=>refreshRuleIntelligence(showCompletion),delay)}
async function formatRuleCandidate(){try{const r=await api('/api/rule-lab/format',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:$('ruleYaml').value})});if(!r.ok){$('ruleLabStatus').innerHTML=ruleDiagnostics(r.diagnostics);renderRuleEditorIntelligence({...ruleEditorIntelligence,diagnostics:r.diagnostics||[]});return}setRuleEditorValue(r.yaml||$('ruleYaml').value,true);ruleEditorUserChanged();$('ruleLabStatus').innerHTML='<div class=pass>Rule formatted canonically with SRL Core.</div>'}catch(e){$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`}}
function resetRuleEditorHistory(value){ruleUndoStack=[];ruleRedoStack=[];ruleHistoryCurrent=String(value||'')}
function captureRuleEditorHistory(){if(ruleHistoryApplying||!currentWorkspaceRule?.editable)return;const value=$('ruleYaml').value;if(ruleUndoStack[ruleUndoStack.length-1]===value)return;ruleUndoStack.push(value);if(ruleUndoStack.length>200)ruleUndoStack.shift();ruleRedoStack=[]}
function ruleEditorUndo(){if(!currentWorkspaceRule?.editable||!ruleUndoStack.length)return false;const el=$('ruleYaml'),current=el.value,previous=ruleUndoStack.pop();ruleRedoStack.push(current);ruleHistoryApplying=true;el.value=previous;ruleHistoryCurrent=previous;ruleHistoryApplying=false;renderRuleEditorText();scheduleRuleIntelligence(false,0);ruleEditorUserChanged();el.focus();return true}
function ruleEditorRedo(){if(!currentWorkspaceRule?.editable||!ruleRedoStack.length)return false;const el=$('ruleYaml'),current=el.value,next=ruleRedoStack.pop();ruleUndoStack.push(current);ruleHistoryApplying=true;el.value=next;ruleHistoryCurrent=next;ruleHistoryApplying=false;renderRuleEditorText();scheduleRuleIntelligence(false,0);ruleEditorUserChanged();el.focus();return true}
function setRuleEditorValue(value,preserveHistory=false){const next=String(value||'');if(preserveHistory&&currentWorkspaceRule?.editable){const el=$('ruleYaml');if(el.value!==next){ruleUndoStack.push(el.value);if(ruleUndoStack.length>200)ruleUndoStack.shift();ruleRedoStack=[]}}$('ruleYaml').value=next;ruleHistoryCurrent=next;if(!preserveHistory)resetRuleEditorHistory(next);hideRuleCompletions();renderRuleEditorText();scheduleRuleIntelligence(false,0)}
function ruleEditorUserChanged(){if(!currentWorkspaceRule?.editable)return;currentVisualGraph=null;markRuleWorkspaceDirty(true);$('ruleVisualStatus').textContent='YAML changed · reopen Visual to rebuild graph'}
function insertRuleIndent(outdent=false){const el=$('ruleYaml'),start=el.selectionStart,end=el.selectionEnd,value=el.value;captureRuleEditorHistory();if(start!==end&&value.slice(start,end).includes('\n')){const first=value.lastIndexOf('\n',start-1)+1,last=value.indexOf('\n',end);const blockEnd=last<0?value.length:last,block=value.slice(first,blockEnd),lines=block.split('\n'),changed=lines.map(x=>outdent?x.replace(/^ {1,2}/,''):'  '+x).join('\n');el.value=value.slice(0,first)+changed+value.slice(blockEnd);el.setSelectionRange(first,first+changed.length)}else if(outdent){const lineStart=value.lastIndexOf('\n',start-1)+1,prefix=value.slice(lineStart,start),remove=(prefix.match(/^ {1,2}/)||[''])[0].length;if(remove){el.value=value.slice(0,lineStart)+value.slice(lineStart+remove);el.setSelectionRange(Math.max(lineStart,start-remove),Math.max(lineStart,start-remove))}}else{el.value=value.slice(0,start)+'  '+value.slice(end);el.setSelectionRange(start+2,start+2)}ruleHistoryCurrent=el.value;renderRuleEditorText();scheduleRuleIntelligence(false,80);ruleEditorUserChanged()}
function wireRuleSmartEditor(){const el=$('ruleYaml');el.addEventListener('scroll',syncRuleEditorScroll);el.addEventListener('beforeinput',()=>captureRuleEditorHistory());el.addEventListener('input',e=>{ruleHistoryCurrent=el.value;renderRuleEditorText();scheduleRuleIntelligence(e.data===':',180);ruleEditorUserChanged()});['click','keyup','select'].forEach(name=>el.addEventListener(name,()=>{renderRuleEditorCursor();scheduleRuleIntelligence(false,180)}));el.addEventListener('keydown',e=>{const mod=e.ctrlKey||e.metaKey,key=e.key.toLowerCase();if(mod&&key==='z'){e.preventDefault();if(e.shiftKey)ruleEditorRedo();else ruleEditorUndo();return}if(mod&&key==='y'){e.preventDefault();ruleEditorRedo();return}if(mod&&e.code==='Space'){e.preventDefault();scheduleRuleIntelligence(true,0);return}if(mod&&e.key==='Enter'){e.preventDefault();ruleCompileCandidate();return}if(e.shiftKey&&e.altKey&&e.key.toLowerCase()==='f'){e.preventDefault();formatRuleCandidate();return}if(!$('ruleCompletionPopup').hidden){if(e.key==='ArrowDown'){e.preventDefault();ruleCompletionIndex=Math.min(ruleCompletionItems.length-1,ruleCompletionIndex+1);renderRuleCompletionPopup(ruleCompletionItems);return}if(e.key==='ArrowUp'){e.preventDefault();ruleCompletionIndex=Math.max(0,ruleCompletionIndex-1);renderRuleCompletionPopup(ruleCompletionItems);return}if(e.key==='Enter'||e.key==='Tab'){e.preventDefault();applyRuleCompletion();return}if(e.key==='Escape'){e.preventDefault();hideRuleCompletions();return}}if(e.key==='Tab'){e.preventDefault();insertRuleIndent(e.shiftKey)}});$('ruleEditorComplete').addEventListener('click',()=>scheduleRuleIntelligence(true,0));$('ruleFormat').addEventListener('click',formatRuleCandidate);$('ruleSpellcheck').addEventListener('change',e=>{el.spellcheck=!!e.target.checked;el.setAttribute('spellcheck',e.target.checked?'true':'false');el.focus()})}
function ruleVariantId(){const i=currentPluginDetail?.identity||{};return Number(i.variant_id||i.variantId||0)}
function ruleDiagnostics(items){if(!Array.isArray(items)||!items.length)return '<div class="pass">No compiler diagnostics.</div>';return items.map(d=>`<div class="rule-lab-diag ${esc(d.severity||'info')}"><b>${esc((d.stage||'diagnostic').toUpperCase())}</b> · ${esc(d.message||'')}</div>`).join('')}
function ruleSummaryCards(values){return `<div class="rule-lab-summary">${values.map(([l,v])=>`<div class=card><div class=n>${esc(v)}</div><div class=muted>${esc(l)}</div></div>`).join('')}</div>`}
function ruleCompileView(r){$('ruleLabStatus').innerHTML=ruleDiagnostics(r.diagnostics);if(!r.ok){$('ruleLabResult').innerHTML='';return}$('ruleLabResult').innerHTML=ruleSummaryCards([['Rules',(r.ruleIds||[]).length],['Collections',(r.requiredCollections||[]).length],['Findings',(r.findingIds||[]).length],['Write-back','OFF']])+`<div class=kv><b>Ruleset revision</b><span>${esc(r.ruleSetRevision||'')}</span><b>Rule IDs</b><span>${esc((r.ruleIds||[]).join(', ')||'—')}</span><b>Required observations</b><span>${esc((r.requiredCollections||[]).join(', ')||'none')}</span></div>`}
async function ruleCompileCandidate(){try{const r=await api('/api/rule-lab/compile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:$('ruleYaml').value})});ruleCompileView(r);return r}catch(e){$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`;return null}}
function ruleDiffView(d){if(!d)return'';const clean=d.clean;return `<div class=section><h3>Baseline vs candidate</h3>${ruleSummaryCards([['Added',(d.added||[]).length],['Removed',(d.removed||[]).length],['Changed',(d.changed||[]).length],['Parity',clean?'CLEAN':'DIFF']])}${clean?'<div class=pass>Candidate finding payload matches the retained baseline for the candidate finding IDs.</div>':`<details open><summary>Finding diff</summary><div>${evidence({added:d.added||[],removed:d.removed||[],changed:d.changed||[]})}</div></details>`}</div>`}
function ruleExplanationView(x){if(!x)return'';const rules=(x.rules||[]).map(r=>`<details ${r.matched?'open':''}><summary><span class="${r.matched?'pass':'muted'}">${r.matched?'MATCH':'NO MATCH'}</span> · ${esc(r.ruleId)} · ${esc(r.kind)}</summary><div>${r.emittedFact?`<div class=pass>Emitted fact: ${esc(r.emittedFact)}</div>`:''}${r.findingId?`<div class=warn>Finding: ${esc(r.findingId)}</div>`:''}${r.analysisRequest?`<div class=warn>Deep scan request: ${esc(r.analysisRequest.profile||'')} · ${esc(r.analysisRequest.depth||'standard')} · ${esc(r.analysisRequest.reason||'')}</div>`:''}${(r.selectors||[]).map(s=>`<div class="selector-card ${s.matched?'matched':''}"><b>${esc(s.name)}</b> · ${esc(s.type)}${s.collection?' · '+esc(s.collection):''}<div class=muted>${s.matched?'matched':'not matched'} · ${fmt(s.matchCount)} row/fact matches${s.truncated?' · evidence truncated':''}</div>${(s.matchedFacts||[]).length?`<div>Facts: ${esc(s.matchedFacts.join(', '))}</div>`:''}${(s.evidenceRows||[]).length?evidence(s.evidenceRows):''}</div>`).join('')}<details><summary>Compiled condition</summary><div>${evidence(r.condition||{})}</div></details></div></details>`).join('');return `<div class=section><h3>Deterministic selector explanation</h3><div class=muted small>Facts: ${esc((x.facts||[]).join(', ')||'none')}</div>${rules||'<div class=empty>No rule evaluations.</div>'}</div>`}
async function ruleEvaluateSelected(){const id=ruleVariantId();if(!id){$('ruleLabStatus').innerHTML='<div class="rule-lab-diag error">Select a plugin first.</div>';return}try{const r=await api('/api/rule-lab/evaluate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:$('ruleYaml').value,variantId:id})});$('ruleLabStatus').innerHTML=ruleDiagnostics((r.compile||{}).diagnostics||r.diagnostics);if(!r.ok){$('ruleLabResult').innerHTML=evidence(r);return}const ev=r.evaluation||{},audit=ev.replayAudit||{};$('ruleLabResult').innerHTML=`<div class=section><h3>${esc(r.plugin?.name||'Selected plugin')} · variant ${id}</h3>${ruleSummaryCards([['Evaluated',ev.evaluated?'YES':'NO'],['Facts',(ev.facts||[]).length],['Findings',(ev.findings||[]).length],['Replay',audit.reusableWithoutRescan?'READY':'NEEDS DATA']])}<div class=muted small>${esc(audit.reason||'Retained observations satisfy the candidate requirements.')}</div></div>`+ruleDiffView(r.baselineDiff)+ruleExplanationView(r.explanation)}catch(e){$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`}}
function parseRuleIdsInput(){return $('ruleVariantIds').value.split(',').map(x=>Number(x.trim())).filter(x=>Number.isInteger(x)&&x>0)}
function ruleReplayView(r){if(!r.ok){$('ruleLabResult').innerHTML=evidence(r);return}$('ruleLabResult').innerHTML=ruleSummaryCards([['Checked',r.variantsChecked],['Evaluated',r.evaluatedVariants],['Rescan',r.rescanRequiredVariants],['Parity',r.baselineParity?'CLEAN':'DIFF']])+`<div class=kv><b>Added findings</b><span>${fmt(r.diffCounts?.added||0)}</span><b>Removed findings</b><span>${fmt(r.diffCounts?.removed||0)}</span><b>Changed findings</b><span>${fmt(r.diffCounts?.changed||0)}</span><b>Production write-back</b><span>disabled</span></div><details><summary>Variant replay details</summary><div>${evidence((r.variants||[]).map(v=>({variantId:v.variantId,plugin:v.plugin,ok:v.ok,evaluated:v.evaluation?.evaluated,replayAudit:v.evaluation?.replayAudit,diff:v.baselineDiff})))}</div></details>`}
async function ruleReplay(corpus){try{let ids=corpus?[]:parseRuleIdsInput();if(!corpus&&!ids.length){const id=ruleVariantId();if(id)ids=[id]}if(!corpus&&!ids.length)throw new Error('Enter variant IDs or select a plugin.');const limit=Math.max(1,Math.min(1000,Number($('ruleReplayLimit').value||250)));$('ruleLabStatus').textContent=corpus?'Running bounded corpus replay…':'Running selected-set replay…';const r=await api('/api/rule-lab/replay',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:$('ruleYaml').value,variantIds:ids,limit})});$('ruleLabStatus').innerHTML=ruleDiagnostics((r.compile||{}).diagnostics);ruleReplayView(r)}catch(e){$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`}}
async function ruleCreateFixture(target,polarity){const id=ruleVariantId();if(!id){$('ruleLabStatus').innerHTML='<div class="rule-lab-diag error">Select a plugin first.</div>';return}try{const r=await api('/api/rule-lab/fixture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:$('ruleYaml').value,variantId:id,name:`${polarity} · ${currentPluginDetail?.identity?.canonical_name||currentPluginDetail?.identity?.name||'plugin'} retained-evidence candidate`})});if(!r.ok){$('ruleLabStatus').innerHTML=ruleDiagnostics(r.diagnostics||(r.compile||{}).diagnostics);return}$(target).value=r.fixtureYaml||'';$('ruleLabStatus').innerHTML=`<div class=pass>Created ${esc(polarity)} retained-observation fixture for variant ${id}. Verify its expected matches before proposing it.</div>`}catch(e){$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`}}
async function ruleTestFixture(target,label){try{const r=await api('/api/rule-lab/fixture-test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:$('ruleYaml').value,fixtureYaml:$(target).value})});$('ruleLabStatus').innerHTML=r.ok?`<div class=pass>${esc(label)} fixture passes with the production SRL evaluator.</div>`:ruleDiagnostics(r.diagnostics);$('ruleLabResult').innerHTML=evidence(r.result||r)}catch(e){$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`}}
async function ruleExportBundle(){try{const r=await fetch('/api/rule-lab/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:$('ruleYaml').value,positiveFixtureYaml:$('rulePositiveFixture').value,negativeFixtureYaml:$('ruleNegativeFixture').value,notes:$('ruleExportNotes').value})});if(!r.ok){let msg=r.statusText;try{msg=(await r.json()).error||msg}catch{}throw new Error(msg)}const blob=await r.blob(),disp=r.headers.get('Content-Disposition')||'',m=/filename="([^"]+)"/.exec(disp),name=m?m[1]:'sigmascope-rule-candidate.zip',a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000);$('ruleLabStatus').innerHTML='<div class=pass>Deterministic GitHub-ready candidate bundle exported locally. It has no promotion authority.</div>'}catch(e){$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`}}
function ruleProposalPayload(){return{yaml:$('ruleYaml').value,packId:$('rulePackId').value,packTitle:$('rulePackTitle').value,positiveFixtureYaml:$('rulePositiveFixture').value,negativeFixtureYaml:$('ruleNegativeFixture').value,rationale:$('ruleRationale').value,falsePositiveExpectations:$('ruleFalsePositives').value,provenance:$('ruleProvenance').value,license:$('ruleLicense').value}}
async function copyRuleField(id,label){try{await navigator.clipboard.writeText($(id).value);$('ruleLabStatus').innerHTML=`<div class=pass>Copied ${esc(label)} to clipboard.</div>`}catch(e){$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">Could not copy ${esc(label)}: ${esc(e.message)}</div>`}}
async function ruleProposeGitHub(){const pending=window.open('about:blank','_blank');try{const r=await api('/api/rule-lab/proposal',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(ruleProposalPayload())});if(!r.ok){if(pending)pending.close();$('ruleLabStatus').innerHTML=ruleDiagnostics(r.diagnostics);return}if(pending)pending.location.replace(r.openUrl);else window.open(r.openUrl,'_blank','noopener,noreferrer');const fallback=r.manualPasteRequired?`<div class="proposal-result warn"><b>GitHub URL size fallback:</b> the form was opened with ${esc(r.mode)}. Paste the omitted YAML fields manually; DeltaScope did not submit anything.<div class="rule-lab-actions"><button id=copyProposalRule>Copy candidate YAML</button><button id=copyProposalPositive>Copy positive fixture</button><button id=copyProposalNegative>Copy negative fixture</button></div></div>`:`<div class="proposal-result"><b>GitHub issue form opened.</b> Review every pre-filled field and press GitHub's own Submit button when ready. DeltaScope has made no write request.</div>`;$('ruleProposalResult').innerHTML=fallback;if(r.manualPasteRequired){$('copyProposalRule').addEventListener('click',()=>copyRuleField('ruleYaml','candidate YAML'));$('copyProposalPositive').addEventListener('click',()=>copyRuleField('rulePositiveFixture','positive fixture'));$('copyProposalNegative').addEventListener('click',()=>copyRuleField('ruleNegativeFixture','negative fixture'))}$('ruleLabStatus').innerHTML=`<div class=pass>Candidate validated locally for GitHub proposal · ${esc(r.ruleSetRevision||'')} · ${r.openUrlBytes} URL bytes.</div>`}catch(e){if(pending)pending.close();$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`}}
async function initRuleLab(){try{ruleLabReference=await api('/api/rule-lab/reference');$('ruleEditorScope').textContent=`${Object.keys(ruleLabReference?.editor?.typedCollections||{}).length} typed collections · SRL Core`;if(!currentWorkspaceRule)setRuleEditorValue('')}catch(e){$('ruleLabStatus').innerHTML=`<div class="rule-lab-diag error">${esc(e.message)}</div>`}}
wireRuleSmartEditor();wireUnifiedRuleWorkspace();$('ruleLibrarySearch').addEventListener('input',renderRuleTree);$('ruleLibraryExpand').addEventListener('click',()=>$('ruleTree').querySelectorAll('details').forEach(x=>x.open=true));$('ruleLibraryCollapse').addEventListener('click',()=>$('ruleTree').querySelectorAll('details').forEach(x=>x.open=false));$('ruleImport').addEventListener('change',async e=>{const f=e.target.files?.[0];if(f){setRuleEditorValue(await f.text(),true);ruleEditorUserChanged()}});$('ruleExample').addEventListener('click',()=>{if(!currentWorkspaceRule?.editable)return;setRuleEditorValue(ruleLabReference?.exampleYaml||'',true);ruleEditorUserChanged();ruleCompileCandidate()});$('ruleCompile').addEventListener('click',ruleCompileCandidate);$('ruleEvaluate').addEventListener('click',ruleEvaluateSelected);$('ruleReplaySet').addEventListener('click',()=>ruleReplay(false));$('ruleReplayCorpus').addEventListener('click',()=>ruleReplay(true));$('ruleCreatePositiveFixture').addEventListener('click',()=>ruleCreateFixture('rulePositiveFixture','positive'));$('ruleCreateNegativeFixture').addEventListener('click',()=>ruleCreateFixture('ruleNegativeFixture','negative'));$('ruleTestPositiveFixture').addEventListener('click',()=>ruleTestFixture('rulePositiveFixture','Positive'));$('ruleTestNegativeFixture').addEventListener('click',()=>ruleTestFixture('ruleNegativeFixture','Negative'));$('ruleExport').addEventListener('click',ruleExportBundle);$('ruleProposeGitHub').addEventListener('click',ruleProposeGitHub);initRuleLab();
restoreNavigationState();restoreRuleLibraryState();renderPerspectiveNav();renderSubjectActions();renderHeaderPluginSelect();$('navToggle').addEventListener('click',toggleNavigation);$('perspectiveSelect').addEventListener('change',e=>setPerspective(e.target.value));$('headerPluginSelect').addEventListener('change',e=>selectHeaderPlugin(e.target.value));$('pluginPickerButton').addEventListener('click',()=>togglePluginPicker());$('pluginPickerClose').addEventListener('click',()=>togglePluginPicker(false));$('pluginPickerSearch').addEventListener('input',e=>{pluginPickerFilter=e.target.value;renderPluginPicker()});$('ruleLibraryToggle').addEventListener('click',toggleRuleLibrary);$('ruleVisualFocus').addEventListener('click',toggleVisualFocus);$('notificationButton').addEventListener('click',()=>{if(!$('appSwitcherDrawer').hidden)toggleAppSwitcher(false);if(!$('pluginPickerDrawer').hidden)togglePluginPicker(false);toggleNotifications()});$('notificationClose').addEventListener('click',()=>toggleNotifications(false));$('markNotificationsRead').addEventListener('click',markAllNotificationsRead);$('appSwitcherButton').addEventListener('click',()=>{if(!$('pluginPickerDrawer').hidden)togglePluginPicker(false);toggleAppSwitcher()});$('appSwitcherClose').addEventListener('click',()=>toggleAppSwitcher(false));document.querySelectorAll('[data-app-action]').forEach(x=>x.addEventListener('click',()=>openAppSwitcherAction(x.dataset.appAction)));$('openNotificationsFromDashboard').addEventListener('click',()=>toggleNotifications(true));document.querySelectorAll('[data-workbench-nav]').forEach(x=>x.addEventListener('click',()=>setWorkbenchView(x.dataset.workbenchNav)));$('globalSearch').addEventListener('input',scheduleGlobalSearch);$('globalSearch').addEventListener('keydown',e=>{if(e.key==='Escape'){hideGlobalSearch();e.currentTarget.blur()}else if(e.key==='Enter'){const first=$('globalSearchResults').querySelector('[data-search-index]');if(first&&!$('globalSearchResults').hidden){e.preventDefault();first.click()}}});document.addEventListener('click',e=>{if(!e.target.closest('.omnibox-wrap'))hideGlobalSearch();if(!e.target.closest('#notificationDrawer')&&!e.target.closest('#notificationButton')&&!$('notificationDrawer').hidden)toggleNotifications(false);if(!e.target.closest('#appSwitcherDrawer')&&!e.target.closest('#appSwitcherButton')&&!$('appSwitcherDrawer').hidden)toggleAppSwitcher(false);if(!e.target.closest('#pluginPickerDrawer')&&!e.target.closest('#pluginPickerButton')&&!$('pluginPickerDrawer').hidden)togglePluginPicker(false)});document.querySelectorAll('[data-question]').forEach(x=>x.addEventListener('click',()=>runSubjectQuestion(x.dataset.question)));$('helpClose').addEventListener('click',()=>{$('helpDrawer').hidden=true});$('toniOverview').addEventListener('click',toniOverview);$('toniQueue').addEventListener('click',toniQueue);$('toniSelection').addEventListener('click',toniSelection);$('pluginQuery').addEventListener('input',debouncedLoad);$('severityFilter').addEventListener('change',loadPlugins);$('scanStatusFilter').addEventListener('change',loadPlugins);$('knownRiskFilter').addEventListener('change',loadPlugins);$('refreshPlugins').addEventListener('click',loadPlugins);$('refreshEvidence').addEventListener('click',refreshEvidence);$('refreshOperations').addEventListener('click',()=>loadOperations(true));$('auditButton').addEventListener('click',runAudit);$('tableSearch').addEventListener('input',renderTableList);$('tablePrev').addEventListener('click',()=>currentTable&&openTable(currentTable.name,currentTable.filter?.column||'',currentTable.filter?.value||'',Math.max(0,currentTable.offset-currentTable.limit),currentMetric?.metric||''));$('tableNext').addEventListener('click',()=>currentTable&&openTable(currentTable.name,currentTable.filter?.column||'',currentTable.filter?.value||'',currentTable.offset+currentTable.limit,currentMetric?.metric||''));$('runSqlButton').addEventListener('click',runSql);
init().then(()=>setInterval(checkEvidenceRevision,60000)).catch(e=>{document.body.innerHTML='<pre class=fail>'+esc(e.stack||e.message)+'</pre>'});
</script></body></html>'''


class AppHandler(BaseHTTPRequestHandler):
    inspector: Any
    server_version = "OmegaDeltaScope/4.13.1"

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

    def bytes_response(self, body: bytes, *, content_type: str, filename: str = "") -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if filename:
            safe = re.sub(r"[^A-Za-z0-9._-]+", "-", filename).strip("-") or "download.bin"
            self.send_header("Content-Disposition", f'attachment; filename="{safe}"')
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
            if parsed.path == "/api/rule-lab/reference":
                return self.json_response(rule_lab.reference())
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
            if parsed.path == "/api/workbench":
                rows = self.inspector.list_plugins(
                    q=(query.get("q") or [""])[0], severity=(query.get("severity") or [""])[0],
                    status=(query.get("status") or [""])[0], known_risk=(query.get("known_risk") or ["0"])[0] == "1",
                    limit=int((query.get("limit") or ["500"])[0]), offset=int((query.get("offset") or ["0"])[0]),
                )
                return self.json_response(deltascope_workbench.project_workbench(rows, self.inspector.summary()))
            if parsed.path == "/api/workbench/search":
                raw_query = (query.get("q") or [""])[0]
                assets = self.inspector.list_plugins(limit=2000)
                relationships = self.inspector.workbench_relationship_index() if hasattr(self.inspector, "workbench_relationship_index") else {}
                provenance = self.inspector.definition_provenance() if hasattr(self.inspector, "definition_provenance") else {}
                return self.json_response(deltascope_workbench.project_global_search(
                    assets, relationships, provenance, raw_query,
                    limit=int((query.get("limit") or ["40"])[0]),
                ))
            if parsed.path == "/api/workbench/compare":
                variant_id = int((query.get("variant_id") or ["0"])[0])
                if variant_id <= 0:
                    raise ValueError("variant_id is required")
                snapshots = self.inspector.variant_snapshots(variant_id) if hasattr(self.inspector, "variant_snapshots") else []
                requested_path = str((query.get("path") or [""])[0]).strip()
                if not requested_path:
                    for candidate in snapshots:
                        if str(candidate.get("snapshotKind") or "") != "current" and candidate.get("variantPath"):
                            requested_path = str(candidate.get("variantPath") or "")
                            break
                if not requested_path:
                    return self.json_response({
                        "schema": deltascope_workbench.VERSION_COMPARE_SCHEMA, "readOnly": True,
                        "mutationAuthority": "none", "policyInput": False, "variantId": variant_id,
                        "available": False, "reason": "No retained prior snapshot is available for this variant.",
                        "snapshots": snapshots,
                    })
                before = self.inspector.snapshot_detail(requested_path)
                after = self.inspector.plugin_detail(variant_id)
                result = deltascope_workbench.project_version_compare(before, after)
                result["available"] = True
                result["selectedPath"] = requested_path
                result["snapshots"] = snapshots
                return self.json_response(result)
            if parsed.path == "/api/workbench/findings":
                limit = min(max(1, int((query.get("limit") or ["20"])[0])), 100)
                rows = self.inspector.latest_findings(limit) if hasattr(self.inspector, "latest_findings") else []
                return self.json_response({
                    "schema": "omega.deltascope.latest-findings.v1", "readOnly": True,
                    "mutationAuthority": "none", "findings": rows, "count": len(rows),
                })
            if parsed.path == "/api/operations":
                if not getattr(self, "operations_client", None):
                    return self.json_response({
                        "schema": deltascope_operations.SCHEMA, "available": False, "readOnly": True,
                        "mutationAuthority": "none", "components": [], "events": [],
                        "actionsRunning": 0, "recentFailureCount": 0, "error": "GitHub status disabled",
                    })
                return self.json_response(self.operations_client.status(refresh=(query.get("refresh") or ["0"])[0] == "1"))
            if parsed.path == "/api/workbench/collectors":
                summary = self.inspector.summary()
                context = self.inspector.workbench_system_context() if hasattr(self.inspector, "workbench_system_context") else {
                    "readOnly": True, "mutationAuthority": "none", "generatedAtUtc": summary.get("generatedAtUtc", ""),
                    "evidence": {"schema": "", "revisions": dict(summary.get("revisions") or summary.get("meta") or {})},
                    "queue": {"available": False, "summary": {}}, "ruleProjections": {"available": False},
                }
                workflow_histories: dict[str, dict[str, Any]] = {}
                refresh = (query.get("refresh") or ["0"])[0] == "1"
                workflows = sorted({str(row.get("workflow") or "") for row in deltascope_collectors.COLLECTORS if row.get("workflow")})
                if getattr(self, "operations_client", None):
                    for workflow_file in workflows:
                        log_jobs = {
                            str(row.get("job") or "") for row in deltascope_collectors.COLLECTORS
                            if str(row.get("workflow") or "") == workflow_file and str(row.get("job") or "")
                        }
                        workflow_histories[workflow_file] = self.operations_client.workflow_history(
                            workflow_file, limit=3, include_logs=True, log_job_names=log_jobs or None, refresh=refresh
                        )
                else:
                    for workflow_file in workflows:
                        workflow_histories[workflow_file] = {
                            "schema": "omega.deltascope.workflow-history.v1", "available": False, "readOnly": True,
                            "mutationAuthority": "none", "workflowFile": workflow_file, "runs": [],
                            "error": "GitHub Actions history disabled",
                        }
                return self.json_response(deltascope_collectors.project_collectors(workflow_histories, summary, context))
            if parsed.path == "/api/docs":
                return self.json_response(deltascope_docs.catalog())
            if parsed.path == "/api/doc":
                return self.json_response(deltascope_docs.read_document((query.get("id") or [""])[0]))
            if parsed.path == "/api/workbench/rule-library":
                return self.json_response(local_definition_library())
            if parsed.path == "/api/workbench/rule-workspace":
                return self.json_response(rule_workspace_library(self.rule_store))
            if parsed.path == "/api/rule-lab/local":
                rule_id = str((query.get("rule_id") or [""])[0])
                return self.json_response(self.rule_store.get_rule(rule_id))
            if parsed.path == "/api/workbench/rules":
                provenance = self.inspector.definition_provenance() if hasattr(self.inspector, "definition_provenance") else {
                    "available": False, "readOnly": True, "mutationAuthority": "none", "policyInput": False,
                    "provenanceRevision": "", "definitions": {}, "srl": {}, "packs": [], "activeRules": [],
                }
                return self.json_response(deltascope_workbench.project_rule_catalog(provenance))
            if parsed.path == "/api/workbench/reports":
                summary = self.inspector.summary()
                context = self.inspector.workbench_system_context() if hasattr(self.inspector, "workbench_system_context") else {
                    "readOnly": True, "mutationAuthority": "none", "generatedAtUtc": summary.get("generatedAtUtc", ""),
                    "evidence": {"schema": "", "revisions": dict(summary.get("revisions") or summary.get("meta") or {})},
                    "queue": {"available": False, "summary": {}}, "ruleProjections": {"available": False},
                }
                return self.json_response(deltascope_workbench.project_reports({}, summary, context))
            if parsed.path == "/api/workbench/system":
                provenance = self.inspector.definition_provenance() if hasattr(self.inspector, "definition_provenance") else {
                    "available": False, "definitions": {}, "srl": {}, "packs": [], "activeRules": [],
                }
                summary = self.inspector.summary()
                context = self.inspector.workbench_system_context() if hasattr(self.inspector, "workbench_system_context") else {
                    "readOnly": True, "mutationAuthority": "none", "generatedAtUtc": summary.get("generatedAtUtc", ""),
                    "evidence": {"schema": "", "revisions": dict(summary.get("revisions") or summary.get("meta") or {})},
                    "engine": {"version": summary.get("sigmascopeVersion", "")}, "source": {},
                    "queue": {"available": False, "summary": {}}, "ruleProjections": {"available": False},
                    "relationshipIndex": {"available": False}, "definitionProvenance": {"available": False},
                }
                return self.json_response(deltascope_workbench.project_system_status(context, provenance))
            if parsed.path == "/api/workbench/relationships":
                relationship_index = self.inspector.workbench_relationship_index() if hasattr(self.inspector, "workbench_relationship_index") else {}
                return self.json_response(deltascope_workbench.project_intelligence_catalog(
                    relationship_index, limit=int((query.get("limit") or ["1000"])[0])
                ))
            if parsed.path == "/api/workbench/pivot":
                relationship_index = self.inspector.workbench_relationship_index() if hasattr(self.inspector, "workbench_relationship_index") else {}
                kind = (query.get("kind") or [""])[0]
                key = (query.get("key") or [""])[0]
                variant_ids = deltascope_workbench.relationship_variant_ids(relationship_index, kind, key)
                asset_rows = self.inspector.workbench_assets_for_variants(variant_ids) if hasattr(self.inspector, "workbench_assets_for_variants") else self.inspector.list_plugins(limit=1000)
                return self.json_response(deltascope_workbench.project_intelligence_pivot(relationship_index, kind, key, asset_rows))
            if parsed.path == "/api/workbench/asset-relations":
                variant_id = int((query.get("variant_id") or ["0"])[0])
                if variant_id <= 0:
                    raise ValueError("variant_id is required")
                relationship_index = self.inspector.workbench_relationship_index() if hasattr(self.inspector, "workbench_relationship_index") else {}
                asset_rows = self.inspector.workbench_assets_for_variants([variant_id]) if hasattr(self.inspector, "workbench_assets_for_variants") else []
                if not asset_rows:
                    raise ValueError(f"unknown current variant {variant_id}")
                return self.json_response(deltascope_workbench.project_asset_relationships(relationship_index, variant_id, asset_rows[0]))
            if parsed.path == "/api/workbench/journey":
                variant_id = int((query.get("variant_id") or ["0"])[0])
                if variant_id <= 0:
                    raise ValueError("variant_id is required")
                detail = self.inspector.plugin_detail(variant_id)
                observations = self.inspector.workbench_observation_rows(variant_id) if hasattr(self.inspector, "workbench_observation_rows") else {}
                projection_state = self.inspector.srl_projection_state(variant_id) if hasattr(self.inspector, "srl_projection_state") else {}
                return self.json_response(deltascope_workbench.project_asset_journey(detail, observations, projection_state))
            if parsed.path == "/api/workbench/case":
                variant_id = int((query.get("variant_id") or ["0"])[0])
                if variant_id <= 0:
                    raise ValueError("variant_id is required")
                detail = self.inspector.plugin_detail(variant_id)
                observations = self.inspector.workbench_observation_rows(variant_id) if hasattr(self.inspector, "workbench_observation_rows") else {}
                projection_state = self.inspector.srl_projection_state(variant_id) if hasattr(self.inspector, "srl_projection_state") else {}
                return self.json_response(deltascope_workbench.project_incident_case(detail, observations, projection_state))
            if parsed.path == "/api/plugins":
                rows = self.inspector.list_plugins(
                    q=(query.get("q") or [""])[0], severity=(query.get("severity") or [""])[0],
                    status=(query.get("status") or [""])[0], known_risk=(query.get("known_risk") or ["0"])[0] == "1",
                    limit=int((query.get("limit") or ["300"])[0]), offset=int((query.get("offset") or ["0"])[0]),
                )
                return self.json_response(rows)
            if parsed.path == "/api/plugin":
                return self.json_response(self.inspector.plugin_detail(int((query.get("variant_id") or ["0"])[0])))
            if parsed.path == "/api/snapshots":
                if not hasattr(self.inspector, "variant_snapshots"):
                    return self.json_response([])
                return self.json_response(self.inspector.variant_snapshots(int((query.get("variant_id") or ["0"])[0])))
            if parsed.path == "/api/snapshot":
                if not hasattr(self.inspector, "snapshot_detail"):
                    raise ValueError("snapshot browsing requires Security Evidence v2")
                return self.json_response(self.inspector.snapshot_detail((query.get("path") or [""])[0]))
            if parsed.path == "/api/analysis-manifest":
                if not hasattr(self.inspector, "analysis_manifest"):
                    raise ValueError("analysis manifest browsing requires Security Evidence v2")
                return self.json_response(self.inspector.analysis_manifest((query.get("path") or [""])[0]))
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
            print(f"[DeltaScope] GET {self.path} failed: {exc}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return self.json_response({"error": str(exc)}, 500)

    def do_POST(self) -> None:  # noqa: N802
        try:
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/refresh":
                if not hasattr(self.inspector, "refresh_online"):
                    return self.json_response({"error": "the current evidence source is not refreshable online"}, 400)
                return self.json_response(self.inspector.refresh_online())
            length = min(int(self.headers.get("Content-Length") or 0), 2 * 1024 * 1024)
            payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            if path == "/api/developer-profile/render":
                document = payload.get("profile")
                if not isinstance(document, dict):
                    raise ValueError("profile must be an object")
                return self.json_response(developer_profile_render(document))
            if path == "/api/developer-profile/validate":
                return self.json_response(developer_profile_validate_text(str(payload.get("yaml") or "")))
            if path == "/api/rule-lab/local/save":
                return self.json_response(self.rule_store.save_rule(
                    str(payload.get("yaml") or ""),
                    expected_rule_id=str(payload.get("expectedRuleId") or ""),
                ))
            if path == "/api/rule-lab/local/fork":
                return self.json_response(self.rule_store.fork_rule(
                    str(payload.get("yaml") or ""),
                    new_rule_id=str(payload.get("newRuleId") or ""),
                ))
            if path == "/api/rule-lab/new":
                return self.json_response({
                    "ok": True, "yaml": rule_lab.new_rule_yaml(
                        str(payload.get("ruleId") or "local.new-rule"),
                        kind=str(payload.get("kind") or "observation"),
                    ),
                    "productionWriteBack": False, "mutationAuthority": "local-user-files-only",
                })
            if path == "/api/rule-lab/graph":
                return self.json_response(rule_lab.visual_graph_from_yaml(str(payload.get("yaml") or "")))
            if path == "/api/rule-lab/graph-yaml":
                graph = payload.get("graph")
                if not isinstance(graph, dict):
                    raise ValueError("graph must be an object")
                return self.json_response(rule_lab.yaml_from_visual_graph(graph))
            if path == "/api/rule-lab/compile":
                return self.json_response(rule_lab.compile_candidate_text(str(payload.get("yaml") or "")))
            if path == "/api/rule-lab/intelligence":
                return self.json_response(rule_lab.editor_intelligence(
                    str(payload.get("yaml") or ""),
                    cursor_line=max(1, int(payload.get("line") or 1)),
                    cursor_column=max(1, int(payload.get("column") or 1)),
                ))
            if path == "/api/rule-lab/format":
                return self.json_response(rule_lab.format_candidate_text(str(payload.get("yaml") or "")))
            if path == "/api/rule-lab/evaluate":
                variant_id = int(payload.get("variantId") or 0)
                if variant_id <= 0:
                    raise ValueError("variantId is required for Rule Lab evaluation")
                return self.json_response(rule_lab.evaluate_variant(self.inspector, str(payload.get("yaml") or ""), variant_id))
            if path == "/api/rule-lab/replay":
                raw_ids = payload.get("variantIds") or []
                if not isinstance(raw_ids, list):
                    raise ValueError("variantIds must be a list")
                ids = [int(item) for item in raw_ids if int(item) > 0]
                return self.json_response(rule_lab.replay_inspector(
                    self.inspector, str(payload.get("yaml") or ""), variant_ids=ids,
                    limit=min(rule_lab.MAX_REPLAY_VARIANTS, max(1, int(payload.get("limit") or rule_lab.MAX_REPLAY_VARIANTS))),
                ))
            if path == "/api/rule-lab/fixture":
                variant_id = int(payload.get("variantId") or 0)
                if variant_id <= 0:
                    raise ValueError("variantId is required for fixture creation")
                return self.json_response(rule_lab.build_fixture(
                    self.inspector, str(payload.get("yaml") or ""), variant_id,
                    name=str(payload.get("name") or "Rule Lab retained-evidence fixture"),
                ))
            if path == "/api/rule-lab/fixture-test":
                return self.json_response(rule_lab.test_fixture_text(
                    str(payload.get("yaml") or ""), str(payload.get("fixtureYaml") or "")
                ))
            if path == "/api/rule-lab/export":
                archive, manifest = rule_lab.build_export_bundle(
                    str(payload.get("yaml") or ""), fixture_text=str(payload.get("fixtureYaml") or ""),
                    positive_fixture_text=str(payload.get("positiveFixtureYaml") or ""),
                    negative_fixture_text=str(payload.get("negativeFixtureYaml") or ""),
                    notes=str(payload.get("notes") or ""),
                )
                revision = str(manifest.get("bundleRevision") or "candidate")
                return self.bytes_response(archive, content_type="application/zip", filename=f"sigmascope-{revision}.zip")
            if path == "/api/rule-lab/proposal":
                return self.json_response(rule_lab.build_github_issue_proposal(
                    str(payload.get("yaml") or ""),
                    pack_id=str(payload.get("packId") or ""), pack_title=str(payload.get("packTitle") or ""),
                    positive_fixture_text=str(payload.get("positiveFixtureYaml") or ""),
                    negative_fixture_text=str(payload.get("negativeFixtureYaml") or ""),
                    rationale=str(payload.get("rationale") or ""),
                    false_positive_expectations=str(payload.get("falsePositiveExpectations") or ""),
                    provenance=str(payload.get("provenance") or ""), license_text=str(payload.get("license") or ""),
                ))
            if path == "/api/sql":
                return self.json_response(self.inspector.read_sql(str(payload.get("query") or "")))
            return self.json_response({"error": "not found"}, 404)
        except (ValueError, sqlite3.DatabaseError, srl.SRLError) as exc:
            return self.json_response({"error": str(exc)}, 400)
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)


def serve(
    inspector: Any, host: str, port: int, open_browser: bool, rule_home: Path | None = None,
    *, github_repository: str = REPOSITORY, github_status: bool = True,
) -> int:
    rule_store = deltascope_rule_store.LocalRuleStore(rule_home)
    operations_client = deltascope_operations.GitHubOperationsClient(github_repository) if github_status else None
    handler = type("BoundAppHandler", (AppHandler,), {
        "inspector": inspector, "rule_store": rule_store, "operations_client": operations_client,
    })
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{server.server_address[1]}/"
    print(f"DeltaScope · Omega security research workbench: {url}", file=sys.stderr)
    print(f"Evidence source: {inspector.evidence_path}", file=sys.stderr)
    print(f"Local rule home: {rule_store.root}", file=sys.stderr)
    print(f"GitHub operations: {'public read-only '+github_repository if github_status else 'disabled'}", file=sys.stderr)
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
    parser = argparse.ArgumentParser(description="DeltaScope: browse Omega SigmaScope evidence read-only. Published Evidence v2 is streamed lazily from GitHub by default.")
    parser.add_argument("command", nargs="?", choices=["fetch", "serve", "serve-online", "audit", "rule-schema", "observation-schema", "capabilities", "definition-packs", "rule-compile", "rule-test", "rule-eval", "rule-parity", "rule-replay", "rule-reproject"], default="serve")
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
    parser.add_argument("--advisories", type=Path, help="Optional frozen Definitions OSV advisory payload used to verify the exact query universe during a local audit.")
    parser.add_argument("--definitions-root", type=Path, help="Frozen Daily Definitions root for definition-packs inspection.")
    parser.add_argument("--rule", type=Path, help="SRL YAML rule/ruleset file for rule-compile/rule-test/rule-eval.")
    parser.add_argument("--fixture", type=Path, help="SRL fixture YAML for rule-test.")
    parser.add_argument("--observations", type=Path, help="JSON logical-observation mapping for rule-eval.")
    parser.add_argument("--observation-contract", type=Path, help="Optional JSON Phase-4 observation contract for exact replay gating during rule-eval.")
    parser.add_argument("--initial-fact", action="append", default=[], help="Optional pre-existing typed fact for rule-eval; repeat as needed.")
    parser.add_argument("--packs-root", type=Path, help="Source Definition Pack root for rule-parity/rule-replay/rule-reproject. Defaults to repository security-definitions/packs.")
    parser.add_argument("--rule-home", type=Path, help="Versioned DeltaScope local rule root. Default: ~/.omega/deltascope/rules/v1 (or OMEGA_DELTASCOPE_RULE_HOME).")
    parser.add_argument("--github-repository", default=os.environ.get("OMEGA_GITHUB_REPOSITORY", REPOSITORY), help="Public GitHub owner/name used for read-only Actions status. Default: dalagab/omega.")
    parser.add_argument("--no-github-status", action="store_true", help="Disable the optional read-only GitHub Actions status/events feed.")
    parser.add_argument("--projection-output", type=Path, help="Optional non-production output directory for rule-reproject materialization.")
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
        if args.command == "rule-parity":
            packs_root = (args.packs_root or (Path(__file__).resolve().parents[2] / "security-definitions" / "packs")).resolve()
            report = srl_migration_parity.run_pack_root_parity(packs_root)
            print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
            return 0 if report.get("ok") else 2
        if args.command == "rule-replay":
            if not args.evidence_v2:
                raise ValueError("--evidence-v2 is required for rule-replay")
            packs_root = (args.packs_root or (Path(__file__).resolve().parents[2] / "security-definitions" / "packs")).resolve()
            compiled = definition_packs.compile_pack_root(packs_root)["compiledRuleSet"]
            srl_migration_parity._assert_migrated_rules(compiled)
            report = srl_evidence_replay.replay_evidence_root(args.evidence_v2.resolve(), compiled)
            print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
            if not report.get("auditOk"):
                return 2
            return 3 if args.strict_warnings and not report.get("cutoverReady") else 0
        if args.command == "rule-reproject":
            if not args.evidence_v2:
                raise ValueError("--evidence-v2 is required for rule-reproject")
            packs_root = (args.packs_root or (Path(__file__).resolve().parents[2] / "security-definitions" / "packs")).resolve()
            compiled = definition_packs.compile_pack_root(packs_root)["compiledRuleSet"]
            report = rule_reprojection.plan_reprojection(args.evidence_v2.resolve(), compiled)
            if args.projection_output:
                output = args.projection_output.resolve()
                index = rule_reprojection.materialize_projection_set(output, report)
                report["materialized"] = {
                    "path": str(output),
                    "index": index,
                    "validation": rule_reprojection.verify_projection_set(output),
                }
            print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
            if not report.get("auditOk"):
                return 2
            return 3 if args.strict_warnings and int(report.get("reanalysisRequiredVariants") or 0) > 0 else 0
        if args.command == "definition-packs":
            if not args.definitions_root:
                raise ValueError("--definitions-root is required for definition-packs")
            definitions_root = args.definitions_root.resolve()
            definitions_index = json.loads((definitions_root / "index.json").read_text(encoding="utf-8"))
            descriptor = definitions_index.get("srlDefinitionPacks") if isinstance(definitions_index.get("srlDefinitionPacks"), dict) else {}
            validation = definition_packs.verify_frozen(definitions_root, descriptor)
            if not validation.get("ok"):
                print(json.dumps(validation, indent=2, ensure_ascii=False, sort_keys=True))
                return 2
            frozen_index = json.loads((definitions_root / str(descriptor["path"])).read_text(encoding="utf-8"))
            payload = {
                "schema": frozen_index.get("schema"),
                "definitionPackRevision": frozen_index.get("definitionPackRevision"),
                "ruleSetRevision": frozen_index.get("ruleSetRevision"),
                "productionRuleEvaluationEnabled": frozen_index.get("productionRuleEvaluationEnabled", False),
                "activeRuleCount": frozen_index.get("activeRuleCount", 0),
                "totalRuleCount": frozen_index.get("totalRuleCount", 0),
                "packs": frozen_index.get("packs") or [],
                "validation": validation,
            }
            print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
            return 0
        if args.command in {"rule-schema", "observation-schema", "capabilities"}:
            reference = build_rule_author_reference()
            if args.command == "capabilities":
                payload = reference.get("capabilityRegistry") or {}
            elif args.command == "observation-schema":
                payload = observation_projection.build_schema_reference()
            else:
                payload = dict(reference)
                payload["status"] = "srl-v1-phase7-static-observation-replay-production-migration-gated"
                payload["productionRuleEvaluationEnabled"] = False
                payload["srlEngine"] = srl.engine_reference()
                payload["plannedOperators"] = srl.engine_reference()["operators"]
                payload["warning"] = "SRL v1 and Definition Pack v1 freezing are implemented. Reviewed staticPatternMatches observation rules emit fourteen literal-backed primitive facts (including the five facts used by the first two compound correlations), and retained Evidence-v2 replay is available locally. Production projection remains gated until a compatible 2.15 corpus replays cleanly and cutover is explicitly reviewed; workers must load only frozen compiled Definitions."
            if args.json or args.command in {"rule-schema", "observation-schema"}:
                print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
            else:
                print(f"Capability registry {payload.get('revision','')}")
                for item in payload.get("capabilities") or []:
                    aliases = ", ".join(item.get("aliases") or [])
                    suffix = f" (aliases: {aliases})" if aliases else ""
                    print(f"{item.get('id',''):36} {item.get('label','')}{suffix}")
            return 0
        if args.command in {"rule-compile", "rule-test", "rule-eval"}:
            if not args.rule:
                raise ValueError(f"--rule is required for {args.command}")
            compiled = srl.compile_file(args.rule)
            if args.command == "rule-compile":
                print(json.dumps(compiled, indent=2, ensure_ascii=False, sort_keys=True))
                return 0
            if args.command == "rule-test":
                if not args.fixture:
                    raise ValueError("--fixture is required for rule-test")
                result = srl.run_fixture(compiled, srl.load_yaml(args.fixture))
                print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
                return 0 if result.get("passed") else 2
            if not args.observations:
                raise ValueError("--observations is required for rule-eval")
            observations = json.loads(args.observations.read_text(encoding="utf-8"))
            if not isinstance(observations, dict):
                raise ValueError("--observations must contain a JSON object mapping logical collection names to rows")
            contract = None
            if args.observation_contract:
                contract = json.loads(args.observation_contract.read_text(encoding="utf-8"))
                if not isinstance(contract, dict):
                    raise ValueError("--observation-contract must contain a JSON object")
            result = srl.evaluate_ruleset(compiled, observations, args.initial_fact or [], observation_contract=contract)
            print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
            return 0 if result.get("evaluated") else 3

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
            inspector = SecurityInspector(evidence, marketplace, args.advisories)

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
        return serve(
            inspector, args.host, args.port, not args.no_browser, args.rule_home,
            github_repository=args.github_repository, github_status=not args.no_github_status,
        )
    except (RuntimeError, OSError, ValueError, sqlite3.DatabaseError, urllib.error.URLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

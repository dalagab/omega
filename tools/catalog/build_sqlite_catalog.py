#!/usr/bin/env python3
"""Build Omega's production SQLite catalog.

The SQLite file is the only catalog format consumed by the Omega plugin.
JSON remains an input/debug/export format for the online builder.

Inputs may include:
  * raw-sources.json from collect_sources.py
  * enriched-sources.json from enrich_metadata.py
  * website-enrichment.json from scrape_websites.py
  * sources/curated-sources.json (human-maintained source metadata)
  * an optional previous omega-catalog.sqlite(.zip) seed

The builder preserves last-known-good source and website data when a new
network pass fails, recalculates presentation metadata, validates the DB,
and publishes a deterministic descriptor plus compressed transport ZIP.
"""
from __future__ import annotations

from contextlib import closing
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Iterable

from catalog_revisions import compute_catalog_base_revision, ensure_revision_schema, read_meta, write_meta
from catalog_presentation import is_adult_content, split_project_image_urls

SCHEMA_VERSION = 1
SCHEMA_NAME = "omega.catalog.sqlite.v1"
DB_FILENAME = "omega-catalog.sqlite"
ZIP_FILENAME = "omega-catalog.sqlite.zip"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_url(value: str | None) -> str:
    return (value or "").strip().rstrip("/")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path | None, default: Any) -> Any:
    if path is None or not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def json_text(value: Any) -> str:
    return json.dumps(value if value is not None else [], ensure_ascii=False, separators=(",", ":"))


def bool_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        return int(value.strip().lower() == "true")
    if isinstance(value, (int, float)):
        return int(value != 0)
    return 0


def int_value(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default




def looks_like_http_diagnostic(value: Any) -> bool:
    """Return true for transport/debug output that must never become storefront copy."""
    text = str(value or "").strip()
    if not text:
        return False
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    lower = text.lower()
    if lower.startswith((
        "404 not found", "404:", "error 404", "http 404",
        "500 internal server error", "500:", "error 500", "http 500",
        "502 bad gateway", "503 service unavailable", "504 gateway timeout",
    )):
        return True
    status_lines = sum(bool(re.match(r"^(?:http\s*)?[45]\d\d(?:\s|:|-|$)", line, re.I)) for line in lines)
    url_lines = sum(bool(re.match(r"^(?:[-*]\s*)?https?://", line, re.I)) for line in lines)
    return status_lines >= 2 or (status_lines >= 1 and url_lines >= 1)


def sanitize_presentation_text(value: Any) -> str:
    text = str(value or "").strip()
    return "" if looks_like_http_diagnostic(text) else text


def sanitize_seeded_website_cache(db: sqlite3.Connection) -> int:
    """Remove previously-cached HTTP diagnostics before presentation is recomputed."""
    changed = 0
    for row in db.execute("SELECT website_id,description,readme_excerpt FROM websites").fetchall():
        description = sanitize_presentation_text(row["description"])
        excerpt = sanitize_presentation_text(row["readme_excerpt"])
        if description == str(row["description"] or "") and excerpt == str(row["readme_excerpt"] or ""):
            continue
        db.execute(
            "UPDATE websites SET description=?,readme_excerpt=? WHERE website_id=?",
            (description, excerpt, int(row["website_id"])),
        )
        changed += 1
    return changed


def sanitize_seeded_plugin_presentation_fields(db: sqlite3.Connection) -> int:
    """Clean normalized display fields while keeping raw_manifest_json untouched for audit."""
    changed = 0
    for row in db.execute("SELECT variant_id,punchline,description FROM plugin_variants").fetchall():
        punchline = sanitize_presentation_text(row["punchline"])
        description = sanitize_presentation_text(row["description"])
        if punchline == str(row["punchline"] or "") and description == str(row["description"] or ""):
            continue
        db.execute(
            "UPDATE plugin_variants SET punchline=?,description=? WHERE variant_id=?",
            (punchline, description, int(row["variant_id"])),
        )
        changed += 1
    return changed


def copy_seed_database(seed: Path | None, destination: Path) -> bool:
    if seed is None or not seed.exists():
        return False
    try:
        if seed.suffix.lower() == ".zip":
            with zipfile.ZipFile(seed, "r") as zf:
                candidates = [n for n in zf.namelist() if n.endswith("/" + DB_FILENAME) or n == DB_FILENAME]
                if not candidates:
                    return False
                with zf.open(candidates[0]) as src, destination.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
        else:
            shutil.copy2(seed, destination)
        with closing(sqlite3.connect(destination)) as db:
            row = db.execute("SELECT value FROM catalog_meta WHERE key='schema_version'").fetchone()
            if row is None or int(row[0]) != SCHEMA_VERSION:
                raise ValueError("seed schema mismatch")
            integrity = db.execute("PRAGMA integrity_check").fetchone()
            if integrity is None or str(integrity[0]).lower() != "ok":
                raise ValueError("seed integrity check failed")
        return True
    except Exception:
        destination.unlink(missing_ok=True)
        return False


SCHEMA_SQL = r"""
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = DELETE;
PRAGMA synchronous = FULL;

CREATE TABLE IF NOT EXISTS catalog_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
    source_id INTEGER PRIMARY KEY,
    url TEXT NOT NULL UNIQUE COLLATE NOCASE,
    provider TEXT NOT NULL DEFAULT '',
    curated_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT '',
    discovered_by TEXT NOT NULL DEFAULT '',
    source_repo_url TEXT NOT NULL DEFAULT '',
    is_official INTEGER NOT NULL DEFAULT 0,
    enabled_by_default INTEGER NOT NULL DEFAULT 1,
    integrate_with_dalamud INTEGER NOT NULL DEFAULT 0,
    etag TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT '',
    content_sha256 TEXT NOT NULL DEFAULT '',
    last_checked_utc TEXT NOT NULL DEFAULT '',
    last_success_utc TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    plugin_count INTEGER NOT NULL DEFAULT 0,
    highest_api INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS plugins (
    plugin_id INTEGER PRIMARY KEY,
    internal_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    canonical_name TEXT NOT NULL DEFAULT '',
    first_seen_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS plugin_variants (
    variant_id INTEGER PRIMARY KEY,
    plugin_id INTEGER NOT NULL REFERENCES plugins(plugin_id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
    source_entry_key TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    punchline TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    changelog TEXT NOT NULL DEFAULT '',
    assembly_version TEXT NOT NULL DEFAULT '0.0.0.0',
    testing_assembly_version TEXT,
    dalamud_api_level INTEGER NOT NULL DEFAULT 0,
    testing_dalamud_api_level INTEGER,
    applicable_version TEXT NOT NULL DEFAULT 'any',
    minimum_dalamud_version TEXT,
    repo_url TEXT NOT NULL DEFAULT '',
    download_link_install TEXT NOT NULL DEFAULT '',
    download_link_update TEXT NOT NULL DEFAULT '',
    download_link_testing TEXT NOT NULL DEFAULT '',
    icon_url TEXT NOT NULL DEFAULT '',
    image_urls_json TEXT NOT NULL DEFAULT '[]',
    tags_json TEXT NOT NULL DEFAULT '[]',
    category_tags_json TEXT NOT NULL DEFAULT '[]',
    download_count INTEGER NOT NULL DEFAULT 0,
    last_update INTEGER NOT NULL DEFAULT 0,
    is_hide INTEGER NOT NULL DEFAULT 0,
    is_testing_exclusive INTEGER NOT NULL DEFAULT 0,
    dip17_channel TEXT NOT NULL DEFAULT '',
    raw_manifest_json TEXT NOT NULL DEFAULT '{}',
    first_seen_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    UNIQUE(source_id, source_entry_key)
);

CREATE INDEX IF NOT EXISTS ix_variants_plugin ON plugin_variants(plugin_id);
CREATE INDEX IF NOT EXISTS ix_variants_source ON plugin_variants(source_id);
CREATE INDEX IF NOT EXISTS ix_variants_api ON plugin_variants(dalamud_api_level);
CREATE INDEX IF NOT EXISTS ix_variants_repo_url ON plugin_variants(repo_url COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS plugin_tags (
    variant_id INTEGER NOT NULL REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
    tag TEXT NOT NULL COLLATE NOCASE,
    kind TEXT NOT NULL DEFAULT 'tag',
    PRIMARY KEY (variant_id, tag, kind)
);
CREATE INDEX IF NOT EXISTS ix_plugin_tags_tag ON plugin_tags(tag COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS plugin_images (
    image_id INTEGER PRIMARY KEY,
    variant_id INTEGER NOT NULL REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    image_kind TEXT NOT NULL,
    ordinal INTEGER NOT NULL DEFAULT 0,
    source_kind TEXT NOT NULL DEFAULT 'manifest',
    UNIQUE(variant_id, url, image_kind)
);

CREATE TABLE IF NOT EXISTS websites (
    website_id INTEGER PRIMARY KEY,
    url TEXT NOT NULL UNIQUE COLLATE NOCASE,
    ok INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    homepage TEXT NOT NULL DEFAULT '',
    stars INTEGER,
    forks INTEGER,
    watchers INTEGER,
    topics_json TEXT NOT NULL DEFAULT '[]',
    language TEXT NOT NULL DEFAULT '',
    license TEXT NOT NULL DEFAULT '',
    default_branch TEXT NOT NULL DEFAULT '',
    last_commit_utc TEXT NOT NULL DEFAULT '',
    readme_excerpt TEXT NOT NULL DEFAULT '',
    image_urls_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    last_checked_utc TEXT NOT NULL DEFAULT '',
    last_success_utc TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    failure_count INTEGER NOT NULL DEFAULT 0,
    next_retry_utc TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS presentation (
    plugin_id INTEGER PRIMARY KEY REFERENCES plugins(plugin_id) ON DELETE CASCADE,
    preferred_variant_id INTEGER NOT NULL REFERENCES plugin_variants(variant_id),
    presentation_variant_id INTEGER NOT NULL REFERENCES plugin_variants(variant_id),
    rich_card INTEGER NOT NULL DEFAULT 0,
    web_enriched INTEGER NOT NULL DEFAULT 0,
    official INTEGER NOT NULL DEFAULT 0,
    nsfw INTEGER NOT NULL DEFAULT 0,
    richness_score INTEGER NOT NULL DEFAULT 0,
    image_urls_json TEXT NOT NULL DEFAULT '[]',
    summary TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS plugin_search (
    plugin_id INTEGER PRIMARY KEY REFERENCES plugins(plugin_id) ON DELETE CASCADE,
    internal_name TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    author TEXT NOT NULL DEFAULT '',
    punchline TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    website_text TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_plugin_search_internal_name ON plugin_search(internal_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_plugin_search_name ON plugin_search(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_plugin_search_author ON plugin_search(author COLLATE NOCASE);

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
    automation_level TEXT NOT NULL DEFAULT 'none',
    automation_capabilities_json TEXT NOT NULL DEFAULT '[]',
    findings_json TEXT NOT NULL DEFAULT '[]',
    source_available INTEGER NOT NULL DEFAULT 0,
    source_repository TEXT NOT NULL DEFAULT '',
    source_commit TEXT NOT NULL DEFAULT '',
    source_to_binary_verified INTEGER NOT NULL DEFAULT 0,
    report_json TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT ''
);
"""


def reset_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA_SQL)
    security_current_columns = {row[1] for row in db.execute("PRAGMA table_info(plugin_security_current)")}
    if "automation_level" not in security_current_columns:
        db.execute("ALTER TABLE plugin_security_current ADD COLUMN automation_level TEXT NOT NULL DEFAULT 'none'")
    if "automation_capabilities_json" not in security_current_columns:
        db.execute("ALTER TABLE plugin_security_current ADD COLUMN automation_capabilities_json TEXT NOT NULL DEFAULT '[]'")
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
    db.commit()
    return db


def source_definition_map(curated_doc: Any) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not isinstance(curated_doc, list):
        return out
    for item in curated_doc:
        if not isinstance(item, dict):
            continue
        url = normalize_url(item.get("url"))
        if not url:
            continue
        out[url.lower()] = item
    return out


def upsert_sources(db: sqlite3.Connection, raw_doc: Any, curated: dict[str, dict], now: str) -> None:
    raw_sources = raw_doc.get("sources", []) if isinstance(raw_doc, dict) else []
    for src in raw_sources:
        if not isinstance(src, dict):
            continue
        url = normalize_url(src.get("url"))
        if not url:
            continue
        c = curated.get(url.lower(), {})
        provider = str(src.get("provider") or c.get("name") or "")
        name = str(c.get("name") or provider or url)
        db.execute(
            """INSERT INTO sources(url,provider,curated_id,name,description,kind,discovered_by,source_repo_url,is_official,enabled_by_default,integrate_with_dalamud,last_checked_utc)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(url) DO UPDATE SET
                 provider=excluded.provider, curated_id=excluded.curated_id,
                 name=excluded.name,
                 description=excluded.description,
                 kind=excluded.kind,
                 discovered_by=excluded.discovered_by,
                 source_repo_url=excluded.source_repo_url,
                 is_official=excluded.is_official,
                 enabled_by_default=excluded.enabled_by_default,
                 integrate_with_dalamud=excluded.integrate_with_dalamud""",
            (
                url,
                provider,
                str(c.get("id") or ""),
                name,
                str(c.get("description") or ""),
                str(src.get("kind") or ""),
                str(src.get("discoveredBy") or ""),
                str(src.get("sourceRepoUrl") or ""),
                bool_int(c.get("isOfficial")),
                0 if c.get("enabledByDefault") is False else 1,
                bool_int(c.get("integrateWithDalamudByDefault")),
                now,
            ),
        )

    # Curated definitions not seen by the discovery pass still belong in source metadata.
    for c in curated.values():
        url = normalize_url(c.get("url"))
        if not url:
            continue
        db.execute(
            """INSERT INTO sources(url,provider,curated_id,name,description,kind,discovered_by,is_official,enabled_by_default,integrate_with_dalamud,last_checked_utc)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(url) DO UPDATE SET
                 curated_id=excluded.curated_id, name=excluded.name, description=excluded.description, is_official=excluded.is_official,
                 enabled_by_default=excluded.enabled_by_default, integrate_with_dalamud=excluded.integrate_with_dalamud""",
            (
                url,
                str(c.get("name") or ""),
                str(c.get("id") or ""),
                str(c.get("name") or url),
                str(c.get("description") or ""),
                "curated",
                "curated-sources.json",
                bool_int(c.get("isOfficial")),
                0 if c.get("enabledByDefault") is False else 1,
                bool_int(c.get("integrateWithDalamudByDefault")),
                now,
            ),
        )


def ensure_plugin(db: sqlite3.Connection, internal_name: str, display_name: str, now: str) -> int:
    row = db.execute("SELECT plugin_id FROM plugins WHERE internal_name=? COLLATE NOCASE", (internal_name,)).fetchone()
    if row:
        db.execute("UPDATE plugins SET last_seen_utc=?, active=1 WHERE plugin_id=?", (now, row[0]))
        return int(row[0])
    cur = db.execute(
        "INSERT INTO plugins(internal_name,canonical_name,first_seen_utc,last_seen_utc,active) VALUES(?,?,?,?,1)",
        (internal_name, display_name, now, now),
    )
    return int(cur.lastrowid)


def source_id_for(db: sqlite3.Connection, url: str, provider: str, now: str) -> int:
    row = db.execute("SELECT source_id FROM sources WHERE url=? COLLATE NOCASE", (url,)).fetchone()
    if row:
        return int(row[0])
    cur = db.execute(
        "INSERT INTO sources(url,provider,name,last_checked_utc) VALUES(?,?,?,?)",
        (url, provider or url, provider or url, now),
    )
    return int(cur.lastrowid)


def entry_key(plugin: dict, index: int) -> str:
    internal = str(plugin.get("internalName") or plugin.get("InternalName") or "").strip().lower()
    version = str(plugin.get("assemblyVersion") or plugin.get("AssemblyVersion") or "0.0.0.0")
    api = int_value(plugin.get("dalamudApiLevel") if "dalamudApiLevel" in plugin else plugin.get("DalamudApiLevel"))
    testing = int_value(plugin.get("testingDalamudApiLevel") if "testingDalamudApiLevel" in plugin else plugin.get("TestingDalamudApiLevel"))
    return f"{internal}|{version}|{api}|{testing}|{index}"


def manifest_field(plugin: dict, camel: str, pascal: str, default: Any = None) -> Any:
    if camel in plugin:
        return plugin.get(camel)
    return plugin.get(pascal, default)


def import_enriched(db: sqlite3.Connection, enriched_doc: Any, now: str) -> None:
    source_records = enriched_doc.get("sources", []) if isinstance(enriched_doc, dict) else []
    seen_plugins: set[int] = set()
    successful_sources: set[int] = set()

    for src in source_records:
        if not isinstance(src, dict):
            continue
        url = normalize_url(src.get("url"))
        if not url:
            continue
        sid = source_id_for(db, url, str(src.get("provider") or ""), now)
        ok = bool(src.get("ok"))
        error = str(src.get("error") or "")
        etag = str(src.get("etag") or "")
        last_modified = str(src.get("lastModified") or "")
        content_sha = str(src.get("contentSha256") or "")
        if not ok:
            db.execute(
                "UPDATE sources SET last_checked_utc=?, last_error=? WHERE source_id=?",
                (now, error, sid),
            )
            continue

        successful_sources.add(sid)
        if bool(src.get("notModified")):
            db.execute(
                """UPDATE sources SET last_checked_utc=?,last_success_utc=?,last_error='',
                       etag=CASE WHEN ?<>'' THEN ? ELSE etag END,
                       last_modified=CASE WHEN ?<>'' THEN ? ELSE last_modified END,
                       content_sha256=CASE WHEN ?<>'' THEN ? ELSE content_sha256 END
                   WHERE source_id=?""",
                (now, now, etag, etag, last_modified, last_modified, content_sha, content_sha, sid),
            )
            continue

        plugins = src.get("plugins") or []
        highest_api = max((int_value(manifest_field(p, "dalamudApiLevel", "DalamudApiLevel")) for p in plugins if isinstance(p, dict)), default=0)
        db.execute(
            """UPDATE sources SET last_checked_utc=?,last_success_utc=?,last_error='',plugin_count=?,highest_api=?,
                   etag=?,last_modified=?,content_sha256=? WHERE source_id=?""",
            (now, now, len(plugins), highest_api, etag, last_modified, content_sha, sid),
        )
        # A changed successful manifest is authoritative for this source.
        db.execute("UPDATE plugin_variants SET active=0 WHERE source_id=?", (sid,))

        for idx, p in enumerate(plugins):
            if not isinstance(p, dict):
                continue
            internal_name = str(manifest_field(p, "internalName", "InternalName", "") or "").strip()
            name = str(manifest_field(p, "name", "Name", "") or "").strip()
            if not internal_name or not name:
                continue
            pid = ensure_plugin(db, internal_name, name, now)
            seen_plugins.add(pid)
            key = entry_key(p, idx)
            tags = manifest_field(p, "tags", "Tags", []) or []
            categories = manifest_field(p, "categoryTags", "CategoryTags", []) or []
            images = manifest_field(p, "imageUrls", "ImageUrls", []) or []
            raw_manifest = p.get("rawManifest") if isinstance(p.get("rawManifest"), dict) else p
            values = (
                pid, sid, key,
                str(manifest_field(p, "author", "Author", "") or ""),
                name,
                sanitize_presentation_text(manifest_field(p, "punchline", "Punchline", "")),
                sanitize_presentation_text(manifest_field(p, "description", "Description", "")),
                str(manifest_field(p, "changelog", "Changelog", "") or ""),
                str(manifest_field(p, "assemblyVersion", "AssemblyVersion", "0.0.0.0") or "0.0.0.0"),
                manifest_field(p, "testingAssemblyVersion", "TestingAssemblyVersion"),
                int_value(manifest_field(p, "dalamudApiLevel", "DalamudApiLevel")),
                int_value(manifest_field(p, "testingDalamudApiLevel", "TestingDalamudApiLevel"), default=-1),
                str(manifest_field(p, "applicableVersion", "ApplicableVersion", "any") or "any"),
                manifest_field(p, "minimumDalamudVersion", "MinimumDalamudVersion"),
                normalize_url(manifest_field(p, "repoUrl", "RepoUrl", "")),
                str(manifest_field(p, "downloadLinkInstall", "DownloadLinkInstall", "") or ""),
                str(manifest_field(p, "downloadLinkUpdate", "DownloadLinkUpdate", "") or ""),
                str(manifest_field(p, "downloadLinkTesting", "DownloadLinkTesting", "") or ""),
                str(manifest_field(p, "iconUrl", "IconUrl", "") or ""),
                json_text(images),
                json_text(tags),
                json_text(categories),
                int_value(manifest_field(p, "downloadCount", "DownloadCount")),
                int_value(manifest_field(p, "lastUpdate", "LastUpdate")),
                bool_int(manifest_field(p, "isHide", "IsHide")),
                bool_int(manifest_field(p, "isTestingExclusive", "IsTestingExclusive")),
                str(manifest_field(p, "dip17Channel", "_Dip17Channel", "") or ""),
                json.dumps(raw_manifest, ensure_ascii=False, separators=(",", ":")),
                now, now,
            )
            testing_api = None if values[11] < 0 else values[11]
            values = values[:11] + (testing_api,) + values[12:]
            db.execute(
                """INSERT INTO plugin_variants(
                    plugin_id,source_id,source_entry_key,author,name,punchline,description,changelog,
                    assembly_version,testing_assembly_version,dalamud_api_level,testing_dalamud_api_level,
                    applicable_version,minimum_dalamud_version,repo_url,download_link_install,download_link_update,
                    download_link_testing,icon_url,image_urls_json,tags_json,category_tags_json,download_count,last_update,
                    is_hide,is_testing_exclusive,dip17_channel,raw_manifest_json,first_seen_utc,last_seen_utc,active)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
                   ON CONFLICT(source_id,source_entry_key) DO UPDATE SET
                    plugin_id=excluded.plugin_id, author=excluded.author, name=excluded.name,
                    punchline=excluded.punchline, description=excluded.description, changelog=excluded.changelog,
                    assembly_version=excluded.assembly_version, testing_assembly_version=excluded.testing_assembly_version,
                    dalamud_api_level=excluded.dalamud_api_level, testing_dalamud_api_level=excluded.testing_dalamud_api_level,
                    applicable_version=excluded.applicable_version, minimum_dalamud_version=excluded.minimum_dalamud_version,
                    repo_url=excluded.repo_url, download_link_install=excluded.download_link_install,
                    download_link_update=excluded.download_link_update, download_link_testing=excluded.download_link_testing,
                    icon_url=excluded.icon_url, image_urls_json=excluded.image_urls_json, tags_json=excluded.tags_json,
                    category_tags_json=excluded.category_tags_json, download_count=excluded.download_count,
                    last_update=excluded.last_update, is_hide=excluded.is_hide,
                    is_testing_exclusive=excluded.is_testing_exclusive, dip17_channel=excluded.dip17_channel,
                    raw_manifest_json=excluded.raw_manifest_json, last_seen_utc=excluded.last_seen_utc, active=1""",
                values,
            )
            variant_id = int(db.execute("SELECT variant_id FROM plugin_variants WHERE source_id=? AND source_entry_key=?", (sid, key)).fetchone()[0])
            db.execute("DELETE FROM plugin_tags WHERE variant_id=?", (variant_id,))
            db.execute("DELETE FROM plugin_images WHERE variant_id=?", (variant_id,))
            for tag in tags:
                if str(tag).strip():
                    db.execute("INSERT OR IGNORE INTO plugin_tags(variant_id,tag,kind) VALUES(?,?, 'tag')", (variant_id, str(tag).strip()))
            for cat in categories:
                if str(cat).strip():
                    db.execute("INSERT OR IGNORE INTO plugin_tags(variant_id,tag,kind) VALUES(?,?, 'category')", (variant_id, str(cat).strip()))
            for ordinal, image_url in enumerate(images[:5]):
                if str(image_url).strip():
                    db.execute(
                        "INSERT OR IGNORE INTO plugin_images(variant_id,url,image_kind,ordinal,source_kind) VALUES(?,?, 'screenshot',?, 'manifest')",
                        (variant_id, str(image_url).strip(), ordinal),
                    )

    # Sources that refreshed successfully may have removed entries; inactive old rows stay historical.
    db.execute("UPDATE plugins SET active=CASE WHEN EXISTS(SELECT 1 FROM plugin_variants v WHERE v.plugin_id=plugins.plugin_id AND v.active=1) THEN 1 ELSE 0 END")


def readme_images(repo_url: str, excerpt: str) -> list[str]:
    if not repo_url or not excerpt:
        return []
    # Markdown image URLs and HTML <img src>. Skip obvious badges/icons.
    urls = re.findall(r"!\[[^\]]*\]\((https?://[^)\s]+)", excerpt, flags=re.I)
    urls += re.findall(r"<img[^>]+src=[\"'](https?://[^\"']+)", excerpt, flags=re.I)
    out: list[str] = []
    for url in urls:
        lower = url.lower()
        if any(token in lower for token in ("shields.io", "badge", "limes.pink", "icon.png", "logo.png")):
            continue
        if url not in out:
            out.append(url)
        if len(out) >= 5:
            break
    return out


def import_websites(db: sqlite3.Connection, website_doc: Any, now: str) -> None:
    repos = website_doc.get("repos", {}) if isinstance(website_doc, dict) else {}
    if not isinstance(repos, dict):
        return
    for key, rec in repos.items():
        if not isinstance(rec, dict):
            continue
        url = normalize_url(rec.get("url") or key)
        if not url:
            continue
        ok = bool(rec.get("ok"))
        existing = db.execute("SELECT * FROM websites WHERE url=? COLLATE NOCASE", (url,)).fetchone()
        if ok:
            excerpt = sanitize_presentation_text(rec.get("readmeExcerpt"))
            description = sanitize_presentation_text(rec.get("description"))
            image_candidates = list(rec.get("imageUrls") or readme_images(url, excerpt)) + list(rec.get("discordJoinImageUrls") or [])
            images, discord_join_images = split_project_image_urls(image_candidates)
            metadata = dict(rec)
            metadata["discordJoinImageUrls"] = discord_join_images
            db.execute(
                """INSERT INTO websites(url,ok,title,description,homepage,stars,forks,watchers,topics_json,language,license,
                    default_branch,last_commit_utc,readme_excerpt,image_urls_json,metadata_json,last_checked_utc,last_success_utc,last_error,failure_count,next_retry_utc)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'',0,'')
                   ON CONFLICT(url) DO UPDATE SET
                    ok=1,title=excluded.title,description=excluded.description,homepage=excluded.homepage,
                    stars=excluded.stars,forks=excluded.forks,watchers=excluded.watchers,topics_json=excluded.topics_json,
                    language=excluded.language,license=excluded.license,default_branch=excluded.default_branch,
                    last_commit_utc=excluded.last_commit_utc,readme_excerpt=excluded.readme_excerpt,
                    image_urls_json=excluded.image_urls_json,metadata_json=excluded.metadata_json,
                    last_checked_utc=excluded.last_checked_utc,last_success_utc=excluded.last_success_utc,
                    last_error='',failure_count=0,next_retry_utc=''""",
                (
                    url, 1, str(rec.get("title") or ""), description, str(rec.get("homepage") or ""),
                    rec.get("stars"), rec.get("forks"), rec.get("watchers"), json_text(rec.get("topics") or []),
                    str(rec.get("language") or ""), str(rec.get("license") or ""), str(rec.get("defaultBranch") or ""),
                    str(rec.get("lastCommit") or ""), excerpt, json_text(images), json.dumps(metadata, ensure_ascii=False, separators=(",", ":")),
                    now, now,
                ),
            )
        else:
            error = str(rec.get("error") or "unknown scrape error")
            if existing:
                failures = int(existing["failure_count"] or 0) + 1
                db.execute(
                    "UPDATE websites SET ok=CASE WHEN last_success_utc<>'' THEN 1 ELSE 0 END,last_checked_utc=?,last_error=?,failure_count=? WHERE website_id=?",
                    (now, error, failures, int(existing["website_id"])),
                )
            else:
                db.execute(
                    "INSERT INTO websites(url,ok,last_checked_utc,last_error,failure_count) VALUES(?,0,?,?,1)",
                    (url, now, error),
                )


def parse_json_array(value: str | None) -> list[str]:
    try:
        data = json.loads(value or "[]")
        return [str(x) for x in data if str(x).strip()] if isinstance(data, list) else []
    except Exception:
        return []


def version_key(text: str) -> tuple[int, ...]:
    parts = []
    for p in (text or "").split("."):
        try: parts.append(int(p))
        except ValueError: parts.append(0)
    return tuple(parts + [0] * (4 - len(parts)))


def recompute_presentation(db: sqlite3.Connection, now: str) -> None:
    db.execute("DELETE FROM presentation")
    db.execute("DELETE FROM plugin_search")
    plugin_rows = db.execute("SELECT plugin_id,internal_name FROM plugins WHERE active=1 ORDER BY internal_name COLLATE NOCASE").fetchall()
    for prow in plugin_rows:
        pid = int(prow["plugin_id"])
        variants = db.execute(
            """SELECT v.*,s.is_official,s.name AS source_name,s.url AS source_url,
                      w.ok AS website_ok,w.description AS website_description,w.readme_excerpt,w.image_urls_json AS website_images
               FROM plugin_variants v
               JOIN sources s ON s.source_id=v.source_id
               LEFT JOIN websites w ON w.url=v.repo_url COLLATE NOCASE
               WHERE v.plugin_id=? AND v.active=1 AND v.is_hide=0""",
            (pid,),
        ).fetchall()
        if not variants:
            continue

        def image_list(v: sqlite3.Row) -> list[str]:
            values = parse_json_array(v["image_urls_json"]) + parse_json_array(v["website_images"])
            out: list[str] = []
            for x in values:
                if x not in out:
                    out.append(x)
                if len(out) >= 5:
                    break
            return out

        def richness(v: sqlite3.Row) -> int:
            images = image_list(v)
            desc = str(v["description"] or "")
            web = str(v["website_description"] or "")
            punch = str(v["punchline"] or "")
            return len(images) * 10000 + min(1200, len(desc) + len(web)) + min(300, len(punch)) + (800 if v["website_ok"] else 0) + (100 if v["icon_url"] else 0) + (50 if v["repo_url"] else 0)

        presentation_variant = max(
            variants,
            key=lambda v: (len(image_list(v)), richness(v), int(v["is_official"] or 0), int(v["dalamud_api_level"] or 0), version_key(str(v["assembly_version"] or ""))),
        )
        preferred_variant = max(
            variants,
            key=lambda v: (int(v["is_official"] or 0), int(v["dalamud_api_level"] or 0), version_key(str(v["assembly_version"] or "")), richness(v)),
        )
        images = image_list(presentation_variant)
        native_desc = str(presentation_variant["description"] or "").strip()
        web_desc = str(presentation_variant["website_description"] or "").strip()
        summary = str(presentation_variant["punchline"] or "").strip() or native_desc or web_desc
        description = native_desc if len(native_desc) >= 120 or not web_desc else (web_desc if len(web_desc) > len(native_desc) else native_desc)
        tags = parse_json_array(presentation_variant["tags_json"]) + parse_json_array(presentation_variant["category_tags_json"])
        nsfw = is_adult_content(
            tags,
            [
                presentation_variant["name"], presentation_variant["punchline"], native_desc, web_desc,
                presentation_variant["readme_excerpt"],
            ],
        )
        official = any(int(v["is_official"] or 0) for v in variants)
        web_enriched = any(int(v["website_ok"] or 0) for v in variants)
        score = richness(presentation_variant)
        rich_card = int(bool(images) and bool(summary) and bool(presentation_variant["icon_url"]))
        db.execute(
            """INSERT INTO presentation(plugin_id,preferred_variant_id,presentation_variant_id,rich_card,web_enriched,official,nsfw,richness_score,image_urls_json,summary,description)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (pid, int(preferred_variant["variant_id"]), int(presentation_variant["variant_id"]), rich_card, int(web_enriched), int(official), int(nsfw), score, json_text(images), summary, description),
        )
        db.execute("UPDATE plugins SET canonical_name=?,last_seen_utc=?,active=1 WHERE plugin_id=?", (str(preferred_variant["name"]), now, pid))
        search_tags = " ".join(sorted(set(tags), key=str.lower))
        website_text = " ".join([str(presentation_variant["website_description"] or ""), str(presentation_variant["readme_excerpt"] or "")])
        db.execute(
            "INSERT INTO plugin_search(plugin_id,internal_name,name,author,punchline,description,tags,website_text) VALUES(?,?,?,?,?,?,?,?)",
            (pid, str(prow["internal_name"]), str(preferred_variant["name"]), str(preferred_variant["author"]), summary, description, search_tags, website_text),
        )


def create_runtime_view(db: sqlite3.Connection) -> None:
    db.execute("DROP VIEW IF EXISTS runtime_plugin_variants")
    db.execute(
        """CREATE VIEW runtime_plugin_variants AS
           SELECT
             v.variant_id,
             p.plugin_id,
             p.internal_name,
             v.author,
             v.name,
             v.punchline,
             v.description,
             v.changelog,
             v.assembly_version,
             v.testing_assembly_version,
             v.dalamud_api_level,
             v.testing_dalamud_api_level,
             v.applicable_version,
             v.minimum_dalamud_version,
             v.repo_url,
             v.download_link_install,
             v.download_link_update,
             v.download_link_testing,
             v.icon_url,
             v.image_urls_json,
             v.tags_json,
             v.category_tags_json,
             v.download_count,
             v.last_update,
             v.is_hide,
             v.is_testing_exclusive,
             v.dip17_channel,
             s.name AS source_name,
             s.url AS source_url,
             s.is_official AS source_is_official,
             COALESCE(w.url,'') AS website_url,
             COALESCE(w.title,'') AS website_title,
             COALESCE(w.description,'') AS website_description,
             COALESCE(w.readme_excerpt,'') AS website_readme_excerpt,
             COALESCE(w.image_urls_json,'[]') AS website_image_urls_json,
             CASE WHEN w.website_id IS NOT NULL AND w.ok=1 THEN 1 ELSE 0 END AS website_enriched,
             COALESCE(pr.rich_card,0) AS rich_card,
             COALESCE(pr.official,0) AS plugin_official,
             COALESCE(pr.nsfw,0) AS plugin_nsfw,
             COALESCE(pr.richness_score,0) AS richness_score,
             CASE WHEN pr.presentation_variant_id=v.variant_id THEN 1 ELSE 0 END AS is_presentation_variant,
             CASE WHEN pr.preferred_variant_id=v.variant_id THEN 1 ELSE 0 END AS is_preferred_variant,
             COALESCE(sc.status,'') AS security_status,
             COALESCE(sc.scanned_at_utc,'') AS security_scanned_at_utc,
             COALESCE(sc.artifact_sha256,'') AS security_artifact_sha256,
             COALESCE(sc.scanner_version,'') AS security_scanner_version,
             COALESCE(sc.highest_severity,'none') AS security_highest_severity,
             COALESCE(sc.informational_count,0) AS security_informational_count,
             COALESCE(sc.caution_count,0) AS security_caution_count,
             COALESCE(sc.high_count,0) AS security_high_count,
             COALESCE(sc.critical_count,0) AS security_critical_count,
             COALESCE(sc.capabilities_json,'[]') AS security_capabilities_json,
             COALESCE(sc.automation_level,'none') AS security_automation_level,
             COALESCE(sc.automation_capabilities_json,'[]') AS security_automation_capabilities_json,
             COALESCE(sc.findings_json,'[]') AS security_findings_json,
             COALESCE(sc.source_available,0) AS security_source_available,
             COALESCE(sc.source_repository,'') AS security_source_repository,
             COALESCE(sc.source_commit,'') AS security_source_commit,
             COALESCE(sc.source_to_binary_verified,0) AS security_source_to_binary_verified,
             COALESCE(sc.error,'') AS security_error
           FROM plugin_variants v
           JOIN plugins p ON p.plugin_id=v.plugin_id
           JOIN sources s ON s.source_id=v.source_id
           LEFT JOIN websites w ON w.url=v.repo_url COLLATE NOCASE
           LEFT JOIN presentation pr ON pr.plugin_id=p.plugin_id
           LEFT JOIN plugin_security_current sc ON sc.variant_id=v.variant_id
           WHERE v.active=1 AND p.active=1"""
    )


def validate_database(db: sqlite3.Connection) -> None:
    integrity = db.execute("PRAGMA integrity_check").fetchone()
    if integrity is None or str(integrity[0]).lower() != "ok":
        raise RuntimeError(f"SQLite integrity_check failed: {integrity}")
    schema = db.execute("SELECT value FROM catalog_meta WHERE key='schema_version'").fetchone()
    if schema is None or int(schema[0]) != SCHEMA_VERSION:
        raise RuntimeError("catalog schema version missing or invalid")
    plugins = int(db.execute("SELECT COUNT(*) FROM plugins WHERE active=1").fetchone()[0])
    variants = int(db.execute("SELECT COUNT(*) FROM plugin_variants WHERE active=1").fetchone()[0])
    if plugins <= 0 or variants <= 0:
        raise RuntimeError("catalog contains no active plugins/variants")


def export_debug(db: sqlite3.Connection, out_dir: Path) -> None:
    debug = out_dir / "debug"
    debug.mkdir(parents=True, exist_ok=True)
    sources = [dict(r) for r in db.execute("SELECT * FROM sources ORDER BY name COLLATE NOCASE,url COLLATE NOCASE")]
    plugins = [dict(r) for r in db.execute("SELECT * FROM plugins WHERE active=1 ORDER BY canonical_name COLLATE NOCASE")]
    websites = [dict(r) for r in db.execute("SELECT * FROM websites ORDER BY url COLLATE NOCASE")]
    presentation = [dict(r) for r in db.execute("SELECT * FROM presentation ORDER BY plugin_id")]
    (debug / "sources.json").write_text(json.dumps(sources, ensure_ascii=False, indent=2), encoding="utf-8")
    (debug / "plugins.json").write_text(json.dumps(plugins, ensure_ascii=False, indent=2), encoding="utf-8")
    (debug / "websites.json").write_text(json.dumps(websites, ensure_ascii=False, indent=2), encoding="utf-8")
    (debug / "presentation.json").write_text(json.dumps(presentation, ensure_ascii=False, indent=2), encoding="utf-8")


def build(args: argparse.Namespace) -> dict:
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = out_dir / DB_FILENAME
    db_path.unlink(missing_ok=True)
    seed = Path(args.seed) if args.seed else None
    seeded = copy_seed_database(seed, db_path)
    db = reset_database(db_path)
    now = utc_now()
    parent_catalog_revision = read_meta(db, "catalog_revision")
    parent_security_revision = read_meta(db, "security_revision")
    try:
        ensure_revision_schema(db)
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('schema_name',?)", (SCHEMA_NAME,))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('generated_at_utc',?)", (now,))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('seeded',?)", ("1" if seeded else "0",))
        curated = source_definition_map(load_json(Path(args.curated) if args.curated else None, []))
        community = source_definition_map(load_json(Path(args.community) if args.community else None, []))
        source_definitions = dict(community)
        source_definitions.update(curated)  # curated metadata wins on duplicate URLs
        raw_doc = load_json(Path(args.raw_sources) if args.raw_sources else None, {"sources": []})
        enriched_doc = load_json(Path(args.enriched_sources) if args.enriched_sources else None, {"sources": []})
        website_doc = load_json(Path(args.website_enrichment) if args.website_enrichment else None, {"repos": {}})
        upsert_sources(db, raw_doc, source_definitions, now)
        import_enriched(db, enriched_doc, now)
        import_websites(db, website_doc, now)
        sanitize_seeded_plugin_presentation_fields(db)
        sanitize_seeded_website_cache(db)
        recompute_presentation(db, now)
        create_runtime_view(db)
        base_revision = compute_catalog_base_revision(db)
        write_meta(db, "catalog_base_revision", base_revision)
        write_meta(db, "catalog_parent_revision", parent_catalog_revision)
        write_meta(db, "security_parent_revision", parent_security_revision)
        db.execute("ANALYZE")
        db.commit()
        validate_database(db)
        counts = {
            "plugins": int(db.execute("SELECT COUNT(*) FROM plugins WHERE active=1").fetchone()[0]),
            "variants": int(db.execute("SELECT COUNT(*) FROM plugin_variants WHERE active=1").fetchone()[0]),
            "sources": int(db.execute("SELECT COUNT(*) FROM sources").fetchone()[0]),
            "websites": int(db.execute("SELECT COUNT(*) FROM websites WHERE ok=1").fetchone()[0]),
            "richCards": int(db.execute("SELECT COUNT(*) FROM presentation WHERE rich_card=1").fetchone()[0]),
            "securityScanned": int(db.execute("SELECT COUNT(*) FROM plugin_security_current WHERE status='complete'").fetchone()[0]),
            "securityHighOrCritical": int(db.execute("SELECT COUNT(*) FROM plugin_security_current WHERE status='complete' AND highest_severity IN ('high','critical')").fetchone()[0]),
        }
        export_debug(db, out_dir)
    finally:
        db.close()

    # Compact only after closing normal transaction work.
    with closing(sqlite3.connect(db_path)) as compact:
        compact.execute("VACUUM")
        compact.execute("PRAGMA optimize")
        validate_database(compact)

    catalog_sha = sha256_file(db_path)
    zip_path = out_dir / ZIP_FILENAME
    zip_path.unlink(missing_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.write(db_path, DB_FILENAME)
    bundle_sha = sha256_file(zip_path)
    descriptor = {
        "schemaVersion": 1,
        "schema": SCHEMA_NAME,
        "generatedAtUtc": now,
        "downloadUrl": args.download_url,
        "catalogSha256": catalog_sha,
        "bundleSha256": bundle_sha,
        "size": zip_path.stat().st_size,
        "databaseBytes": db_path.stat().st_size,
        "pluginCount": counts["plugins"],
        "variantCount": counts["variants"],
        "sourceCount": counts["sources"],
        "websiteCount": counts["websites"],
        "richCardCount": counts["richCards"],
        "securityScanCount": counts["securityScanned"],
        "securityHighOrCriticalCount": counts["securityHighOrCritical"],
        "catalogBaseRevision": base_revision,
        "parentCatalogRevision": parent_catalog_revision,
        "parentSecurityRevision": parent_security_revision,
    }
    (out_dir / "catalog.json").write_text(json.dumps(descriptor, indent=2) + "\n", encoding="utf-8")
    (out_dir / f"{ZIP_FILENAME}.sha256").write_text(f"{bundle_sha}  {ZIP_FILENAME}\n", encoding="utf-8")
    endpoint = {"schemaVersion": 1, "descriptorUrl": args.descriptor_url}
    (out_dir / "catalog-endpoint.json").write_text(json.dumps(endpoint, indent=2) + "\n", encoding="utf-8")
    report = {"generatedAtUtc": now, "seeded": seeded, **counts, "catalogBaseRevision": base_revision, "parentCatalogRevision": parent_catalog_revision, "parentSecurityRevision": parent_security_revision, "catalogSha256": catalog_sha, "bundleSha256": bundle_sha}
    (out_dir / "catalog-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="Build Omega SQLite catalog")
    ap.add_argument("--out", default="catalog/dist")
    ap.add_argument("--seed", default="")
    ap.add_argument("--curated", default="sources/curated-sources.json")
    ap.add_argument("--community", default="sources/community-sources.json")
    ap.add_argument("--raw-sources", default="catalog/raw-sources.json")
    ap.add_argument("--enriched-sources", default="catalog/enriched-sources.json")
    ap.add_argument("--website-enrichment", default="catalog/website-enrichment.json")
    ap.add_argument("--download-url", required=True)
    ap.add_argument("--descriptor-url", required=True)
    args = ap.parse_args()
    report = build(args)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

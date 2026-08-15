#!/usr/bin/env python3
"""Semantic revision and changelog support for Omega's SQLite catalog.

Revision IDs intentionally ignore transport hashes, timestamps, scan timestamps and compaction
metadata. Catalog Revision identifies the current logical marketplace + security state. Security
Revision identifies the current static-analysis state. Historical scan rows remain in SQLite, but
re-checking an unchanged artifact does not create a new semantic revision by itself.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

CATALOG_REVISION_SCHEMA = "omega.catalog-revision.v1"
SECURITY_REVISION_SCHEMA = "omega.security-revision.v1"
CHANGELOG_SCHEMA = "omega.catalog-changelog.v1"

JSON_COLUMNS = {
    "image_urls_json", "tags_json", "category_tags_json", "topics_json", "metadata_json",
    "capabilities_json", "findings_json", "evidence_json", "versions_json", "source_only_json",
    "artifact_only_json", "version_mismatches_json", "requirement_mismatches_json",
}

CHANGELOG_SQL = """
CREATE TABLE IF NOT EXISTS catalog_changelog (
    changelog_id INTEGER PRIMARY KEY,
    created_at_utc TEXT NOT NULL,
    catalog_revision TEXT NOT NULL,
    previous_catalog_revision TEXT NOT NULL DEFAULT '',
    security_revision TEXT NOT NULL,
    previous_security_revision TEXT NOT NULL DEFAULT '',
    schema_version TEXT NOT NULL DEFAULT '',
    scanner_version TEXT NOT NULL DEFAULT '',
    compactor_version TEXT NOT NULL DEFAULT '',
    plugins_added INTEGER NOT NULL DEFAULT 0,
    plugins_removed INTEGER NOT NULL DEFAULT 0,
    plugins_updated INTEGER NOT NULL DEFAULT 0,
    sources_added INTEGER NOT NULL DEFAULT 0,
    sources_removed INTEGER NOT NULL DEFAULT 0,
    sources_updated INTEGER NOT NULL DEFAULT 0,
    security_variants_added INTEGER NOT NULL DEFAULT 0,
    security_variants_removed INTEGER NOT NULL DEFAULT 0,
    security_variants_changed INTEGER NOT NULL DEFAULT 0,
    security_findings_added INTEGER NOT NULL DEFAULT 0,
    security_findings_removed INTEGER NOT NULL DEFAULT 0,
    security_findings_changed INTEGER NOT NULL DEFAULT 0,
    dependencies_added INTEGER NOT NULL DEFAULT 0,
    dependencies_removed INTEGER NOT NULL DEFAULT 0,
    dependencies_changed INTEGER NOT NULL DEFAULT 0,
    change_reason TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_catalog_changelog_revision ON catalog_changelog(catalog_revision);
CREATE INDEX IF NOT EXISTS ix_catalog_changelog_created ON catalog_changelog(created_at_utc DESC);
"""


def table_exists(db: sqlite3.Connection, name: str) -> bool:
    row = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return row is not None


def ensure_revision_schema(db: sqlite3.Connection) -> None:
    db.executescript(CHANGELOG_SQL)
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('catalog_revision_schema',?)", (CATALOG_REVISION_SCHEMA,))
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_revision_schema',?)", (SECURITY_REVISION_SCHEMA,))
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('catalog_changelog_schema',?)", (CHANGELOG_SCHEMA,))


def read_meta(db: sqlite3.Connection, key: str, default: str = "") -> str:
    if not table_exists(db, "catalog_meta"):
        return default
    row = db.execute("SELECT value FROM catalog_meta WHERE key=?", (key,)).fetchone()
    return str(row[0]) if row is not None and row[0] is not None else default


def write_meta(db: sqlite3.Connection, key: str, value: str) -> None:
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES(?,?)", (key, value))


def _canonical_json(value: Any) -> str:
    text = "" if value is None else str(value)
    if not text:
        return ""
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return text
    return json.dumps(parsed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _normalized_value(name: str, value: Any) -> Any:
    if value is None:
        return None
    if name in JSON_COLUMNS or name.endswith("_json"):
        return _canonical_json(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


def _hash_queries(schema: str, db: sqlite3.Connection, queries: Iterable[tuple[str, str]]) -> str:
    digest = hashlib.sha256()
    digest.update(schema.encode("utf-8"))
    digest.update(b"\n")
    for label, sql in queries:
        digest.update(label.encode("utf-8"))
        digest.update(b"\n")
        cursor = db.execute(sql)
        names = [str(item[0]) for item in cursor.description or []]
        for row in cursor:
            payload = [_normalized_value(names[i], row[i]) for i in range(len(names))]
            digest.update(json.dumps(payload, sort_keys=False, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            digest.update(b"\n")
    return digest.hexdigest()


BASE_QUERIES: tuple[tuple[str, str], ...] = (
    ("sources", """
        SELECT url,provider,curated_id,name,description,kind,discovered_by,source_repo_url,
               is_official,enabled_by_default,integrate_with_dalamud,content_sha256,plugin_count,highest_api
          FROM sources ORDER BY url COLLATE NOCASE
    """),
    ("plugins", """
        SELECT internal_name,canonical_name,active FROM plugins ORDER BY internal_name COLLATE NOCASE
    """),
    ("variants", """
        SELECT p.internal_name,s.url AS source_url,v.source_entry_key,v.author,v.name,v.punchline,v.description,
               v.changelog,v.assembly_version,v.testing_assembly_version,v.dalamud_api_level,
               v.testing_dalamud_api_level,v.applicable_version,v.minimum_dalamud_version,v.repo_url,
               v.download_link_install,v.download_link_update,v.download_link_testing,v.icon_url,
               v.image_urls_json,v.tags_json,v.category_tags_json,v.download_count,v.last_update,v.is_hide,
               v.is_testing_exclusive,v.dip17_channel,v.active
          FROM plugin_variants v
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
         ORDER BY p.internal_name COLLATE NOCASE,s.url COLLATE NOCASE,v.source_entry_key
    """),
    ("tags", """
        SELECT p.internal_name,s.url AS source_url,v.source_entry_key,t.tag,t.kind
          FROM plugin_tags t
          JOIN plugin_variants v ON v.variant_id=t.variant_id
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
         ORDER BY p.internal_name COLLATE NOCASE,s.url COLLATE NOCASE,v.source_entry_key,t.kind,t.tag COLLATE NOCASE
    """),
    ("images", """
        SELECT p.internal_name,s.url AS source_url,v.source_entry_key,i.url,i.image_kind,i.ordinal,i.source_kind
          FROM plugin_images i
          JOIN plugin_variants v ON v.variant_id=i.variant_id
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
         ORDER BY p.internal_name COLLATE NOCASE,s.url COLLATE NOCASE,v.source_entry_key,i.image_kind,i.ordinal,i.url
    """),
    ("websites", """
        SELECT url,ok,title,description,homepage,stars,forks,watchers,topics_json,language,license,default_branch,
               last_commit_utc,readme_excerpt,image_urls_json
          FROM websites ORDER BY url COLLATE NOCASE
    """),
    ("presentation", """
        SELECT p.internal_name,
               pp.internal_name AS preferred_internal_name,sp.url AS preferred_source_url,vp.source_entry_key AS preferred_source_entry_key,
               prp.internal_name AS presentation_internal_name,spr.url AS presentation_source_url,vpr.source_entry_key AS presentation_source_entry_key,
               x.rich_card,x.web_enriched,x.official,x.nsfw,x.richness_score,x.image_urls_json,x.summary,x.description
          FROM presentation x
          JOIN plugins p ON p.plugin_id=x.plugin_id
          JOIN plugin_variants vp ON vp.variant_id=x.preferred_variant_id
          JOIN plugins pp ON pp.plugin_id=vp.plugin_id
          JOIN sources sp ON sp.source_id=vp.source_id
          JOIN plugin_variants vpr ON vpr.variant_id=x.presentation_variant_id
          JOIN plugins prp ON prp.plugin_id=vpr.plugin_id
          JOIN sources spr ON spr.source_id=vpr.source_id
         ORDER BY p.internal_name COLLATE NOCASE
    """),
)


def compute_catalog_base_revision(db: sqlite3.Connection) -> str:
    digest = _hash_queries(CATALOG_REVISION_SCHEMA + ":base", db, BASE_QUERIES)
    return f"base-v1-{digest[:16]}"


def _current_variant_prefix(alias: str = "c") -> str:
    return f"""
        FROM plugin_security_current {alias}
        JOIN plugin_variants v ON v.variant_id={alias}.variant_id
        JOIN plugins p ON p.plugin_id=v.plugin_id
        JOIN sources src ON src.source_id=v.source_id
    """


def _child_current_query(table: str, alias: str, columns: str, order: str) -> str:
    return f"""
        SELECT p.internal_name,src.url AS source_url,v.source_entry_key,{columns}
          FROM {table} {alias}
          JOIN plugin_security_current c ON c.scan_id={alias}.scan_id
          JOIN plugin_variants v ON v.variant_id=c.variant_id
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources src ON src.source_id=v.source_id
         ORDER BY p.internal_name COLLATE NOCASE,src.url COLLATE NOCASE,v.source_entry_key,{order}
    """


SECURITY_QUERY_BUILDERS: tuple[tuple[str, str], ...] = (
    ("current", """
        SELECT p.internal_name,src.url AS source_url,v.source_entry_key,c.assembly_version,c.artifact_channel,
               c.artifact_sha256,c.scanner_version,c.status,c.highest_severity,c.informational_count,c.caution_count,
               c.high_count,c.critical_count,c.capabilities_json,c.findings_json,c.source_available,c.source_repository,
               c.source_commit,c.source_to_binary_verified
          FROM plugin_security_current c
          JOIN plugin_variants v ON v.variant_id=c.variant_id
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources src ON src.source_id=v.source_id
         ORDER BY p.internal_name COLLATE NOCASE,src.url COLLATE NOCASE,v.source_entry_key
    """),
    ("findings", _child_current_query(
        "plugin_security_findings", "f",
        "f.rule_id,f.severity,f.category,f.title,f.description,f.evidence_json",
        "f.rule_id,f.severity,f.category,f.title,f.evidence_json"
    )),
    ("dependencies", _child_current_query(
        "plugin_security_dependencies", "d",
        "d.origin,d.kind,d.name,d.version,d.version_requirement,d.resolved_version,d.path,d.status,d.requirement,d.evidence_json",
        "d.origin,d.kind,d.name COLLATE NOCASE,d.path,d.requirement,d.version,d.version_requirement,d.resolved_version,d.evidence_json"
    )),
    ("imports", _child_current_query(
        "plugin_security_imports", "i", "i.origin,i.namespace,i.path", "i.origin,i.namespace COLLATE NOCASE,i.path"
    )),
    ("permission_candidates", _child_current_query(
        "plugin_security_permission_candidates", "pc",
        "pc.origin,pc.permission_id,pc.risk,pc.confidence,pc.reason,pc.evidence_json",
        "pc.origin,pc.permission_id,pc.risk,pc.confidence,pc.reason,pc.evidence_json"
    )),
    ("managed_assemblies", _child_current_query(
        "plugin_security_managed_assemblies", "ma",
        "ma.origin,ma.path,ma.sha256,ma.assembly_name,ma.assembly_version,ma.metadata_version,ma.parse_status,"
        "ma.reference_count,ma.type_reference_count,ma.member_reference_count,ma.native_import_count,ma.truncated,ma.error",
        "ma.origin,ma.path,ma.sha256,ma.assembly_name,ma.assembly_version"
    )),
    ("managed_symbols", _child_current_query(
        "plugin_security_managed_symbols", "ms",
        "ms.origin,ms.path,ms.symbol_kind,ms.declaring_type,ms.name,ms.assembly_name,ms.evidence_json",
        "ms.origin,ms.path,ms.symbol_kind,ms.declaring_type,ms.name,ms.assembly_name,ms.evidence_json"
    )),
    ("managed_calls", _child_current_query(
        "plugin_security_managed_calls", "mc",
        "mc.origin,mc.path,mc.source_method_token,mc.source_declaring_type,mc.source_method_name,mc.il_offset,mc.opcode,"
        "mc.target_token,mc.target_kind,mc.target_declaring_type,mc.target_name,mc.target_assembly_name,"
        "mc.target_native_library,mc.target_native_entry_point,mc.target_method_token,mc.evidence_json",
        "mc.origin,mc.path,mc.source_method_token,mc.il_offset,mc.opcode,mc.target_token,mc.target_method_token,mc.evidence_json"
    )),
    ("managed_reachability", _child_current_query(
        "plugin_security_managed_reachability", "mr",
        "mr.origin,mr.path,mr.root_method_token,mr.root_declaring_type,mr.root_method_name,mr.root_kind,mr.root_confidence,"
        "mr.method_token,mr.method_declaring_type,mr.method_name,mr.depth,mr.via_method_token,mr.via_il_offset,mr.evidence_json",
        "mr.origin,mr.path,mr.root_method_token,mr.method_token,mr.depth,mr.via_method_token,mr.via_il_offset,mr.evidence_json"
    )),
    ("source_artifact_comparisons", _child_current_query(
        "plugin_security_source_artifact_comparisons", "sa",
        "sa.source_available,sa.source_dependency_count,sa.artifact_dependency_count,sa.matched_component_count,"
        "sa.source_only_count,sa.artifact_only_count,sa.version_mismatch_count,sa.requirement_mismatch_count,"
        "sa.source_project_sha256,sa.artifact_project_sha256,sa.comparison_status,sa.source_only_json,sa.artifact_only_json,"
        "sa.version_mismatches_json,sa.requirement_mismatches_json",
        "sa.comparison_status,sa.source_project_sha256,sa.artifact_project_sha256"
    )),
    ("dependency_resolutions", """
        SELECT p.internal_name,src.url AS source_url,v.source_entry_key,r.dependency_kind,r.dependency_name,
               r.dependency_version,r.version_requirement,r.resolved_version,r.normalized_name,r.component_key,r.requirement,
               r.resolution_status,r.version_status,r.target_internal_name,r.target_variant_count,r.target_version,
               r.confidence,r.match_basis,r.evidence_json
          FROM plugin_security_dependency_resolutions r
          JOIN plugin_security_current c ON c.scan_id=r.scan_id AND c.variant_id=r.source_variant_id
          JOIN plugin_variants v ON v.variant_id=c.variant_id
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources src ON src.source_id=v.source_id
         ORDER BY p.internal_name COLLATE NOCASE,src.url COLLATE NOCASE,v.source_entry_key,r.component_key COLLATE NOCASE,
                  r.dependency_kind,r.dependency_name COLLATE NOCASE,r.requirement,r.version_requirement,r.resolved_version
    """),
    ("dependency_components", """
        SELECT component_key,component_kind,display_name,normalized_name,current_usage_count,source_plugin_count,
               source_variant_count,required_count,soft_count,optional_count,bundled_count,observed_count,unknown_count,
               versions_json,distinct_version_count,version_divergence
          FROM plugin_security_dependency_components ORDER BY component_key COLLATE NOCASE
    """),
    ("dependency_issues", """
        SELECT COALESCE(p.internal_name,''),COALESCE(src.url,''),COALESCE(v.source_entry_key,''),i.component_key,i.issue_code,
               i.severity,i.title,i.detail,i.requirement,i.version_requirement,i.observed_version,i.target_version,i.evidence_json
          FROM plugin_security_dependency_issues i
          LEFT JOIN plugin_variants v ON v.variant_id=i.source_variant_id
          LEFT JOIN plugins p ON p.plugin_id=v.plugin_id
          LEFT JOIN sources src ON src.source_id=v.source_id
         ORDER BY COALESCE(p.internal_name,'') COLLATE NOCASE,COALESCE(src.url,'') COLLATE NOCASE,
                  COALESCE(v.source_entry_key,''),i.component_key COLLATE NOCASE,i.issue_code,i.title
    """),
    ("advisory_matches", """
        SELECT advisory_id,component_key,component_kind,component_name,affected_version,affected_range,fixed_version,
               severity,title,advisory_url,advisory_source
          FROM plugin_security_dependency_advisory_matches
         ORDER BY advisory_id,component_key COLLATE NOCASE,affected_version,affected_range
    """),
)


def compute_security_revision(db: sqlite3.Connection) -> str:
    scanner_version = read_meta(db, "security_scanner_version", "unknown") or "unknown"
    # Older/pre-security catalogs have only the baseline tables. Treat that as a stable empty state.
    required = ("plugin_security_current", "plugin_security_findings", "plugin_security_dependencies")
    if not all(table_exists(db, name) for name in required):
        digest = hashlib.sha256((SECURITY_REVISION_SCHEMA + ":empty:" + scanner_version).encode("utf-8")).hexdigest()
    else:
        available_queries = []
        for label, sql in SECURITY_QUERY_BUILDERS:
            # Each query's first table name follows FROM. Skip optional tables absent in older seeds.
            tokens = sql.replace("\n", " ").split()
            table = ""
            if "FROM" in tokens:
                table = tokens[tokens.index("FROM") + 1]
            if table and not table_exists(db, table):
                continue
            available_queries.append((label, sql))
        digest = _hash_queries(SECURITY_REVISION_SCHEMA + ":" + scanner_version, db, available_queries)
    safe_version = "".join(ch if ch.isalnum() or ch in ".-_" else "-" for ch in scanner_version)[:24] or "unknown"
    return f"sec-{safe_version}-{digest[:16]}"


def compute_catalog_revision(db: sqlite3.Connection, base_revision: str | None = None, security_revision: str | None = None) -> str:
    base = base_revision or compute_catalog_base_revision(db)
    security = security_revision or compute_security_revision(db)
    schema_version = read_meta(db, "schema_version", "")
    payload = f"{CATALOG_REVISION_SCHEMA}\n{schema_version}\n{base}\n{security}\n"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"cat-v1-{digest[:16]}"


def update_candidate_revisions(db: sqlite3.Connection) -> dict[str, str]:
    ensure_revision_schema(db)
    base_revision = compute_catalog_base_revision(db)
    security_revision = compute_security_revision(db)
    catalog_revision = compute_catalog_revision(db, base_revision, security_revision)
    write_meta(db, "catalog_base_revision", base_revision)
    write_meta(db, "security_revision_candidate", security_revision)
    write_meta(db, "catalog_revision_candidate", catalog_revision)
    return {
        "baseRevision": base_revision,
        "securityRevision": security_revision,
        "catalogRevision": catalog_revision,
    }


def finalize_revisions(db: sqlite3.Connection) -> dict[str, str]:
    revisions = update_candidate_revisions(db)
    write_meta(db, "security_revision", revisions["securityRevision"])
    write_meta(db, "catalog_revision", revisions["catalogRevision"])
    return revisions


def _digest_map(db: sqlite3.Connection, sql: str, key_columns: int, json_columns: set[int] | None = None) -> dict[str, str]:
    json_columns = json_columns or set()
    result: dict[str, str] = {}
    for row in db.execute(sql):
        key = "\x1f".join("" if row[i] is None else str(row[i]) for i in range(key_columns))
        values = []
        for i in range(key_columns, len(row)):
            value = row[i]
            values.append(_canonical_json(value) if i in json_columns else value)
        result[key] = hashlib.sha256(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
    return result


def _diff_maps(previous: dict[str, str], current: dict[str, str]) -> tuple[int, int, int]:
    previous_keys = set(previous)
    current_keys = set(current)
    added = len(current_keys - previous_keys)
    removed = len(previous_keys - current_keys)
    updated = sum(1 for key in previous_keys & current_keys if previous[key] != current[key])
    return added, removed, updated


def _multiset(db: sqlite3.Connection, sql: str) -> Counter[str]:
    result: Counter[str] = Counter()
    for row in db.execute(sql):
        payload = []
        for value in row:
            text = "" if value is None else str(value)
            if text.startswith("{") or text.startswith("["):
                text = _canonical_json(text)
            payload.append(text)
        result[json.dumps(payload, ensure_ascii=False, separators=(",", ":"))] += 1
    return result


def _diff_multisets(previous: Counter[str], current: Counter[str]) -> tuple[int, int]:
    added = sum((current - previous).values())
    removed = sum((previous - current).values())
    return added, removed


def change_summary(previous: sqlite3.Connection | None, current: sqlite3.Connection) -> dict[str, int]:
    plugin_sql = "SELECT internal_name,canonical_name,active FROM plugins ORDER BY internal_name COLLATE NOCASE"
    source_sql = """
        SELECT url,provider,curated_id,name,description,kind,source_repo_url,is_official,enabled_by_default,
               integrate_with_dalamud,content_sha256,plugin_count,highest_api FROM sources ORDER BY url COLLATE NOCASE
    """
    security_sql = """
        SELECT p.internal_name,src.url,v.source_entry_key,c.assembly_version,c.artifact_channel,c.artifact_sha256,
               c.scanner_version,c.status,c.highest_severity,c.informational_count,c.caution_count,c.high_count,
               c.critical_count,c.capabilities_json,c.findings_json,c.source_available,c.source_repository,c.source_commit,
               c.source_to_binary_verified
          FROM plugin_security_current c JOIN plugin_variants v ON v.variant_id=c.variant_id
          JOIN plugins p ON p.plugin_id=v.plugin_id JOIN sources src ON src.source_id=v.source_id
         ORDER BY p.internal_name COLLATE NOCASE,src.url COLLATE NOCASE,v.source_entry_key
    """
    findings_sql = """
        SELECT p.internal_name,src.url,v.source_entry_key,f.rule_id,f.severity,f.category,f.title,f.description,f.evidence_json
          FROM plugin_security_findings f JOIN plugin_security_current c ON c.scan_id=f.scan_id
          JOIN plugin_variants v ON v.variant_id=c.variant_id JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources src ON src.source_id=v.source_id
         ORDER BY p.internal_name COLLATE NOCASE,src.url COLLATE NOCASE,v.source_entry_key,f.rule_id,f.title,f.evidence_json
    """
    dependencies_sql = """
        SELECT p.internal_name,src.url,v.source_entry_key,d.origin,d.kind,d.name,d.version,d.version_requirement,
               d.resolved_version,d.path,d.status,d.requirement,d.evidence_json
          FROM plugin_security_dependencies d JOIN plugin_security_current c ON c.scan_id=d.scan_id
          JOIN plugin_variants v ON v.variant_id=c.variant_id JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources src ON src.source_id=v.source_id
         ORDER BY p.internal_name COLLATE NOCASE,src.url COLLATE NOCASE,v.source_entry_key,d.origin,d.kind,d.name,d.path,d.evidence_json
    """

    prev_plugins = _digest_map(previous, plugin_sql, 1) if previous and table_exists(previous, "plugins") else {}
    curr_plugins = _digest_map(current, plugin_sql, 1)
    prev_sources = _digest_map(previous, source_sql, 1) if previous and table_exists(previous, "sources") else {}
    curr_sources = _digest_map(current, source_sql, 1)
    prev_security = _digest_map(previous, security_sql, 3, {13, 14}) if previous and table_exists(previous, "plugin_security_current") else {}
    curr_security = _digest_map(current, security_sql, 3, {13, 14}) if table_exists(current, "plugin_security_current") else {}
    p_add, p_remove, p_update = _diff_maps(prev_plugins, curr_plugins)
    s_add, s_remove, s_update = _diff_maps(prev_sources, curr_sources)
    sec_add, sec_remove, sec_update = _diff_maps(prev_security, curr_security)

    prev_findings = _multiset(previous, findings_sql) if previous and table_exists(previous, "plugin_security_findings") else Counter()
    curr_findings = _multiset(current, findings_sql) if table_exists(current, "plugin_security_findings") else Counter()
    finding_add, finding_remove = _diff_multisets(prev_findings, curr_findings)

    prev_dependencies = _multiset(previous, dependencies_sql) if previous and table_exists(previous, "plugin_security_dependencies") else Counter()
    curr_dependencies = _multiset(current, dependencies_sql) if table_exists(current, "plugin_security_dependencies") else Counter()
    dep_add, dep_remove = _diff_multisets(prev_dependencies, curr_dependencies)

    # A changed finding/dependency appears as one removed + one added canonical row. Keep a conservative
    # changed count while still exposing the raw added/removed counts in details_json.
    finding_changed = min(finding_add, finding_remove)
    dependency_changed = min(dep_add, dep_remove)
    return {
        "pluginsAdded": p_add, "pluginsRemoved": p_remove, "pluginsUpdated": p_update,
        "sourcesAdded": s_add, "sourcesRemoved": s_remove, "sourcesUpdated": s_update,
        "securityVariantsAdded": sec_add, "securityVariantsRemoved": sec_remove, "securityVariantsChanged": sec_update,
        "securityFindingsAdded": finding_add, "securityFindingsRemoved": finding_remove, "securityFindingsChanged": finding_changed,
        "dependenciesAdded": dep_add, "dependenciesRemoved": dep_remove, "dependenciesChanged": dependency_changed,
    }


def append_changelog_if_changed(
    db: sqlite3.Connection,
    previous_db_path: Path | None,
    created_at_utc: str,
    compactor_version: str,
    change_reason: str = "catalog-security-refresh",
) -> dict[str, Any]:
    ensure_revision_schema(db)
    revisions = finalize_revisions(db)
    previous_db: sqlite3.Connection | None = None
    previous_catalog_revision = ""
    previous_security_revision = ""
    try:
        if previous_db_path is not None and previous_db_path.exists():
            previous_db = sqlite3.connect(previous_db_path)
            previous_db.row_factory = sqlite3.Row
            previous_catalog_revision = read_meta(previous_db, "catalog_revision")
            previous_security_revision = read_meta(previous_db, "security_revision")
        changes = change_summary(previous_db, db)
    finally:
        if previous_db is not None:
            previous_db.close()

    changed = revisions["catalogRevision"] != previous_catalog_revision
    security_changed = revisions["securityRevision"] != previous_security_revision
    write_meta(db, "previous_published_catalog_revision", previous_catalog_revision)
    write_meta(db, "previous_published_security_revision", previous_security_revision)
    write_meta(db, "catalog_revision_updated_at_utc", created_at_utc if changed else read_meta(db, "catalog_revision_updated_at_utc", created_at_utc))
    write_meta(db, "security_revision_updated_at_utc", created_at_utc if security_changed else read_meta(db, "security_revision_updated_at_utc", created_at_utc))

    if changed:
        details = {
            "schema": CHANGELOG_SCHEMA,
            "catalogRevisionSchema": CATALOG_REVISION_SCHEMA,
            "securityRevisionSchema": SECURITY_REVISION_SCHEMA,
            "baseRevision": revisions["baseRevision"],
            "changes": changes,
        }
        db.execute(
            """
            INSERT OR IGNORE INTO catalog_changelog(
                created_at_utc,catalog_revision,previous_catalog_revision,security_revision,previous_security_revision,
                schema_version,scanner_version,compactor_version,
                plugins_added,plugins_removed,plugins_updated,sources_added,sources_removed,sources_updated,
                security_variants_added,security_variants_removed,security_variants_changed,
                security_findings_added,security_findings_removed,security_findings_changed,
                dependencies_added,dependencies_removed,dependencies_changed,change_reason,details_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                created_at_utc,revisions["catalogRevision"],previous_catalog_revision,revisions["securityRevision"],previous_security_revision,
                read_meta(db, "schema_version"),read_meta(db, "security_scanner_version"),compactor_version,
                changes["pluginsAdded"],changes["pluginsRemoved"],changes["pluginsUpdated"],
                changes["sourcesAdded"],changes["sourcesRemoved"],changes["sourcesUpdated"],
                changes["securityVariantsAdded"],changes["securityVariantsRemoved"],changes["securityVariantsChanged"],
                changes["securityFindingsAdded"],changes["securityFindingsRemoved"],changes["securityFindingsChanged"],
                changes["dependenciesAdded"],changes["dependenciesRemoved"],changes["dependenciesChanged"],
                change_reason,json.dumps(details, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            ),
        )

    return {
        **revisions,
        "previousCatalogRevision": previous_catalog_revision,
        "previousSecurityRevision": previous_security_revision,
        "catalogRevisionChanged": changed,
        "securityRevisionChanged": security_changed,
        "changes": changes,
    }


def latest_changelog(db: sqlite3.Connection) -> dict[str, Any] | None:
    if not table_exists(db, "catalog_changelog"):
        return None
    row = db.execute("SELECT * FROM catalog_changelog ORDER BY changelog_id DESC LIMIT 1").fetchone()
    if row is None:
        return None
    names = [item[0] for item in db.execute("SELECT * FROM catalog_changelog LIMIT 0").description or []]
    return dict(zip(names, row))

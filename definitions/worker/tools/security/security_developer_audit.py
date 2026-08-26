#!/usr/bin/env python3
"""Independent read-only audit of the working SigmaScope SQLite evidence projection.

This is production/security-service validation tooling. It intentionally contains no
DeltaScope UI, consumer SDK, local rule store, or Investigator state dependency.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import datetime as dt
import json
from pathlib import Path
import sqlite3
import threading
import urllib.parse
from typing import Any, Iterable

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

class SecurityAuditInspector:

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

    def marketplace_security(self, variant_id: int) -> dict[str, Any] | None:
            if not self.marketplace or "marketplace_security_current" not in self.marketplace_tables:
                return None
            row = self.marketplace.execute("SELECT * FROM marketplace_security_current WHERE variant_id=?", (variant_id,)).fetchone()
            return dict(row) if row else None

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Reproduce SigmaScope security conclusions from a local working SQLite evidence database.")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--marketplace-database", type=Path)
    parser.add_argument("--advisories", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict-warnings", action="store_true")
    return parser

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    inspector = SecurityAuditInspector(args.database, args.marketplace_database, args.advisories)
    try:
        result = inspector.global_audit()
    finally:
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

if __name__ == "__main__":
    raise SystemExit(main())

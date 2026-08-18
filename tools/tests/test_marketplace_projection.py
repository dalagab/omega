from __future__ import annotations

from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import common  # noqa: F401
import compact_sqlite_catalog
import project_marketplace_catalog
import sigmascope
import validate_marketplace_catalog


class MarketplaceProjectionTests(unittest.TestCase):
    def test_sqlite_validators_use_windows_safe_temporary_paths(self) -> None:
        for name in ("validate_marketplace_catalog.py", "validate_evidence_catalog.py"):
            source = (common.ROOT / "tools" / "catalog" / name).read_text(encoding="utf-8")
            self.assertNotIn("tempfile.NamedTemporaryFile(", source, f"{name} must not keep a temporary SQLite file open on Windows")
            self.assertIn("TemporaryDirectory", source, f"{name} must materialize SQLite into a reopenable temporary path")

    def test_projection_removes_detailed_security_tables_and_keeps_runtime_projection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-test-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.execute("UPDATE plugin_variants SET repo_url='https://github.com/example/fixture' WHERE variant_id=1")
                db.execute("INSERT INTO websites(url,ok,readme_excerpt,image_urls_json) VALUES('https://github.com/example/fixture',1,'# Fixture README','[\"https://example.invalid/preview.png\"]')")
                db.execute("UPDATE plugin_security_dependencies SET kind='external-plugin',name='Fixture.Dependency',requirement='required' WHERE dependency_id=1")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('catalog_revision','cat-v1-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_revision','sec-2.0.0-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('evidence_revision','ev-v1-0123456789abcdef')")
                db.commit()
                before = project_marketplace_catalog.runtime_projection_digest(
                    db, project_marketplace_catalog.ARTIFACT_CANONICAL_RUNTIME_COLUMNS)
            out = root / "marketplace.sqlite"
            projected = project_marketplace_catalog.project_database(evidence, out)
            self.assertEqual(before, projected["runtimeProjectionSha256"])
            with closing(sqlite3.connect(out)) as db:
                leaked = db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchone()[0]
                self.assertEqual(0, leaked)
                self.assertGreater(db.execute("SELECT COUNT(*) FROM runtime_plugin_variants").fetchone()[0], 0)
                row = db.execute(
                    "SELECT website_readme_excerpt,website_image_urls_json,security_dependencies_json,security_dependency_total_count FROM runtime_plugin_variants WHERE internal_name='Fixture'"
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual("# Fixture README", row[0])
                self.assertEqual(["https://example.invalid/preview.png"], json.loads(row[1]))
                dependencies = json.loads(row[2])
                self.assertEqual("Fixture.Dependency", dependencies[0]["name"])
                self.assertGreaterEqual(row[3], 1)
                self.assertLessEqual(len(dependencies), project_marketplace_catalog.DEPENDENCY_SUMMARY_LIMIT)
                self.assertEqual("marketplace", dict(db.execute("SELECT key,value FROM catalog_meta"))["database_role"])



    def test_same_artifact_hash_projects_one_canonical_security_result(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-artifact-canonical-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.execute("UPDATE sources SET name='Puni.sh Fixture',url='https://puni.sh/fixture' WHERE source_id=1")
                baseline_findings = json.dumps([{"ruleId": "baseline", "severity": "caution"}], separators=(",", ":"))
                db.execute("UPDATE plugin_security_current SET artifact_sha256=?,highest_severity='caution',caution_count=1,high_count=0,findings_json=? WHERE variant_id=1", ("a" * 64, baseline_findings))
                db.execute("UPDATE plugin_security_scans SET artifact_sha256=? WHERE scan_id=1", ("a" * 64,))
                db.execute("UPDATE plugin_security_dependencies SET kind='external-plugin',name='BaselineDependency',requirement='required' WHERE scan_id=1")
                db.execute("INSERT INTO sources(source_id,url,name,is_official) VALUES(2,'https://mirror.invalid/repo.json','Mirror',0)")
                db.execute("""INSERT INTO plugin_variants(
                    variant_id,plugin_id,source_id,source_entry_key,name,author,assembly_version,dalamud_api_level,
                    download_link_install,first_seen_utc,last_seen_utc,active)
                    VALUES(2,1,2,'Fixture-Mirror','Fixture','Mirror author','1.0',15,'https://mirror.invalid/plugin.zip','','',1)""")
                report = json.dumps({"findings": [{"ruleId": "mirror-only", "severity": "high"}], "capabilities": ["Mirror only"]}, separators=(",", ":"))
                db.execute("""INSERT INTO plugin_security_scans(
                    scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,scanned_at_utc,
                    highest_severity,informational_count,caution_count,high_count,critical_count,capabilities_json,source_available,source_repository,source_commit,
                    source_to_binary_verified,report_json,error)
                    VALUES(2,1,2,2,'1.0','stable','https://mirror.invalid/plugin.zip',?,'2.0.0','complete','2026-01-02T00:00:00Z',
                           'high',0,0,1,0,'["Mirror only"]',0,'','',0,?, '')""", ("a" * 64, report))
                db.execute("""INSERT INTO plugin_security_current(
                    variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,scanned_at_utc,highest_severity,
                    informational_count,caution_count,high_count,critical_count,capabilities_json,findings_json,source_available,source_repository,source_commit,
                    source_to_binary_verified,report_json,error)
                    VALUES(2,2,'1.0','stable','https://mirror.invalid/plugin.zip',?,'2.0.0','complete','2026-01-02T00:00:00Z','high',
                           0,0,1,0,?, ?,0,'','',0,?, '')""", ("a" * 64, json.dumps(["Mirror only"]), json.dumps([{"ruleId": "mirror-only", "severity": "high"}], separators=(",", ":")), report))
                db.execute("INSERT INTO plugin_security_dependencies(scan_id,origin,kind,name,version,status,requirement,evidence_json) VALUES(2,'artifact','external-plugin','MirrorDependency','1.0','known','required','[]')")
                db.commit()
            out = root / "marketplace.sqlite"
            project_marketplace_catalog.project_database(evidence, out)
            with closing(sqlite3.connect(out)) as db:
                rows = db.execute("""SELECT source_name,security_artifact_sha256,security_highest_severity,security_caution_count,security_high_count,
                                            security_capabilities_json,security_findings_json,security_dependencies_json
                                       FROM runtime_plugin_variants WHERE internal_name='Fixture' ORDER BY source_name""").fetchall()
                self.assertEqual(2, len(rows))
                static_signatures = {tuple(row[1:7]) for row in rows}
                self.assertEqual(1, len(static_signatures), "same artifact SHA must project one canonical static security result")
                self.assertEqual("caution", rows[0][2])
                dependencies_by_source = {row[0]: [item["name"] for item in json.loads(row[7])] for row in rows}
                self.assertEqual(["BaselineDependency"], dependencies_by_source["Puni.sh Fixture"])
                self.assertEqual(["MirrorDependency"], dependencies_by_source["Mirror"], "source/dependency evidence must not be overwritten by artifact-static canonicalization")

    def test_same_artifact_mirrors_do_not_erase_variant_advisory_projection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-advisory-mirror-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.execute("UPDATE sources SET name='Primary',url='https://primary.invalid/repo.json' WHERE source_id=1")
                db.execute("UPDATE plugin_security_current SET artifact_sha256=? WHERE variant_id=1", ("c" * 64,))
                db.execute("UPDATE plugin_security_scans SET artifact_sha256=? WHERE scan_id=1", ("c" * 64,))
                db.execute("UPDATE plugin_security_dependencies SET kind='nuget',name='Risky.Package',version='1.2.3',resolved_version='1.2.3',requirement='required' WHERE dependency_id=1")
                db.execute("""INSERT INTO plugin_security_dependency_resolutions(
                    dependency_id,scan_id,source_plugin_id,source_variant_id,dependency_kind,dependency_name,version_requirement,
                    normalized_name,component_key,requirement,resolution_status,version_status,target_plugin_id,target_variant_id,
                    target_internal_name,target_variant_count,target_version,confidence,match_basis,evidence_json)
                    VALUES(1,1,1,1,'nuget','Risky.Package','','risky.package','nuget:risky.package','required',
                           'resolved-component','observed',NULL,NULL,'',0,'1.2.3','high','nuget-component','[]')""")
                db.execute("""INSERT INTO plugin_security_dependency_advisory_matches(
                    advisory_id,component_key,component_kind,component_name,affected_version,affected_range,fixed_version,
                    severity,title,advisory_url,advisory_source,refreshed_at_utc)
                    VALUES('OSV-MIRROR','nuget:risky.package','nuget','Risky.Package','1.2.3','','1.2.4',
                           'high','Affected','https://osv.dev/vulnerability/OSV-MIRROR','OSV','')""")
                db.execute("INSERT INTO sources(source_id,url,name,is_official) VALUES(2,'https://mirror.invalid/repo.json','Mirror',0)")
                db.execute("""INSERT INTO plugin_variants(
                    variant_id,plugin_id,source_id,source_entry_key,name,author,assembly_version,dalamud_api_level,
                    download_link_install,first_seen_utc,last_seen_utc,active)
                    VALUES(2,1,2,'Fixture-Mirror','Fixture','Mirror','1.0',15,'https://mirror.invalid/plugin.zip','','',1)""")
                mirror_report = json.dumps({"findings": [], "capabilities": []}, separators=(",", ":"))
                db.execute("""INSERT INTO plugin_security_scans(
                    scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,scanned_at_utc,
                    highest_severity,informational_count,caution_count,high_count,critical_count,capabilities_json,source_available,source_repository,source_commit,
                    source_to_binary_verified,report_json,error)
                    VALUES(2,1,2,2,'1.0','stable','https://mirror.invalid/plugin.zip',?,'2.0.0','complete','2026-01-02T00:00:00Z',
                           'none',0,0,0,0,'[]',0,'','',0,?, '')""", ("c" * 64, mirror_report))
                db.execute("""INSERT INTO plugin_security_current(
                    variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,scanned_at_utc,highest_severity,
                    informational_count,caution_count,high_count,critical_count,capabilities_json,findings_json,source_available,source_repository,source_commit,
                    source_to_binary_verified,report_json,error)
                    VALUES(2,2,'1.0','stable','https://mirror.invalid/plugin.zip',?,'2.0.0','complete','2026-01-02T00:00:00Z','none',
                           0,0,0,0,'[]','[]',0,'','',0,?, '')""", ("c" * 64, mirror_report))
                db.commit()
            out = root / "marketplace.sqlite"
            project_marketplace_catalog.project_database(evidence, out)
            with closing(sqlite3.connect(out)) as db:
                rows = db.execute("""SELECT source_name,security_known_advisory_count,security_known_advisory_highest_severity,security_risk_score
                                       FROM runtime_plugin_variants WHERE internal_name='Fixture' ORDER BY source_name""").fetchall()
        by_source = {row[0]: row[1:] for row in rows}
        self.assertEqual((1, "high", project_marketplace_catalog._security_risk_score(0, 0, 0, 0, 25)), by_source["Primary"])
        self.assertEqual((0, "none", 0), by_source["Mirror"], "artifact canonicalization must not copy a stale mirror's advisory counters over reproduced evidence")

    def test_completed_scan_history_backfills_missing_current_pointer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-history-backfill-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.execute("INSERT INTO sources(source_id,url,name,is_official) VALUES(2,'https://history.invalid/repository.json','History mirror',0)")
                db.execute("""INSERT INTO plugin_variants(
                    variant_id,plugin_id,source_id,source_entry_key,name,author,assembly_version,dalamud_api_level,
                    download_link_install,first_seen_utc,last_seen_utc,active)
                    VALUES(2,1,2,'Fixture-History','Fixture','History author','1.0',15,'https://history.invalid/plugin.zip','','',1)""")
                report = json.dumps({
                    "findings": [{"ruleId": "history", "severity": "high", "category": "fixture", "title": "history", "description": "history", "evidence": []}],
                    "automation": {"level": "none", "capabilities": []},
                }, separators=(",", ":"))
                db.execute("""INSERT INTO plugin_security_scans(
                    scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,scanned_at_utc,
                    highest_severity,informational_count,caution_count,high_count,critical_count,capabilities_json,source_available,source_repository,source_commit,
                    source_to_binary_verified,report_json,error)
                    VALUES(2,1,2,2,'1.0','stable','https://history.invalid/plugin.zip',?,'2.0.0','complete','2026-01-03T00:00:00Z',
                           'high',0,0,1,0,'[]',0,'','',0,?, '')""", ("b" * 64, report))
                # Simulate a lost/compacted per-variant current pointer: immutable scan history remains authoritative.
                self.assertIsNone(db.execute("SELECT 1 FROM plugin_security_current WHERE variant_id=2").fetchone())
                db.commit()
            out = root / "marketplace.sqlite"
            project_marketplace_catalog.project_database(evidence, out)
            with closing(sqlite3.connect(out)) as db:
                row = db.execute("""SELECT security_status,security_artifact_sha256,security_highest_severity,security_high_count
                                      FROM runtime_plugin_variants WHERE variant_id=2""").fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(("complete", "b" * 64, "high", 1), tuple(row))

    def test_exact_package_url_reuses_proven_artifact_for_unscanned_mirror(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-url-artifact-backfill-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.execute("UPDATE plugin_variants SET assembly_version='1.0',download_link_install='https://example.invalid/plugin.zip' WHERE variant_id=1")
                db.execute("UPDATE plugin_security_scans SET artifact_sha256=? WHERE scan_id=1", ("c" * 64,))
                db.execute("UPDATE plugin_security_current SET artifact_sha256=? WHERE variant_id=1", ("c" * 64,))
                db.execute("INSERT INTO sources(source_id,url,name,is_official) VALUES(2,'https://urlmirror.invalid/repository.json','URL mirror',0)")
                db.execute("""INSERT INTO plugin_variants(
                    variant_id,plugin_id,source_id,source_entry_key,name,author,assembly_version,dalamud_api_level,
                    download_link_install,first_seen_utc,last_seen_utc,active)
                    VALUES(2,1,2,'Fixture-UrlMirror','Fixture','Mirror author','1.0',15,'https://example.invalid/plugin.zip','','',1)""")
                db.commit()
            out = root / "marketplace.sqlite"
            project_marketplace_catalog.project_database(evidence, out)
            with closing(sqlite3.connect(out)) as db:
                rows = db.execute("""SELECT variant_id,security_status,security_artifact_sha256,security_highest_severity
                                       FROM runtime_plugin_variants WHERE internal_name='Fixture' ORDER BY variant_id""").fetchall()
                self.assertEqual(2, len(rows))
                self.assertEqual("complete", rows[1][1])
                self.assertEqual("c" * 64, rows[1][2])
                self.assertEqual(rows[0][3], rows[1][3], "the exact package URL/version must reuse the proven artifact report")

    def test_dependency_summary_preserves_resolution_type_and_warning_without_forensic_tables(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-dependencies-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                # Give the fixture dependency a current graph resolution and warning.
                db.execute("UPDATE plugin_security_dependencies SET kind='external-plugin',name='TargetPlugin',requirement='required',version_requirement='>=2.0.0' WHERE dependency_id=1")
                db.execute("INSERT INTO plugins(plugin_id,internal_name,canonical_name,first_seen_utc,last_seen_utc,active) VALUES(2,'TargetPlugin','Target Plugin','','',1)")
                db.execute("INSERT INTO plugin_variants(variant_id,plugin_id,source_id,source_entry_key,name,author,assembly_version,first_seen_utc,last_seen_utc,active) VALUES(2,2,1,'TargetPlugin','Target Plugin','Omega','2.1.0','','',1)")
                db.execute("""INSERT INTO plugin_security_dependency_resolutions(
                    dependency_id,scan_id,source_plugin_id,source_variant_id,dependency_kind,dependency_name,version_requirement,
                    normalized_name,component_key,requirement,resolution_status,version_status,target_plugin_id,target_variant_id,
                    target_internal_name,target_variant_count,target_version,confidence,match_basis,evidence_json)
                    VALUES(1,1,1,1,'external-plugin','TargetPlugin','>=2.0.0','targetplugin','plugin:targetplugin','required',
                           'resolved-plugin','compatible',2,2,'TargetPlugin',1,'2.1.0','high','internal-name','[]')""")
                db.execute("""INSERT INTO plugin_security_dependency_issues(
                    dependency_id,scan_id,source_plugin_id,source_variant_id,component_key,issue_code,severity,title,detail,
                    requirement,version_requirement,observed_version,target_version,evidence_json,refreshed_at_utc)
                    VALUES(1,1,1,1,'plugin:targetplugin','fixture-warning','caution','Fixture warning','fixture','required','>=2.0.0','2.1.0','2.1.0','[]','')""")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('catalog_revision','cat-v1-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_revision','sec-2.0.0-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('evidence_revision','ev-v1-0123456789abcdef')")
                db.commit()
            out = root / "marketplace.sqlite"
            project_marketplace_catalog.project_database(evidence, out)
            with closing(sqlite3.connect(out)) as db:
                row = db.execute("SELECT security_dependencies_json FROM runtime_plugin_variants WHERE internal_name='Fixture'").fetchone()
                dependency = json.loads(row[0])[0]
                self.assertEqual("hard", dependency["type"])
                self.assertEqual("TargetPlugin", dependency["targetInternalName"])
                self.assertEqual(">=2.0.0", dependency["versionRequirement"])
                self.assertEqual("2.1.0", dependency["targetVersion"])
                self.assertEqual("medium", dependency["warningSeverity"])
                self.assertEqual(1, dependency["warningCount"])
                leaked = db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_dependency_%'").fetchone()[0]
                self.assertEqual(0, leaked)

    def test_ipc_relationship_semantics_are_bounded_in_definitions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-ipc-relationship-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.row_factory = sqlite3.Row
                sigmascope.ensure_schema(db)
                db.execute("UPDATE plugin_security_dependencies SET kind='ipc',name='Omega.Required.Channel',requirement='soft',relationship='required',relationship_confidence='High',relationship_evidence_json=? WHERE dependency_id=1",
                           (json.dumps(["startup path: Initialize", "IPC is invoked directly without an observed availability guard"]),))
                db.execute("INSERT INTO plugins(plugin_id,internal_name,canonical_name,first_seen_utc,last_seen_utc,active) VALUES(2,'ProviderPlugin','Provider Plugin','','',1)")
                db.execute("INSERT INTO plugin_variants(variant_id,plugin_id,source_id,source_entry_key,name,author,assembly_version,first_seen_utc,last_seen_utc,active) VALUES(2,2,1,'ProviderPlugin','Provider Plugin','Omega','1.0','','',1)")
                db.execute("""INSERT OR REPLACE INTO plugin_security_dependency_resolutions(
                    dependency_id,scan_id,source_plugin_id,source_variant_id,dependency_kind,dependency_name,normalized_name,component_key,requirement,
                    relationship,relationship_confidence,relationship_evidence_json,resolution_status,version_status,target_plugin_id,target_variant_id,
                    target_internal_name,target_variant_count,target_version,confidence,match_basis,evidence_json)
                    VALUES(1,1,1,1,'ipc','Omega.Required.Channel','omega.required.channel','ipc:omega.required.channel','soft',
                           'required','High','["startup path: Initialize"]','resolved-ipc-provider','unknown',2,2,'ProviderPlugin',1,'1.0','VeryHigh','exact-ipc-channel-provider','[]')""")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('catalog_revision','cat-v1-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_revision','sec-2.4.0-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('evidence_revision','ev-v1-0123456789abcdef')")
                db.commit()
            out = root / "marketplace.sqlite"
            project_marketplace_catalog.project_database(evidence, out)
            with closing(sqlite3.connect(out)) as db:
                row = db.execute("SELECT security_dependencies_json FROM runtime_plugin_variants WHERE internal_name='Fixture'").fetchone()
                dependency = json.loads(row[0])[0]
                self.assertEqual("required", dependency["relationship"])
                self.assertEqual("High", dependency["relationshipConfidence"])
                self.assertIn("startup path", dependency["relationshipReason"])
                self.assertEqual("ProviderPlugin", dependency["targetInternalName"])
                leaked = db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='plugin_security_ipc_endpoints'").fetchone()[0]
                self.assertEqual(0, leaked, "forensic IPC evidence must stay out of the Definitions database")

    def test_marketplace_descriptor_does_not_expose_evidence_download_url(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-descriptor-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('catalog_revision','cat-v1-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_revision','sec-2.0.0-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('evidence_revision','ev-v1-0123456789abcdef')")
                db.commit()
            evidence_bundle = root / "evidence-input.zip"
            import zipfile
            with zipfile.ZipFile(evidence_bundle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                zf.write(evidence, "omega-catalog.sqlite")
            descriptor = root / "catalog-in.json"
            descriptor.write_text(json.dumps({"schemaVersion":1,"schema":"omega.catalog.sqlite.v1","generatedAtUtc":"2026-08-15T00:00:00Z","catalogRevision":"cat-v1-0123456789abcdef","securityRevision":"sec-2.0.0-0123456789abcdef","evidenceRevision":"ev-v1-0123456789abcdef"}), encoding="utf-8")
            out = root / "out"
            project_marketplace_catalog.project(
                evidence, evidence_bundle, descriptor, out,
                "https://example.invalid/catalog-latest/omega-marketplace.sqlite.zip",
                "https://example.invalid/security-evidence-latest/omega-security-evidence.sqlite.zip",
            )
            marketplace = json.loads((out / "catalog.json").read_text(encoding="utf-8"))
            self.assertEqual("marketplace", marketplace["databaseRole"])
            self.assertFalse(marketplace["detailedSecurityEvidenceIncluded"])
            self.assertEqual("ev-v1-0123456789abcdef", marketplace["evidenceRevision"])
            self.assertNotIn("evidenceDownloadUrl", marketplace)
            self.assertNotIn("security-evidence-latest", json.dumps(marketplace))
            validate_marketplace_catalog.validate_bytes((out / "catalog.json").read_bytes(), (out / "omega-marketplace.sqlite.zip").read_bytes())


    def test_known_osv_risk_is_exact_version_scoped_and_increases_internal_risk_score(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-known-risk-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.row_factory = sqlite3.Row
                db.execute("UPDATE plugin_security_dependencies SET kind='nuget',name='Risky.Package',version='1.2.3',resolved_version='1.2.3',requirement='required' WHERE dependency_id=1")
                db.execute("""INSERT INTO plugin_security_dependency_resolutions(
                    dependency_id,scan_id,source_plugin_id,source_variant_id,dependency_kind,dependency_name,version_requirement,
                    normalized_name,component_key,requirement,resolution_status,version_status,target_plugin_id,target_variant_id,
                    target_internal_name,target_variant_count,target_version,confidence,match_basis,evidence_json)
                    VALUES(1,1,1,1,'nuget','Risky.Package','','risky.package','nuget:risky.package','required',
                           'resolved-component','observed',NULL,NULL,'',0,'1.2.3','high','nuget-component','[]')""")
                db.execute("""INSERT INTO plugin_security_dependency_advisory_matches(
                    advisory_id,component_key,component_kind,component_name,affected_version,affected_range,fixed_version,
                    severity,title,advisory_url,advisory_source,refreshed_at_utc)
                    VALUES('OSV-EXACT','nuget:risky.package','nuget','Risky.Package','1.2.3','','1.2.4',
                           'high','Exact affected version','https://osv.dev/vulnerability/OSV-EXACT','OSV','')""")
                db.execute("""INSERT INTO plugin_security_dependency_advisory_matches(
                    advisory_id,component_key,component_kind,component_name,affected_version,affected_range,fixed_version,
                    severity,title,advisory_url,advisory_source,refreshed_at_utc)
                    VALUES('OSV-OTHER','nuget:risky.package','nuget','Risky.Package','9.9.9','','10.0.0',
                           'critical','Different version must not leak','https://osv.dev/vulnerability/OSV-OTHER','OSV','')""")
                counts = db.execute("SELECT informational_count,caution_count,high_count,critical_count FROM plugin_security_current WHERE variant_id=1").fetchone()
                expected_score = project_marketplace_catalog._security_risk_score(*[int(value or 0) for value in counts], advisory_points=25)
                db.commit()
            out = root / "marketplace.sqlite"
            projected = project_marketplace_catalog.project_database(evidence, out)
            self.assertEqual(1, projected["knownRiskRows"])
            with closing(sqlite3.connect(out)) as db:
                row = db.execute("""SELECT security_known_advisory_count,security_known_advisory_highest_severity,security_risk_score,
                                           security_dependencies_json
                                      FROM runtime_plugin_variants WHERE internal_name='Fixture'""").fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(1, row[0], "only the advisory for the exact dependency version may affect the plugin")
                self.assertEqual("high", row[1])
                self.assertEqual(expected_score, row[2])
                self.assertEqual([], json.loads(row[3]), "NuGet risk evidence remains security context, not a plugin dependency listing")

    def test_dependency_summary_is_bounded_and_retains_total_component_count(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-dependency-bound-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                for index in range(2, 47):
                    db.execute(
                        "INSERT INTO plugin_security_dependencies(dependency_id,scan_id,origin,kind,name,version,status,requirement,evidence_json) VALUES(?,1,'artifact','external-plugin',?,'1.0.0','known','required','[]')",
                        (index, f"Package{index}"),
                    )
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('catalog_revision','cat-v1-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_revision','sec-2.0.0-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('evidence_revision','ev-v1-0123456789abcdef')")
                db.commit()
            out = root / "marketplace.sqlite"
            project_marketplace_catalog.project_database(evidence, out)
            with closing(sqlite3.connect(out)) as db:
                encoded, total = db.execute(
                    "SELECT security_dependencies_json,security_dependency_total_count FROM runtime_plugin_variants WHERE internal_name='Fixture'"
                ).fetchone()
                self.assertEqual(project_marketplace_catalog.DEPENDENCY_SUMMARY_LIMIT, len(json.loads(encoded)))
                self.assertEqual(45, total)


    def test_dependency_summary_only_projects_other_plugins_and_ipc(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-plugin-dependencies-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.execute("DELETE FROM plugin_security_dependencies")
                rows = [
                    (1, "external-plugin", "OtherPlugin", "required"),
                    (2, "ipc", "OtherPlugin.Ipc", "optional"),
                    (3, "assembly", "Dalamud", "required"),
                    (4, "assembly", "FFXIVClientStructs", "required"),
                    (5, "nuget", "Some.Package", "required"),
                    (6, "native-library", "native.dll", "required"),
                    (7, "managed-assembly", "Bundled.Helper", "bundled"),
                    (8, "external-plugin", "Fixture", "required"),
                ]
                for dependency_id, kind, name, requirement in rows:
                    db.execute(
                        "INSERT INTO plugin_security_dependencies(dependency_id,scan_id,origin,kind,name,version,status,requirement,evidence_json) VALUES(?,1,'artifact',?,?,'1.0.0','known',?,'[]')",
                        (dependency_id, kind, name, requirement),
                    )
                db.commit()
            out = root / "marketplace.sqlite"
            project_marketplace_catalog.project_database(evidence, out)
            with closing(sqlite3.connect(out)) as db:
                encoded, total = db.execute(
                    "SELECT security_dependencies_json,security_dependency_total_count FROM runtime_plugin_variants WHERE internal_name='Fixture'"
                ).fetchone()
                dependencies = json.loads(encoded)
                self.assertEqual(2, total)
                self.assertEqual({"OtherPlugin", "OtherPlugin.Ipc"}, {item["name"] for item in dependencies})
                self.assertTrue(all(item["type"] in {"hard", "ipc"} for item in dependencies))

    def test_evidence_revision_change_refreshes_small_marketplace_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-evidence-revision-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('catalog_revision','cat-v1-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_revision','sec-2.0.0-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('evidence_revision','ev-v1-fedcba9876543210')")
                db.commit()
            evidence_bundle = root / "evidence-input.zip"
            import zipfile
            with zipfile.ZipFile(evidence_bundle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                zf.write(evidence, "omega-catalog.sqlite")
            descriptor = root / "catalog-in.json"
            descriptor.write_text(json.dumps({
                "schemaVersion": 1,
                "schema": "omega.catalog.sqlite.v1",
                "generatedAtUtc": "2026-08-15T00:00:00Z",
                "catalogRevision": "cat-v1-0123456789abcdef",
                "securityRevision": "sec-2.0.0-0123456789abcdef",
                "evidenceRevision": "ev-v1-fedcba9876543210",
                "marketplaceProjectorVersion": project_marketplace_catalog.PROJECTOR_VERSION,
            }), encoding="utf-8")
            previous = root / "previous.json"
            previous.write_text(json.dumps({
                "catalogRevision": "cat-v1-0123456789abcdef",
                "securityRevision": "sec-2.0.0-0123456789abcdef",
                "evidenceRevision": "ev-v1-0000000000000000",
                "marketplaceProjectorVersion": project_marketplace_catalog.PROJECTOR_VERSION,
            }), encoding="utf-8")
            out = root / "out"
            report = project_marketplace_catalog.project(
                evidence, evidence_bundle, descriptor, out,
                "https://example.invalid/catalog-latest/omega-marketplace.sqlite.zip",
                "https://example.invalid/security-evidence-latest/omega-security-evidence.sqlite.zip",
                previous,
            )
            self.assertTrue(report["publication"]["marketplaceRequired"])
            self.assertFalse(report["publication"]["semanticChanged"])
            self.assertTrue(report["publication"]["evidenceChanged"])



if __name__ == "__main__":
    unittest.main()

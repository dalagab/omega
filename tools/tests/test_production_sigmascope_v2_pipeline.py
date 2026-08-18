from __future__ import annotations

from contextlib import closing
from pathlib import Path
import io
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

import common
import test_sqlite_catalog

SECURITY = common.ROOT / "tools" / "security"
CATALOG = common.ROOT / "tools" / "catalog"
for item in (SECURITY, CATALOG):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

import sigmascope
import developer_view as developer_view
from migrate_security_evidence_v2 import migrate
from production_sigmascope_v2_pipeline import (
    _current_rows,
    _restore_last_known_good,
    _semantic_security_revision,
    materialize_current_state,
    run_pipeline,
    synchronize_candidate,
)
from security_evidence_v2 import validate_snapshot


class ProductionSecurityV2PipelineTests(unittest.TestCase):
    def make_catalog_with_security(self, root: Path) -> tuple[Path, int, int]:
        curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
        built = root / "built"
        test_sqlite_catalog.run_builder(common.ROOT, built, curated, raw, enriched, websites)
        database = built / "omega-catalog.sqlite"
        with closing(sqlite3.connect(database)) as db:
            db.row_factory = sqlite3.Row
            sigmascope.ensure_schema(db)
            variant = db.execute(
                """SELECT v.variant_id,v.plugin_id,v.source_id,v.assembly_version
                     FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id
                    WHERE v.active=1 AND p.active=1 ORDER BY v.variant_id LIMIT 1"""
            ).fetchone()
            self.assertIsNotNone(variant)
            variant_id = int(variant["variant_id"])
            plugin_id = int(variant["plugin_id"])
            source_id = int(variant["source_id"])
            artifact = "a" * 64
            db.execute(
                """INSERT INTO plugin_security_scans(
                     scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,
                     artifact_sha256,scanner_version,status,scanned_at_utc,highest_severity,
                     informational_count,caution_count,high_count,critical_count,capabilities_json,
                     source_available,source_repository,source_commit,source_to_binary_verified,report_json,error)
                     VALUES(?,?,?,?,?,'stable','https://example.invalid/plugin.zip',?,?,'complete',
                     '2026-08-17T00:00:00Z','caution',0,1,0,0,'[]',1,'https://example.invalid/repo',
                     'abc',1,'{}','')""",
                (9001, plugin_id, variant_id, source_id, str(variant["assembly_version"] or "1.0.0"), artifact, sigmascope.SCANNER_VERSION),
            )
            db.execute(
                """INSERT INTO plugin_security_current(
                     variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,
                     scanner_version,status,scanned_at_utc,highest_severity,informational_count,caution_count,
                     high_count,critical_count,capabilities_json,automation_level,automation_capabilities_json,
                     findings_json,source_available,source_repository,source_commit,source_to_binary_verified,
                     report_json,error)
                     VALUES(?,9001,?,'stable','https://example.invalid/plugin.zip',?,?,'complete',
                     '2026-08-17T00:00:00Z','caution',0,1,0,0,'[]','none','[]','[]',1,
                     'https://example.invalid/repo','abc',1,'{}','')""",
                (variant_id, str(variant["assembly_version"] or "1.0.0"), artifact, sigmascope.SCANNER_VERSION),
            )
            db.execute(
                """INSERT INTO plugin_security_findings(scan_id,rule_id,severity,category,title,description,evidence_json)
                   VALUES(9001,'fixture.rule','caution','fixture','Fixture','Fixture finding','[\"fixture\"]')"""
            )
            db.execute(
                """INSERT INTO plugin_security_dependencies(
                   scan_id,origin,kind,name,version,version_requirement,resolved_version,path,status,requirement,
                   evidence_json,relationship,relationship_confidence,relationship_evidence_json)
                   VALUES(9001,'artifact','nuget-resolved','Example.Package','1.2.3','1.2.3','1.2.3',
                   'Fixture.deps.json','known','required','[]','','','[]')"""
            )
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_scanner_version',?)", (sigmascope.SCANNER_VERSION,))
            db.commit()
        return database, variant_id, plugin_id

    def test_v2_sqlite_test_connections_are_windows_cleanup_safe(self) -> None:
        # sqlite3.Connection.__exit__ commits/rolls back but does not close the handle.
        # A leaked handle is tolerated by POSIX unlink semantics and rejected by Windows,
        # so v2 temporary-database tests must always wrap connections in closing().
        for path in (
            Path(__file__),
            Path(__file__).with_name("test_security_evidence_v2.py"),
        ):
            self.assertNotIn("with sqlite3." + "connect(", path.read_text(encoding="utf-8"))

    def test_materializes_published_v2_into_disposable_working_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-production-") as td:
            root = Path(td)
            database, variant_id, _ = self.make_catalog_with_security(root)
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            self.assertTrue(validate_snapshot(evidence)["ok"])

            # Simulate the catalog builder delivering identities/presentation without detailed state.
            base = root / "base.sqlite"
            shutil.copy2(database, base)
            with closing(sqlite3.connect(base)) as db:
                sigmascope.ensure_schema(db)
                db.execute("PRAGMA foreign_keys=OFF")
                for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchall():
                    db.execute(f'DELETE FROM "{row[0]}"')
                db.execute("PRAGMA foreign_keys=ON")
                db.commit()

            work = root / "work.sqlite"
            report = materialize_current_state(base, evidence, work)
            self.assertEqual(report["currentVariantsMaterialized"], 1)
            with closing(sqlite3.connect(work)) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM plugin_security_current").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM plugin_security_findings").fetchone()[0], 1)
                dep = db.execute("SELECT kind,name,resolved_version FROM plugin_security_dependencies").fetchone()
                self.assertEqual(dep, ("nuget-resolved", "Example.Package", "1.2.3"))
                self.assertEqual(db.execute("SELECT scan_id FROM plugin_security_current WHERE variant_id=?", (variant_id,)).fetchone()[0], 9001)

    def test_materialization_repairs_stale_v2_summary_from_normalized_findings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-stale-summary-repair-") as td:
            root = Path(td)
            database, variant_id, _ = self.make_catalog_with_security(root)
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            variant_path = next((evidence / "variants").rglob("*.json"))
            payload = json.loads(variant_path.read_text(encoding="utf-8"))
            legacy_report = {
                "scannerVersion": "2.0.0",
                "status": "complete",
                "highestSeverity": "caution",
                "counts": {"informational": 0, "caution": 1, "high": 0, "critical": 0},
                "capabilities": ["Fixture capability"],
                "source": {"repository": "https://example.invalid/repo"},
            }
            for field in ("scan", "current"):
                payload[field]["highest_severity"] = "none"
                payload[field]["informational_count"] = 0
                payload[field]["caution_count"] = 0
                payload[field]["high_count"] = 0
                payload[field]["critical_count"] = 0
                payload[field]["report_json"] = legacy_report
            payload["current"]["findings_json"] = []
            variant_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            base = root / "base.sqlite"
            shutil.copy2(database, base)
            with closing(sqlite3.connect(base)) as db:
                sigmascope.ensure_schema(db)
                db.execute("PRAGMA foreign_keys=OFF")
                for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchall():
                    db.execute(f'DELETE FROM "{row[0]}"')
                db.execute("PRAGMA foreign_keys=ON")
                db.commit()

            work = root / "work.sqlite"
            materialize_current_state(base, evidence, work)
            with closing(sqlite3.connect(work)) as db:
                db.row_factory = sqlite3.Row
                scan = db.execute("SELECT highest_severity,informational_count,caution_count,high_count,critical_count,report_json FROM plugin_security_scans WHERE scan_id=9001").fetchone()
                current = db.execute("SELECT highest_severity,informational_count,caution_count,high_count,critical_count,findings_json,report_json FROM plugin_security_current WHERE variant_id=?", (variant_id,)).fetchone()
                self.assertEqual(tuple(scan[:5]), ("caution", 0, 1, 0, 0))
                self.assertEqual(tuple(current[:5]), ("caution", 0, 1, 0, 0))
                self.assertEqual(json.loads(current["findings_json"])[0]["ruleId"], "fixture.rule")
                self.assertEqual(json.loads(scan["report_json"])["highestSeverity"], "caution")
                self.assertEqual(json.loads(current["report_json"])["counts"]["caution"], 1)

            # Reproduce the live workflow's next gate: the independent developer audit
            # must accept the self-healed historical row after materialization.
            inspector = developer_view.SecurityInspector(work)
            try:
                failures = [item for item in inspector.audit_variant(variant_id) if item.status == "fail"]
                self.assertEqual([], failures)
            finally:
                inspector.close()

    def test_candidate_synchronization_repairs_legacy_oversized_variant_reports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-legacy-report-repair-") as td:
            root = Path(td)
            database, variant_id, _plugin_id = self.make_catalog_with_security(root)
            candidate = root / "candidate"
            migrate(database, candidate, reset=True)
            variant_path = next((candidate / "variants").rglob("*.json"))
            payload = json.loads(variant_path.read_text(encoding="utf-8"))
            legacy = {
                "opaqueLegacyEvidence": "x" * (18 * 1024 * 1024),
                "source": {"dependencyIntelligence": {"fingerprints": {"relevantSourceSha256": "c" * 64}}},
            }
            payload["scan"]["report_json"] = legacy
            payload["current"]["report_json"] = legacy
            variant_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            self.assertGreater(variant_path.stat().st_size, 32 * 1024 * 1024)

            # Loading an old published branch must not recreate the oversized report
            # in the disposable SQLite working database either.
            work_database = root / "materialized.sqlite"
            materialize_current_state(database, candidate, work_database)
            with closing(sqlite3.connect(work_database)) as db:
                report_json = db.execute(
                    "SELECT report_json FROM plugin_security_current WHERE variant_id=?", (variant_id,)
                ).fetchone()[0]
            compact = json.loads(report_json)
            self.assertEqual(compact["schema"], "omega.security-evidence.scan-summary.v2")
            self.assertLess(len(report_json.encode("utf-8")), 256 * 1024)

            synchronize_candidate(candidate, database, {variant_id})
            self.assertLess(variant_path.stat().st_size, 1024 * 1024)
            repaired = json.loads(variant_path.read_text(encoding="utf-8"))
            self.assertEqual(repaired["scan"]["report_json"]["schema"], "omega.security-evidence.scan-summary.v2")
            self.assertEqual(
                repaired["scan"]["report_json"]["source"]["dependencyIntelligence"]["fingerprints"]["relevantSourceSha256"],
                "c" * 64,
            )
            self.assertNotIn("opaqueLegacyEvidence", variant_path.read_text(encoding="utf-8"))

    def test_failed_revalidation_restores_last_known_good_current_pointer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-retain-") as td:
            root = Path(td)
            database, variant_id, plugin_id = self.make_catalog_with_security(root)
            previous = _current_rows(database)
            with closing(sqlite3.connect(database)) as db:
                source_id = int(db.execute("SELECT source_id FROM plugin_variants WHERE variant_id=?", (variant_id,)).fetchone()[0])
                db.execute(
                    """INSERT INTO plugin_security_scans(scan_id,plugin_id,variant_id,source_id,artifact_sha256,
                       scanner_version,status,scanned_at_utc,report_json,error)
                       VALUES(9002,?,?,?,?,?,'failed','2026-08-17T01:00:00Z','{}','network failure')""",
                    (plugin_id, variant_id, source_id, "b" * 64, sigmascope.SCANNER_VERSION),
                )
                db.execute(
                    """UPDATE plugin_security_current SET scan_id=9002,artifact_sha256=?,status='failed',error='network failure'
                       WHERE variant_id=?""",
                    ("b" * 64, variant_id),
                )
                db.commit()
            successful, failed = _restore_last_known_good(database, previous)
            self.assertEqual(successful, [])
            self.assertEqual(failed, [variant_id])
            with closing(sqlite3.connect(database)) as db:
                current = db.execute("SELECT scan_id,status,artifact_sha256 FROM plugin_security_current WHERE variant_id=?", (variant_id,)).fetchone()
                self.assertEqual(current, (9001, "complete", "a" * 64))


    def test_full_noop_pipeline_builds_valid_candidate_and_marketplace_without_network(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-full-pipeline-") as td:
            root = Path(td)
            database, _variant_id, _plugin_id = self.make_catalog_with_security(root)
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            self.assertTrue(validate_snapshot(evidence)["ok"])

            base = root / "base.sqlite"
            shutil.copy2(database, base)
            with closing(sqlite3.connect(base)) as db:
                sigmascope.ensure_schema(db)
                db.execute("PRAGMA foreign_keys=OFF")
                for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchall():
                    db.execute(f'DELETE FROM "{row[0]}"')
                db.execute("PRAGMA foreign_keys=ON")
                db.commit()

            descriptor = root / "built" / "catalog.json"
            self.assertTrue(descriptor.is_file())
            args = SimpleNamespace(
                base_database=base,
                descriptor=descriptor,
                current_evidence=evidence,
                candidate_evidence=root / "candidate",
                work_dir=root / "work",
                publication_output=root / "publication",
                previous_marketplace_descriptor=None,
                marketplace_download_url="https://example.invalid/catalog-latest/omega-marketplace.sqlite.zip",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
                source_overrides=common.ROOT / "sources" / "source-overrides.json",
                max_scans=0,
                rescan_after_hours=168,
                max_batch_seconds=0,
                internal_names="",
                skip_source=True,
                osv_timeout=1.0,
                max_osv_packages=2000,
                github_output=None,
            )

            def fake_collect(index_path, output, timeout=20.0, max_packages=2000):
                import collect_public_advisories
                packages = collect_public_advisories.observed_nuget_index(Path(index_path), max_packages)
                document = {
                    "schema": "omega.public-advisories.v1",
                    "generatedAtUtc": "2026-08-17T00:00:00Z",
                    "source": "OSV",
                    "ecosystem": "NuGet",
                    "queriedPackages": len(packages),
                    "matchedPackages": 0,
                    "advisories": [],
                }
                Path(output).write_text(__import__("json").dumps(document, indent=2) + "\n", encoding="utf-8")
                return document

            with patch("production_sigmascope_v2_pipeline.collect_public_advisories.collect_from_nuget_index", side_effect=fake_collect):
                result = run_pipeline(args)

            self.assertTrue(result["candidate"]["validation"]["ok"], result["candidate"]["validation"] )
            self.assertEqual(result["osv"]["gate"], "pass")
            self.assertTrue((root / "candidate" / "index.json").is_file())
            self.assertTrue((root / "publication" / "omega-marketplace.sqlite").is_file())
            self.assertTrue((root / "publication" / "omega-marketplace.sqlite.zip").is_file())
            self.assertEqual(result["summary"]["nugetPackageVersionPairs"], 1)
            variant_file = next((root / "candidate" / "variants").rglob("*.json"))
            payload = json.loads(variant_file.read_text(encoding="utf-8"))
            for name in ("dependencyResolutions", "dependencyIssues", "advisoryMatches"):
                self.assertNotIn(name, payload.get("derived") or {})
                descriptor = (payload.get("derivedEvidence") or {}).get(name)
                self.assertIsInstance(descriptor, dict)
                self.assertIn("recordDigest", descriptor)
                for file_info in descriptor.get("files") or []:
                    self.assertLessEqual(int(file_info.get("bytes") or 0), 32 * 1024 * 1024)


    def test_full_incremental_pipeline_merges_fresh_deps_json_analysis(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-incremental-pipeline-") as td:
            root = Path(td)
            database, variant_id, _plugin_id = self.make_catalog_with_security(root)
            # The published baseline came from Sigmascope generation 2.4.0; 2.5.0 must refresh it.
            with closing(sqlite3.connect(database)) as db:
                db.execute("UPDATE plugin_security_scans SET scanner_version='2.4.0' WHERE scan_id=9001")
                db.execute("UPDATE plugin_security_current SET scanner_version='2.4.0' WHERE variant_id=?", (variant_id,))
                db.commit()
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            self.assertTrue(validate_snapshot(evidence)["ok"])

            base = root / "base.sqlite"
            shutil.copy2(database, base)
            with closing(sqlite3.connect(base)) as db:
                sigmascope.ensure_schema(db)
                db.execute("PRAGMA foreign_keys=OFF")
                for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchall():
                    db.execute(f'DELETE FROM "{row[0]}"')
                db.execute("PRAGMA foreign_keys=ON")
                db.commit()

            deps = {
                "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0/win-x64"},
                "targets": {
                    ".NETCoreApp,Version=v8.0/win-x64": {
                        "Example.Package/9.8.7": {"runtime": {"lib/net8.0/Example.Package.dll": {}}}
                    }
                },
                "libraries": {"Example.Package/9.8.7": {"type": "package", "serviceable": True, "sha512": ""}},
            }
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("FixturePlugin.deps.json", json.dumps(deps))
            artifact = buffer.getvalue()

            args = SimpleNamespace(
                base_database=base,
                descriptor=root / "built" / "catalog.json",
                current_evidence=evidence,
                candidate_evidence=root / "candidate",
                work_dir=root / "work",
                publication_output=root / "publication",
                previous_marketplace_descriptor=None,
                marketplace_download_url="https://example.invalid/catalog-latest/omega-marketplace.sqlite.zip",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
                source_overrides=common.ROOT / "sources" / "source-overrides.json",
                max_scans=1,
                rescan_after_hours=168,
                max_batch_seconds=0,
                internal_names="",
                skip_source=True,
                osv_timeout=1.0,
                max_osv_packages=2000,
                github_output=None,
            )

            def fake_collect(index_path, output, timeout=20.0, max_packages=2000):
                import collect_public_advisories
                packages = collect_public_advisories.observed_nuget_index(Path(index_path), max_packages)
                document = {
                    "schema": "omega.public-advisories.v1",
                    "generatedAtUtc": "2026-08-17T00:00:00Z",
                    "source": "OSV",
                    "ecosystem": "NuGet",
                    "queriedPackages": len(packages),
                    "matchedPackages": 0,
                    "advisories": [],
                }
                Path(output).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                return document

            with patch("sigmascope.request_bytes", return_value=(artifact, "https://example.invalid/plugin.zip")), \
                 patch("production_sigmascope_v2_pipeline.collect_public_advisories.collect_from_nuget_index", side_effect=fake_collect):
                result = run_pipeline(args)

            self.assertEqual(len(result["successfulVariantIds"]), 1)
            successful_variant_id = result["successfulVariantIds"][0]
            self.assertTrue(result["candidate"]["validation"]["ok"], result["candidate"]["validation"] )
            self.assertGreaterEqual(result["summary"]["nugetPackageVersionPairs"], 1)
            self.assertGreaterEqual(result["osv"]["queriedPackages"], 1)
            variant_files = list((root / "candidate" / "variants").rglob(f"{successful_variant_id}.json"))
            self.assertEqual(len(variant_files), 1)
            payload = json.loads(variant_files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["current"]["scanner_version"], sigmascope.SCANNER_VERSION)
            analysis_path = payload["analysis"]["path"]
            dependency_rows = __import__("security_evidence_v2").read_dataset_rows(root / "candidate", analysis_path, "dependencies")
            self.assertTrue(any(row.get("kind") == "nuget-resolved" and row.get("name") == "Example.Package" and row.get("resolved_version") == "9.8.7" for row in dependency_rows))


    def test_osv_gate_rejects_candidate_when_exact_nuget_versions_are_not_queried(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-osv-gate-") as td:
            root = Path(td)
            database, _variant_id, _plugin_id = self.make_catalog_with_security(root)
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            base = root / "base.sqlite"
            shutil.copy2(database, base)
            with closing(sqlite3.connect(base)) as db:
                sigmascope.ensure_schema(db)
                db.execute("PRAGMA foreign_keys=OFF")
                for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchall():
                    db.execute(f'DELETE FROM "{row[0]}"')
                db.execute("PRAGMA foreign_keys=ON")
                db.commit()
            args = SimpleNamespace(
                base_database=base, descriptor=root / "built" / "catalog.json", current_evidence=evidence,
                candidate_evidence=root / "candidate", work_dir=root / "work", publication_output=root / "publication",
                previous_marketplace_descriptor=None,
                marketplace_download_url="https://example.invalid/catalog-latest/omega-marketplace.sqlite.zip",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
                source_overrides=common.ROOT / "sources" / "source-overrides.json", max_scans=0,
                rescan_after_hours=168, max_batch_seconds=0, internal_names="", skip_source=True,
                osv_timeout=1.0, max_osv_packages=2000, github_output=None,
            )
            def incomplete_collect(index_path, output, timeout=20.0, max_packages=2000):
                document = {
                    "schema": "omega.public-advisories.v1", "generatedAtUtc": "2026-08-17T00:00:00Z",
                    "source": "OSV", "ecosystem": "NuGet", "queriedPackages": 0, "matchedPackages": 0, "advisories": [],
                }
                Path(output).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                return document
            with patch("production_sigmascope_v2_pipeline.collect_public_advisories.collect_from_nuget_index", side_effect=incomplete_collect):
                with self.assertRaisesRegex(RuntimeError, "OSV publication gate failed"):
                    run_pipeline(args)
            self.assertFalse((root / "candidate" / "index.json").exists())

    def test_semantic_security_revision_ignores_transport_scan_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-revision-") as td:
            root = Path(td)
            database, variant_id, plugin_id = self.make_catalog_with_security(root)
            with closing(sqlite3.connect(database)) as db:
                db.row_factory = sqlite3.Row
                before = _semantic_security_revision(db)
                old_scan = dict(db.execute("SELECT * FROM plugin_security_scans WHERE scan_id=9001").fetchone())
                old_scan["scan_id"] = 9003
                columns = list(old_scan)
                db.execute(
                    f"INSERT INTO plugin_security_scans({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
                    tuple(old_scan[c] for c in columns),
                )
                for table in ("plugin_security_findings", "plugin_security_dependencies"):
                    rows = db.execute(f"SELECT * FROM {table} WHERE scan_id=9001").fetchall()
                    info = db.execute(f"PRAGMA table_info({table})").fetchall()
                    pk = next(str(row[1]) for row in info if int(row[5]) == 1)
                    for source in rows:
                        row = dict(source)
                        row.pop(pk, None)
                        row["scan_id"] = 9003
                        cols = list(row)
                        db.execute(
                            f"INSERT INTO {table}({','.join(cols)}) VALUES({','.join('?' for _ in cols)})",
                            tuple(row[c] for c in cols),
                        )
                db.execute("UPDATE plugin_security_current SET scan_id=9003 WHERE variant_id=?", (variant_id,))
                db.commit()
                after = _semantic_security_revision(db)
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()

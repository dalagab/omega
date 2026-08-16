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
                db.execute("UPDATE plugin_security_dependencies SET kind='external-plugin',name='Fixture.Dependency',requirement='required' WHERE dependency_id=1")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('catalog_revision','cat-v1-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_revision','sec-2.0.0-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('evidence_revision','ev-v1-0123456789abcdef')")
                db.commit()
                before = project_marketplace_catalog.runtime_projection_digest(
                    db, {"security_dependencies_json", "security_dependency_total_count"})
            out = root / "marketplace.sqlite"
            projected = project_marketplace_catalog.project_database(evidence, out)
            self.assertEqual(before, projected["runtimeProjectionSha256"])
            with closing(sqlite3.connect(out)) as db:
                leaked = db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchone()[0]
                self.assertEqual(0, leaked)
                self.assertGreater(db.execute("SELECT COUNT(*) FROM runtime_plugin_variants").fetchone()[0], 0)
                row = db.execute(
                    "SELECT security_dependencies_json,security_dependency_total_count FROM runtime_plugin_variants WHERE internal_name='Fixture'"
                ).fetchone()
                self.assertIsNotNone(row)
                dependencies = json.loads(row[0])
                self.assertEqual("Fixture.Dependency", dependencies[0]["name"])
                self.assertGreaterEqual(row[1], 1)
                self.assertLessEqual(len(dependencies), project_marketplace_catalog.DEPENDENCY_SUMMARY_LIMIT)
                self.assertEqual("marketplace", dict(db.execute("SELECT key,value FROM catalog_meta"))["database_role"])


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

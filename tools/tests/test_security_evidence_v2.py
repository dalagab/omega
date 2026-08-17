from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

from migrate_security_evidence_v2 import _resolve_source_database, migrate
from publish_security_evidence_v2 import preflight, validate_audit_report, validate_snapshot_report
from security_evidence_download import DownloadedEvidence, parse_sidecar, safe_extract_sqlite
from security_evidence_v2 import (MAX_PUBLISH_FILE_BYTES, read_record_dataset, sha256_file, validate_snapshot, write_record_dataset)
from validate_security_evidence_v2 import infer_database_from_migration_state, validate


class SecurityEvidenceV2Tests(unittest.TestCase):
    def make_database(self, path: Path) -> Path:
        db = sqlite3.connect(path)
        db.executescript("""
        CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT INTO catalog_meta VALUES('security_revision','sec-test');
        INSERT INTO catalog_meta VALUES('evidence_revision','ev-test');
        INSERT INTO catalog_meta VALUES('catalog_revision','cat-test');
        INSERT INTO catalog_meta VALUES('base_revision','base-test');
        INSERT INTO catalog_meta VALUES('security_scanner_version','2.4.0');

        CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY,internal_name TEXT,name TEXT,author TEXT);
        INSERT INTO plugins VALUES(1,'FixturePlugin','Fixture Plugin','Tester');

        CREATE TABLE sources(source_id INTEGER PRIMARY KEY,name TEXT,url TEXT);
        INSERT INTO sources VALUES(1,'Mirror A','https://example.invalid/a.json');
        INSERT INTO sources VALUES(2,'Mirror B','https://example.invalid/b.json');

        CREATE TABLE plugin_variants(variant_id INTEGER PRIMARY KEY,plugin_id INTEGER,source_id INTEGER,assembly_version TEXT);
        INSERT INTO plugin_variants VALUES(1,1,1,'1.0.0');
        INSERT INTO plugin_variants VALUES(2,1,2,'1.0.0');

        CREATE TABLE plugin_security_scans(
          scan_id INTEGER PRIMARY KEY,plugin_id INTEGER,variant_id INTEGER,source_id INTEGER,
          artifact_sha256 TEXT,scanner_version TEXT,status TEXT,highest_severity TEXT,
          informational_count INTEGER,caution_count INTEGER,high_count INTEGER,critical_count INTEGER,
          scanned_at_utc TEXT,report_json TEXT
        );
        INSERT INTO plugin_security_scans VALUES(10,1,1,1,
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','2.4.0','complete','high',0,0,1,0,
          '2026-08-17T00:00:00Z','{"fixture":true}');
        INSERT INTO plugin_security_scans VALUES(11,1,2,2,
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','2.4.0','complete','high',0,0,1,0,
          '2026-08-17T00:01:00Z','{"fixture":true}');

        CREATE TABLE plugin_security_current(
          variant_id INTEGER PRIMARY KEY,scan_id INTEGER,status TEXT,artifact_sha256 TEXT,scanner_version TEXT,
          highest_severity TEXT,informational_count INTEGER,caution_count INTEGER,high_count INTEGER,critical_count INTEGER
        );
        INSERT INTO plugin_security_current VALUES(1,10,'complete','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','2.4.0','high',0,0,1,0);
        INSERT INTO plugin_security_current VALUES(2,11,'complete','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','2.4.0','high',0,0,1,0);

        CREATE TABLE plugin_security_findings(
          finding_id INTEGER PRIMARY KEY,scan_id INTEGER,rule_id TEXT,severity TEXT,category TEXT,title TEXT,description TEXT,evidence_json TEXT
        );
        INSERT INTO plugin_security_findings VALUES(1,10,'network.http','high','network','Network','Fixture','["HttpClient"]');
        INSERT INTO plugin_security_findings VALUES(2,11,'network.http','high','network','Network','Fixture','["HttpClient"]');

        CREATE TABLE plugin_security_dependencies(
          dependency_id INTEGER PRIMARY KEY,scan_id INTEGER,origin TEXT,kind TEXT,name TEXT,version TEXT,
          version_requirement TEXT,resolved_version TEXT,path TEXT,status TEXT,requirement TEXT,evidence_json TEXT,
          relationship TEXT,relationship_confidence TEXT,relationship_evidence_json TEXT
        );
        INSERT INTO plugin_security_dependencies VALUES(100,10,'artifact','nuget-lock','Newtonsoft.Json','13.0.3','[13.0.3,)','13.0.3','packages.lock.json','known','required','[]','','','[]');
        INSERT INTO plugin_security_dependencies VALUES(101,11,'artifact','nuget-lock','Newtonsoft.Json','13.0.3','[13.0.3,)','13.0.3','packages.lock.json','known','required','[]','','','[]');
        """)
        db.commit()
        db.close()
        return path

    def test_migration_deduplicates_identical_mirror_evidence_and_validates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            index = migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            self.assertEqual(index["counts"]["currentVariants"], 2)
            self.assertEqual(index["counts"]["analyses"], 1)
            self.assertEqual(index["counts"]["artifactGroups"], 1)
            self.assertEqual(index["counts"]["nugetPackageVersionPairs"], 1)
            first = json.loads((output / "variants" / "0000" / "1.json").read_text(encoding="utf-8"))
            second = json.loads((output / "variants" / "0000" / "2.json").read_text(encoding="utf-8"))
            self.assertEqual(first["analysis"]["analysisId"], second["analysis"]["analysisId"])
            report = validate(database, output)
            self.assertTrue(report["ok"], report)
            publication = preflight(output)
            self.assertGreater(publication["files"], 0)
            self.assertEqual(publication["evidenceRevision"], "ev-test")

    def test_resume_reuses_completed_variant_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            first_mtime = (output / "variants" / "0000" / "1.json").stat().st_mtime_ns
            migrate(database, output, resume=True, chunk_bytes=1024 * 1024)
            self.assertEqual(first_mtime, (output / "variants" / "0000" / "1.json").stat().st_mtime_ns)
            self.assertTrue(validate(database, output)["ok"])

    def test_parity_validator_detects_semantic_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            variant = output / "variants" / "0000" / "1.json"
            payload = json.loads(variant.read_text(encoding="utf-8"))
            payload["current"]["highest_severity"] = "none"
            variant.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            report = validate(database, output)
            self.assertFalse(report["ok"])
            self.assertTrue(any("variant 1 current" in item for item in report["errors"]))


    def test_filtered_migration_exports_only_selected_current_variants(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "subset"
            index = migrate(database, output, reset=True, chunk_bytes=1024 * 1024, variant_ids={1})
            self.assertEqual(index["migrationMode"], "incremental-subset")
            self.assertEqual(index["counts"]["currentVariants"], 1)
            self.assertTrue((output / "variants" / "0000" / "1.json").is_file())
            self.assertFalse((output / "variants" / "0000" / "2.json").exists())

    def test_intrinsic_snapshot_validator_verifies_hashes_and_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            report = validate_snapshot(output)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["checkedVariants"], 2)
            self.assertEqual(report["checkedAnalyses"], 1)
            report_path = output / "validation-report.json"
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            accepted = validate_snapshot_report(output, report_path)
            self.assertEqual(accepted["indexSha256"], sha256_file(output / "index.json"))

            finding = next((output / "artifacts").rglob("findings.json"))
            finding.write_text("[]\n", encoding="utf-8")
            broken = validate_snapshot(output)
            self.assertFalse(broken["ok"])
            self.assertTrue(any("sha256" in error or "record" in error for error in broken["errors"]))


    def test_intrinsic_validator_accepts_failed_current_variant_artifact_group(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            with closing(sqlite3.connect(database)) as db:
                db.execute("UPDATE plugin_security_scans SET status='failed',artifact_sha256='' WHERE scan_id=11")
                db.execute("UPDATE plugin_security_current SET status='failed',artifact_sha256='' WHERE variant_id=2")
                db.commit()
            output = root / "v2"
            index = migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            self.assertEqual(index["counts"]["currentVariants"], 2)
            self.assertEqual(index["counts"]["analyses"], 1)
            self.assertEqual(index["counts"]["artifactGroups"], 2)
            report = validate_snapshot(output)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["checkedVariants"], 2)
            self.assertEqual(report["checkedAnalyses"], 1)

    def test_download_current_source_resolution_records_verified_context(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            archive = root / "evidence.zip"
            archive.write_bytes(b"fixture")
            downloaded = DownloadedEvidence(
                database=database,
                archive=archive,
                release_tag="security-evidence-latest",
                asset_name="omega-security-evidence.sqlite.zip",
                asset_bytes=7,
                asset_sha256="a" * 64,
            )
            from unittest.mock import patch
            with patch("migrate_security_evidence_v2.download_current_database", return_value=downloaded):
                resolved, context = _resolve_source_database(None, True, root / "cache")
            self.assertEqual(resolved, database.resolve())
            self.assertEqual(context["mode"], "download-current")
            self.assertEqual(context["assetSha256"], "a" * 64)
            self.assertEqual(context["databasePath"], str(database.resolve()))

    def test_validator_can_infer_migration_source_database(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024, source_context={"mode": "local"})
            self.assertEqual(infer_database_from_migration_state(output), database.resolve())
            self.assertTrue(validate(infer_database_from_migration_state(output), output)["ok"])

    def test_publication_audit_gate_rejects_failures_and_optional_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report = root / "audit.json"
            report.write_text(json.dumps({"counts": {"pass": 10, "warn": 0, "fail": 0}}), encoding="utf-8")
            self.assertEqual(validate_audit_report(report)["counts"]["fail"], 0)

            report.write_text(json.dumps({"counts": {"pass": 9, "warn": 0, "fail": 1}}), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "failing checks"):
                validate_audit_report(report)

            report.write_text(json.dumps({"counts": {"pass": 9, "warn": 1, "fail": 0}}), encoding="utf-8")
            self.assertEqual(validate_audit_report(report)["counts"]["warn"], 1)
            with self.assertRaisesRegex(RuntimeError, "warnings"):
                validate_audit_report(report, strict_warnings=True)

    def test_large_derived_record_dataset_uses_bounded_compressed_shards(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows = [
                {"component_key": f"component-{i}", "evidence": "x" * 512, "status": "resolved"}
                for i in range(6000)
            ]
            descriptor = write_record_dataset(
                root, root / "derived" / "variants" / "0000" / "1", "dependency-resolutions", rows,
                inline_bytes=1024, chunk_bytes=1024 * 1024,
            )
            self.assertEqual(descriptor["records"], len(rows))
            self.assertGreaterEqual(len(descriptor["files"]), 1)
            self.assertTrue(all(item["encoding"] == "jsonl+gzip" for item in descriptor["files"]))
            self.assertTrue(all(int(item["bytes"]) <= MAX_PUBLISH_FILE_BYTES for item in descriptor["files"]))
            self.assertEqual(read_record_dataset(root, descriptor), rows)

    def test_download_helper_sidecar_and_safe_sqlite_extraction(self) -> None:
        import zipfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            bundle = root / "evidence.zip"
            with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.write(database, "nested/omega-security-evidence.sqlite")
            extracted = safe_extract_sqlite(bundle, root / "out")
            self.assertEqual(extracted.read_bytes()[:16], b"SQLite format 3\x00")
            self.assertEqual(parse_sidecar("abc " + "f" * 64 + "  file.zip"), "f" * 64)


if __name__ == "__main__":
    unittest.main()

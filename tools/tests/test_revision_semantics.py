from __future__ import annotations

from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import common  # noqa: F401
import catalog_revisions
import compact_sqlite_catalog
import publication_decision


class RevisionSemanticsTests(unittest.TestCase):
    def build_fixture_database(self, root: Path) -> Path:
        path = root / "omega-catalog.sqlite"
        compact_sqlite_catalog.build_self_test_database(path)
        return path

    def test_security_revision_ignores_scan_timestamps(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-revision-time-") as td:
            path = self.build_fixture_database(Path(td))
            with closing(sqlite3.connect(path)) as db:
                first = catalog_revisions.compute_security_revision(db)
                db.execute("UPDATE plugin_security_current SET scanned_at_utc='2030-01-01T00:00:00Z'")
                db.execute("UPDATE plugin_security_scans SET scanned_at_utc='2030-01-01T00:00:00Z'")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_scanned_at_utc','2030-01-01T00:00:00Z')")
                db.commit()
                second = catalog_revisions.compute_security_revision(db)
            self.assertEqual(first, second)

    def test_security_revision_changes_when_current_evidence_changes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-revision-evidence-") as td:
            path = self.build_fixture_database(Path(td))
            with closing(sqlite3.connect(path)) as db:
                first = catalog_revisions.compute_security_revision(db)
                db.execute("UPDATE plugin_security_current SET artifact_sha256='changed-artifact'")
                db.commit()
                second = catalog_revisions.compute_security_revision(db)
            self.assertNotEqual(first, second)

    def test_detailed_callsite_change_only_changes_evidence_revision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-revision-split-") as td:
            path = self.build_fixture_database(Path(td))
            with closing(sqlite3.connect(path)) as db:
                security_first = catalog_revisions.compute_security_revision(db)
                evidence_first = catalog_revisions.compute_evidence_revision(db)
                row = db.execute("SELECT managed_call_id FROM plugin_security_managed_calls ORDER BY managed_call_id LIMIT 1").fetchone()
                self.assertIsNotNone(row)
                db.execute("UPDATE plugin_security_managed_calls SET il_offset=il_offset+1 WHERE managed_call_id=?", (row[0],))
                db.commit()
                security_second = catalog_revisions.compute_security_revision(db)
                evidence_second = catalog_revisions.compute_evidence_revision(db)
            self.assertEqual(security_first, security_second)
            self.assertNotEqual(evidence_first, evidence_second)

    def test_compaction_records_one_changelog_entry_and_noop_second_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-revision-changelog-") as td:
            root = Path(td)
            source = self.build_fixture_database(root)
            descriptor = root / "catalog.json"
            descriptor.write_text(json.dumps({
                "schemaVersion": 1,
                "schema": "omega.catalog.sqlite.v1",
                "catalogSha256": "",
                "bundleSha256": "",
                "size": 0,
                "databaseBytes": source.stat().st_size,
            }), encoding="utf-8")
            first_out = root / "first"
            first = compact_sqlite_catalog.compact(source, descriptor, first_out, first_out / "compaction-report.json")
            self.assertTrue(first["publication"]["required"])
            self.assertTrue(first["revisions"]["catalogRevisionChanged"])
            with closing(sqlite3.connect(first_out / "omega-catalog.sqlite")) as db:
                self.assertEqual(1, db.execute("SELECT COUNT(*) FROM catalog_changelog").fetchone()[0])
                meta = dict(db.execute("SELECT key,value FROM catalog_meta"))
                self.assertEqual(first["revisions"]["catalogRevision"], meta["catalog_revision"])
                self.assertEqual(first["revisions"]["securityRevision"], meta["security_revision"])

            second_out = root / "second"
            second = compact_sqlite_catalog.compact(
                first_out / "omega-catalog.sqlite",
                first_out / "catalog.json",
                second_out,
                second_out / "compaction-report.json",
                previous_database=first_out / "omega-catalog.sqlite",
                previous_descriptor=first_out / "catalog.json",
            )
            self.assertFalse(second["publication"]["required"])
            self.assertFalse(second["revisions"]["catalogRevisionChanged"])
            with closing(sqlite3.connect(second_out / "omega-catalog.sqlite")) as db:
                self.assertEqual(1, db.execute("SELECT COUNT(*) FROM catalog_changelog").fetchone()[0])

    def test_publication_decision_is_fail_closed_and_reports_revisions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-publication-decision-") as td:
            report = Path(td) / "report.json"
            report.write_text(json.dumps({
                "publication": {"required": False},
                "revisions": {"catalogRevision": "cat-v1-0123456789abcdef", "securityRevision": "sec-2.0.0-0123456789abcdef", "evidenceRevision": "ev-v1-fedcba9876543210"},
            }), encoding="utf-8")
            result = publication_decision.decision(report)
            self.assertEqual("false", result["publish"])
            self.assertEqual("cat-v1-0123456789abcdef", result["catalog_revision"])
            self.assertEqual("sec-2.0.0-0123456789abcdef", result["security_revision"])
            self.assertEqual("ev-v1-fedcba9876543210", result["evidence_revision"])
            report.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                publication_decision.decision(report)

    def test_unversioned_previous_database_creates_baseline_changelog(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-revision-baseline-") as td:
            root = Path(td)
            source = self.build_fixture_database(root)
            previous = root / "previous.sqlite"
            previous.write_bytes(source.read_bytes())
            descriptor = root / "catalog.json"
            descriptor.write_text(json.dumps({
                "schemaVersion": 1, "schema": "omega.catalog.sqlite.v1",
                "catalogSha256": "", "bundleSha256": "", "size": 0, "databaseBytes": source.stat().st_size,
            }), encoding="utf-8")
            out = root / "out"
            result = compact_sqlite_catalog.compact(
                source, descriptor, out, out / "compaction-report.json", previous_database=previous, previous_descriptor=descriptor
            )
            self.assertTrue(result["publication"]["required"])
            self.assertTrue(result["revisions"]["catalogRevisionChanged"])
            with closing(sqlite3.connect(out / "omega-catalog.sqlite")) as db:
                row = db.execute("SELECT previous_catalog_revision,catalog_revision,security_revision FROM catalog_changelog").fetchone()
                self.assertIsNotNone(row)
                self.assertEqual("", row[0])
                self.assertTrue(str(row[1]).startswith("cat-v1-"))
                self.assertTrue(str(row[2]).startswith("sec-"))


if __name__ == "__main__":
    unittest.main()

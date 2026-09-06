from __future__ import annotations
from contextlib import closing
import sqlite3, tempfile, unittest, zipfile
from pathlib import Path

import common  # noqa: F401
import compact_sqlite_catalog
import project_marketplace_catalog
import client_database_audit
import evidence_storage_audit


class StorageAuditTests(unittest.TestCase):
    def test_fresh_client_projection_is_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            out = root / "client.sqlite"
            report = project_marketplace_catalog.project_database(evidence, out)
            self.assertEqual("fresh-allowlist-v1", report["clientProjection"]["mode"])
            with closing(sqlite3.connect(out)) as db:
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
                self.assertTrue(tables <= project_marketplace_catalog.CLIENT_ALLOWED_BASE_TABLES)
                columns = {r[1] for r in db.execute("PRAGMA table_info(plugin_variants)")}
                self.assertNotIn("raw_manifest_json", columns)
                self.assertNotIn("metadata_json", columns)
                meta = dict(db.execute("SELECT key,value FROM catalog_meta"))
                self.assertEqual("fresh-allowlist-v1", meta["client_projection_mode"])
            audit = client_database_audit.audit(out)
            self.assertIn("plugin_search", {row["name"] for row in audit["tables"]})
            self.assertEqual([], audit["prohibitedTables"])
            self.assertEqual("fresh-allowlist-v1", audit["projectionMode"])

    def test_client_database_audit_reports_previous_table_growth(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            previous = root / "previous.sqlite"
            current = root / "current.sqlite"
            bundle = root / "previous.zip"
            for path, count in ((previous, 1), (current, 3)):
                with closing(sqlite3.connect(path)) as db:
                    db.execute("CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT)")
                    db.execute("INSERT INTO catalog_meta VALUES('client_projection_mode','fresh-allowlist-v1')")
                    db.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY,payload TEXT)")
                    db.executemany("INSERT INTO sample(payload) VALUES(?)", [("payload",)] * count)
                    db.commit()
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.write(previous, "omega-marketplace.sqlite")
            report = client_database_audit.audit_with_previous(current, bundle)
            delta = {row["name"]: row for row in report["tableDeltas"]}["sample"]
            self.assertEqual(1, delta["previousRows"])
            self.assertEqual(3, delta["rows"])
            self.assertEqual(2, delta["rowDelta"])
            self.assertEqual(previous.stat().st_size, report["previousDatabaseBytes"])

    def test_evidence_storage_audit_reports_exact_duplicate_bytes_without_deleting(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "variants").mkdir(); (root / "history").mkdir(); (root / "artifacts").mkdir()
            payload = b"same evidence\n"
            (root / "variants" / "1.json").write_bytes(payload)
            (root / "history" / "1.json").write_bytes(payload)
            (root / "artifacts" / "detail.json").write_bytes(b"detail\n")
            report = evidence_storage_audit.audit(root)
            self.assertEqual(3, report["files"])
            self.assertEqual(len(payload), report["exactDuplicateBytes"])
            self.assertGreater(report["historyToCurrentVariantRatio"], 0)


if __name__ == "__main__": unittest.main()

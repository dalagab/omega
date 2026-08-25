from __future__ import annotations
from contextlib import closing
import sqlite3, tempfile, unittest
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
            self.assertEqual([], audit["prohibitedTables"])
            self.assertEqual("fresh-allowlist-v1", audit["projectionMode"])

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

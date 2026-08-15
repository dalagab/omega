from __future__ import annotations

import json
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path

import common  # noqa: F401
import compact_sqlite_catalog
import validate_compacted_catalog


class CompactorUnitTests(unittest.TestCase):
    def test_transport_compression_is_bounded_for_workflow_runtime(self):
        source = Path(compact_sqlite_catalog.__file__).read_text(encoding="utf-8")
        self.assertIn("compresslevel=6", source)
        self.assertNotIn("compresslevel=9", source)

    def test_compactor_preserves_rows_and_bounds_duplicate_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-compactor-unit-") as td:
            tmp = Path(td)
            source = tmp / "omega-catalog.sqlite"
            compact_sqlite_catalog.build_self_test_database(source)
            descriptor = tmp / "catalog.json"
            descriptor.write_text(json.dumps({
                "schemaVersion": 1,
                "schema": "omega.catalog.sqlite.v1",
                "catalogSha256": "",
                "bundleSha256": "",
                "size": 0,
                "databaseBytes": source.stat().st_size,
            }), encoding="utf-8")
            out = tmp / "out"
            report = compact_sqlite_catalog.compact(source, descriptor, out, out / "compaction-report.json")
            self.assertLess(report["databaseBytesAfter"], report["databaseBytesBefore"])
            self.assertLessEqual(report["payload"]["scanReportMaxBytesAfter"], compact_sqlite_catalog.MAX_SUMMARY_BYTES)
            with closing(sqlite3.connect(out / "omega-catalog.sqlite")) as db:
                self.assertEqual(1, db.execute("SELECT COUNT(*) FROM plugin_security_scans").fetchone()[0])
                self.assertEqual(1, db.execute("SELECT COUNT(*) FROM plugin_security_managed_calls").fetchone()[0])
            result = validate_compacted_catalog.validate_local(out)
            self.assertEqual("ok", result["integrity"])


if __name__ == "__main__":
    unittest.main()

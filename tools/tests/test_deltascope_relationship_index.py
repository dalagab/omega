from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from migrate_security_evidence_v2 import _export_workbench_relationship_index
from security_evidence_v2 import read_record_dataset, sha256_file, validate_snapshot
from tools.tests import common


class DeltaScopeRelationshipIndexTests(unittest.TestCase):
    def make_db(self, path: Path) -> sqlite3.Connection:
        db = sqlite3.connect(path)
        db.row_factory = sqlite3.Row
        db.executescript("""
        CREATE TABLE plugin_variants(variant_id INTEGER PRIMARY KEY, plugin_id INTEGER NOT NULL);
        CREATE TABLE plugin_security_current(variant_id INTEGER PRIMARY KEY, scan_id INTEGER, status TEXT, report_json TEXT);
        CREATE TABLE plugin_security_dependencies(dependency_id INTEGER PRIMARY KEY, scan_id INTEGER, origin TEXT, path TEXT);
        CREATE TABLE plugin_security_dependency_resolutions(
            dependency_id INTEGER PRIMARY KEY, scan_id INTEGER, source_plugin_id INTEGER, source_variant_id INTEGER,
            dependency_kind TEXT, dependency_name TEXT, dependency_version TEXT, resolved_version TEXT,
            component_key TEXT, requirement TEXT, relationship TEXT, relationship_confidence TEXT
        );
        CREATE TABLE plugin_security_dependency_components(
            component_key TEXT PRIMARY KEY, component_kind TEXT, display_name TEXT, normalized_name TEXT,
            current_usage_count INTEGER, source_plugin_count INTEGER, source_variant_count INTEGER,
            required_count INTEGER, soft_count INTEGER, optional_count INTEGER, bundled_count INTEGER,
            observed_count INTEGER, unknown_count INTEGER, versions_json TEXT, distinct_version_count INTEGER,
            version_divergence TEXT, refreshed_at_utc TEXT
        );
        CREATE TABLE plugin_security_dependency_advisory_matches(
            advisory_match_id INTEGER PRIMARY KEY, advisory_id TEXT, component_key TEXT, component_kind TEXT,
            component_name TEXT, affected_version TEXT, affected_range TEXT, fixed_version TEXT, severity TEXT,
            title TEXT, advisory_url TEXT, advisory_source TEXT, refreshed_at_utc TEXT
        );
        """)
        report = {
            "intelligence": {
                "networkEndpoints": [
                    {"host": "api.example.test", "url": "https://api.example.test/v1", "classification": "api", "purpose": "service", "originType": "artifact"},
                    {"host": "api.example.test", "url": "https://api.example.test/v2", "classification": "api", "purpose": "service", "originType": "source"},
                ]
            }
        }
        for variant_id, plugin_id, scan_id in ((10, 1, 20), (11, 2, 21)):
            db.execute("INSERT INTO plugin_variants VALUES(?,?)", (variant_id, plugin_id))
            db.execute("INSERT INTO plugin_security_current VALUES(?,?,?,?)", (variant_id, scan_id, "complete", json.dumps(report)))
            dep_id = variant_id
            db.execute("INSERT INTO plugin_security_dependencies VALUES(?,?,?,?)", (dep_id, scan_id, "deps-json", f"plugin{variant_id}.deps.json"))
            db.execute(
                "INSERT INTO plugin_security_dependency_resolutions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (dep_id, scan_id, plugin_id, variant_id, "nuget", "Example.Package", "1.0.0", "1.0.0", "nuget:example.package", "required", "package-reference", "High"),
            )
        db.execute(
            "INSERT INTO plugin_security_dependency_components VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("nuget:example.package", "nuget", "Example.Package", "example.package", 2, 2, 2, 2, 0, 0, 0, 0, 0, '["1.0.0"]', 1, "none", "2026-08-21T00:00:00Z"),
        )
        db.execute(
            "INSERT INTO plugin_security_dependency_advisory_matches VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (1, "GHSA-test", "nuget:example.package", "nuget", "Example.Package", "1.0.0", "<1.0.1", "1.0.1", "high", "Example advisory", "https://example.invalid/GHSA-test", "OSV", "2026-08-21T00:00:00Z"),
        )
        db.commit()
        return db

    def test_relationship_index_groups_endpoints_components_and_advisories(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "indexes").mkdir()
            db = self.make_db(root / "fixture.sqlite")
            try:
                entry, counts = _export_workbench_relationship_index(db, root)
            finally:
                db.close()
            payload = json.loads((root / entry["path"]).read_text(encoding="utf-8"))
            self.assertEqual("omega.security-evidence.workbench-relationships.v2", payload["schema"])
            self.assertEqual("sharded-jsonl-gzip", payload["storage"])
            self.assertTrue(payload["readOnly"])
            self.assertFalse(payload["policyInput"])
            self.assertEqual(payload["relationshipRevision"], entry["relationshipRevision"])
            self.assertEqual(1, counts["endpoints"])
            endpoints = read_record_dataset(root, payload["datasets"]["endpoints"])
            components = read_record_dataset(root, payload["datasets"]["components"])
            advisories = read_record_dataset(root, payload["datasets"]["advisories"])
            self.assertEqual([10, 11], endpoints[0]["variantIds"])
            self.assertEqual(2, len(components[0]["usage"]))
            self.assertEqual([10, 11], [row["variantId"] for row in advisories[0]["affectedAssets"]])
            self.assertTrue(all(
                str(file_info.get("encoding") or "") == "jsonl+gzip"
                for descriptor in payload["datasets"].values()
                for file_info in descriptor.get("files") or []
                if int(descriptor.get("records") or 0) > 0
            ))

    def test_relationship_index_is_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db = self.make_db(root / "fixture.sqlite")
            try:
                out_a, out_b = root / "a", root / "b"
                (out_a / "indexes").mkdir(parents=True)
                (out_b / "indexes").mkdir(parents=True)
                _export_workbench_relationship_index(db, out_a)
                _export_workbench_relationship_index(db, out_b)
            finally:
                db.close()
            files_a = {p.relative_to(out_a).as_posix(): p.read_bytes() for p in out_a.rglob("*") if p.is_file()}
            files_b = {p.relative_to(out_b).as_posix(): p.read_bytes() for p in out_b.rglob("*") if p.is_file()}
            self.assertEqual(files_a, files_b)




if __name__ == "__main__":
    unittest.main()

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
    def test_projection_removes_detailed_security_tables_and_keeps_runtime_projection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-marketplace-test-") as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            compact_sqlite_catalog.build_self_test_database(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('catalog_revision','cat-v1-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_revision','sec-2.0.0-0123456789abcdef')")
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('evidence_revision','ev-v1-0123456789abcdef')")
                db.commit()
                before = project_marketplace_catalog.runtime_projection_digest(db)
            out = root / "marketplace.sqlite"
            projected = project_marketplace_catalog.project_database(evidence, out)
            self.assertEqual(before, projected["runtimeProjectionSha256"])
            with closing(sqlite3.connect(out)) as db:
                leaked = db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchone()[0]
                self.assertEqual(0, leaked)
                self.assertGreater(db.execute("SELECT COUNT(*) FROM runtime_plugin_variants").fetchone()[0], 0)
                self.assertEqual("marketplace", dict(db.execute("SELECT key,value FROM catalog_meta"))["database_role"])

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

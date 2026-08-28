from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import zipfile

import common

CATALOG_TOOLS = common.ROOT / "tools" / "catalog"
if str(CATALOG_TOOLS) not in sys.path:
    sys.path.insert(0, str(CATALOG_TOOLS))

import client_database_audit  # noqa: E402


class ClientDatabaseSecurityRefillGrowthGateTests(unittest.TestCase):
    def _database(
        self,
        path: Path,
        *,
        covered: int,
        finding_bytes: int,
        evidence_revision: str,
        mutate_runtime: bool = False,
    ) -> None:
        with sqlite3.connect(path) as db:
            db.executescript(
                """
                CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE runtime_plugin_variants(
                    variant_id INTEGER PRIMARY KEY,
                    plugin_id INTEGER NOT NULL,
                    internal_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    security_status TEXT NOT NULL DEFAULT '',
                    security_scanned_at_utc TEXT NOT NULL DEFAULT '',
                    security_findings_json TEXT NOT NULL DEFAULT '[]'
                );
                CREATE TABLE plugin_variants(
                    variant_id INTEGER PRIMARY KEY,
                    plugin_id INTEGER NOT NULL
                );
                CREATE TABLE plugins(
                    plugin_id INTEGER PRIMARY KEY,
                    internal_name TEXT NOT NULL
                );
                CREATE TABLE sources(
                    source_id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL
                );
                """
            )
            db.executemany(
                "INSERT INTO catalog_meta(key,value) VALUES(?,?)",
                {
                    "client_projection_mode": "fresh-allowlist-v1",
                    "marketplace_projector_version": "1.7.0",
                    "evidence_revision": evidence_revision,
                }.items(),
            )
            payload = json.dumps(
                [{"id": "fixture", "detail": "x" * finding_bytes}]
            )
            for variant_id in range(1, 81):
                scanned = variant_id <= covered
                db.execute(
                    "INSERT INTO runtime_plugin_variants VALUES(?,?,?,?,?,?,?)",
                    (
                        variant_id,
                        variant_id,
                        f"Plugin{variant_id:03d}",
                        "2.0.0"
                        if mutate_runtime and variant_id == 1
                        else "1.0.0",
                        "complete" if scanned else "",
                        "2026-08-28T20:00:00Z" if scanned else "",
                        payload if scanned else "[]",
                    ),
                )
                db.execute(
                    "INSERT INTO plugin_variants VALUES(?,?)",
                    (variant_id, variant_id),
                )
                db.execute(
                    "INSERT INTO plugins VALUES(?,?)",
                    (variant_id, f"Plugin{variant_id:03d}"),
                )
            db.execute("INSERT INTO sources VALUES(1,'fixture')")
            db.commit()
            db.execute("VACUUM")

    def _bundle(self, database: Path, bundle: Path) -> None:
        with zipfile.ZipFile(
            bundle, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.write(database, "omega-marketplace.sqlite")

    def test_large_security_only_refill_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-security-refill-") as td:
            root = Path(td)
            previous = root / "previous.sqlite"
            current = root / "current.sqlite"
            bundle = root / "previous.zip"
            self._database(
                previous,
                covered=2,
                finding_bytes=64,
                evidence_revision="ev-old",
            )
            self._database(
                current,
                covered=60,
                finding_bytes=4096,
                evidence_revision="ev-new",
            )
            self._bundle(previous, bundle)

            report = client_database_audit.audit_with_previous(
                current, bundle
            )
            self.assertGreater(report["growthRatio"], 1.20)
            allowed, reasons = (
                client_database_audit.security_refill_growth_allowance(report)
            )

            self.assertTrue(allowed, reasons)
            self.assertEqual(
                report["runtimeNonSecurityDigest"],
                report["previousRuntimeNonSecurityDigest"],
            )
            self.assertGreater(
                report["securityCoverage"]["coveredVariants"],
                report["previousSecurityCoverage"]["coveredVariants"],
            )

    def test_non_security_runtime_change_does_not_get_refill_exception(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-security-growth-") as td:
            root = Path(td)
            previous = root / "previous.sqlite"
            current = root / "current.sqlite"
            bundle = root / "previous.zip"
            self._database(
                previous,
                covered=2,
                finding_bytes=64,
                evidence_revision="ev-old",
            )
            self._database(
                current,
                covered=60,
                finding_bytes=4096,
                evidence_revision="ev-new",
                mutate_runtime=True,
            )
            self._bundle(previous, bundle)

            report = client_database_audit.audit_with_previous(
                current, bundle
            )
            allowed, reasons = (
                client_database_audit.security_refill_growth_allowance(report)
            )

            self.assertFalse(allowed)
            self.assertIn("non-security runtime projection changed", reasons)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import common
import compact_sqlite_catalog
import test_sqlite_catalog
import validate_base_catalog
import validate_compacted_catalog
import validate_security_catalog


class ValidationFailClosedTests(unittest.TestCase):
    def build_base(self, tmp: Path) -> Path:
        curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(tmp)
        out = tmp / "base"
        test_sqlite_catalog.run_builder(common.ROOT, out, curated, raw, enriched, websites)
        return out

    def test_base_transport_rejects_descriptor_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-base-validator-") as td:
            root = self.build_base(Path(td))
            descriptor_path = root / "catalog.json"
            descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
            descriptor["bundleSha256"] = "0" * 64
            descriptor_path.write_text(json.dumps(descriptor), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "bundle SHA-256"):
                validate_base_catalog.validate_local(root)

    def test_security_validator_rejects_stale_scanner_report_version(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-security-validator-") as td:
            tmp = Path(td)
            base = self.build_base(tmp)
            security = tmp / "security"
            security.mkdir()
            for name in ("omega-catalog.sqlite", "omega-catalog.sqlite.zip", "catalog.json"):
                (security / name).write_bytes((base / name).read_bytes())
            report = security / "security-report.json"
            subprocess.run([
                sys.executable, str(common.ROOT / "tools/catalog/security_scan.py"),
                "--database", str(security / "omega-catalog.sqlite"),
                "--bundle", str(security / "omega-catalog.sqlite.zip"),
                "--descriptor", str(security / "catalog.json"),
                "--report", str(report),
                "--max-scans", "0", "--max-batch-seconds", "0",
            ], check=True, cwd=common.ROOT, stdout=subprocess.DEVNULL)
            doc = json.loads(report.read_text(encoding="utf-8"))
            doc["scannerVersion"] = "0.0.0"
            report.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "scanner version"):
                validate_security_catalog.validate(security)

    def test_compacted_validator_rejects_descriptor_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-compacted-validator-") as td:
            tmp = Path(td)
            source = tmp / "omega-catalog.sqlite"
            compact_sqlite_catalog.build_self_test_database(source)
            descriptor = tmp / "catalog.json"
            descriptor.write_text(json.dumps({
                "schemaVersion": 1, "schema": "omega.catalog.sqlite.v1",
                "catalogSha256": "", "bundleSha256": "", "size": 0,
                "databaseBytes": source.stat().st_size,
            }), encoding="utf-8")
            out = tmp / "out"
            compact_sqlite_catalog.compact(source, descriptor, out, out / "compaction-report.json")
            output_descriptor = out / "catalog.json"
            doc = json.loads(output_descriptor.read_text(encoding="utf-8"))
            doc["catalogSha256"] = "f" * 64
            output_descriptor.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "catalog SHA-256"):
                validate_compacted_catalog.validate_local(out)


if __name__ == "__main__":
    unittest.main()

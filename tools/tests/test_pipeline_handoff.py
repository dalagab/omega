from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import common
import test_sqlite_catalog
import validate_compacted_catalog
import validate_security_catalog


class PipelineHandoffTests(unittest.TestCase):
    def test_base_to_security_to_compaction_handoff_offline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-pipeline-test-") as td:
            tmp = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(tmp)
            base = tmp / "base"
            test_sqlite_catalog.run_builder(common.ROOT, base, curated, raw, enriched, websites)

            security_root = tmp / "security"
            security_root.mkdir()
            for name in ("omega-catalog.sqlite", "omega-catalog.sqlite.zip", "catalog.json"):
                (security_root / name).write_bytes((base / name).read_bytes())
            report = security_root / "security-report.json"
            subprocess.run(
                [
                    sys.executable,
                    str(common.ROOT / "tools/catalog/security_scan.py"),
                    "--database", str(security_root / "omega-catalog.sqlite"),
                    "--bundle", str(security_root / "omega-catalog.sqlite.zip"),
                    "--descriptor", str(security_root / "catalog.json"),
                    "--report", str(report),
                    "--max-scans", "0",
                    "--max-batch-seconds", "0",
                    "--rescan-after-hours", "168",
                ],
                check=True,
                cwd=common.ROOT,
                stdout=subprocess.DEVNULL,
            )
            security_validation = validate_security_catalog.validate(security_root)
            self.assertEqual("ok", security_validation["database"]["integrity"])

            compacted = tmp / "compacted"
            compaction_report = compacted / "compaction-report.json"
            subprocess.run(
                [
                    sys.executable,
                    str(common.ROOT / "tools/catalog/compact_sqlite_catalog.py"),
                    "--database", str(security_root / "omega-catalog.sqlite"),
                    "--descriptor", str(security_root / "catalog.json"),
                    "--output-dir", str(compacted),
                    "--report", str(compaction_report),
                ],
                check=True,
                cwd=common.ROOT,
                stdout=subprocess.DEVNULL,
            )
            compact_validation = validate_compacted_catalog.validate_local(compacted)
            self.assertEqual("ok", compact_validation["integrity"])
            report_doc = json.loads(compaction_report.read_text(encoding="utf-8"))
            self.assertTrue(report_doc["validation"]["runtimeProjectionSha256"])


if __name__ == "__main__":
    unittest.main()

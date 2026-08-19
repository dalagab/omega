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
import stage_catalog_bootstrap


class _BootstrapRunner(stage_catalog_bootstrap.CommandRunner):
    def __init__(self, artifact_root: Path, fail_first: bool = False) -> None:
        self.artifact_root = artifact_root
        self.fail_first = fail_first
        self.downloads = 0
        self.calls: list[list[str]] = []

    def run(self, argv):
        argv = list(argv)
        self.calls.append(argv)
        if argv[:3] == ["gh", "run", "list"]:
            payload = [
                {"databaseId": 101, "createdAt": "2026-08-19T00:00:00Z", "headSha": "new", "event": "push", "status": "completed", "conclusion": "success"},
                {"databaseId": 100, "createdAt": "2026-08-18T18:00:00Z", "headSha": "fallback", "event": "schedule", "status": "completed", "conclusion": "success"},
            ]
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload), stderr="")
        if argv[:3] == ["gh", "run", "download"]:
            self.downloads += 1
            if self.fail_first and self.downloads == 1:
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="artifact expired")
            destination = Path(argv[argv.index("--dir") + 1])
            destination.mkdir(parents=True, exist_ok=True)
            for name in ("omega-catalog.sqlite", "omega-catalog.sqlite.zip", "catalog.json"):
                (destination / name).write_bytes((self.artifact_root / name).read_bytes())
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(argv, 2, stdout="", stderr="unexpected command")


class PipelineHandoffTests(unittest.TestCase):

    def test_catalog_bootstrap_handoff_uses_latest_retained_builder_artifact_and_falls_back(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-bootstrap-handoff-test-") as td:
            tmp = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(tmp)
            artifact = tmp / "artifact"
            test_sqlite_catalog.run_builder(common.ROOT, artifact, curated, raw, enriched, websites)

            output = tmp / "catalog" / "bootstrap" / "omega-catalog.sqlite.zip"
            runner = _BootstrapRunner(artifact, fail_first=True)
            result = stage_catalog_bootstrap.stage_catalog_bootstrap(
                repository="dalagab/omega",
                branch="main",
                output=output,
                runner=runner,
            )

            self.assertEqual(100, result["runId"], "expired newest artifact must fall back to the next successful builder run")
            self.assertEqual((artifact / "omega-catalog.sqlite.zip").read_bytes(), output.read_bytes())
            self.assertGreater(result["variantCount"], 0)
            listed = next(call for call in runner.calls if call[:3] == ["gh", "run", "list"])
            self.assertIn("catalog-builder.yml", listed)
            self.assertIn("main", listed)
            self.assertIn("success", listed)
            self.assertTrue(any(call[:4] == ["gh", "release", "download", "catalog-latest"] for call in runner.calls))
            downloads = [call for call in runner.calls if call[:3] == ["gh", "run", "download"]]
            self.assertEqual(2, len(downloads))
            self.assertTrue(all("omega-sqlite-catalog" in call for call in downloads))

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
                    str(common.ROOT / "tools/catalog/sigmascope.py"),
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

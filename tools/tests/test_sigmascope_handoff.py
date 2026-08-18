from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import common


MODULE_PATH = common.ROOT / "tools" / "security" / "sigmascope_handoff.py"
spec = importlib.util.spec_from_file_location("omega_sigmascope_handoff", MODULE_PATH)
assert spec and spec.loader
handoff = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = handoff
spec.loader.exec_module(handoff)

AUDIT_SUMMARY_PATH = common.ROOT / "tools" / "security" / "print_sigmascope_audit_failures.py"
audit_spec = importlib.util.spec_from_file_location("omega_sigmascope_audit_summary", AUDIT_SUMMARY_PATH)
assert audit_spec and audit_spec.loader
audit_summary = importlib.util.module_from_spec(audit_spec)
sys.modules[audit_spec.name] = audit_summary
audit_spec.loader.exec_module(audit_summary)


class FakeRunner:
    def __init__(self, *, successful_runs: list[int], downloadable_runs: set[int], release_descriptor: bool = True):
        self.successful_runs = successful_runs
        self.downloadable_runs = downloadable_runs
        self.release_descriptor = release_descriptor
        self.records: list[handoff.CommandRecord] = []

    def _complete(self, argv: list[str], code: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
        self.records.append(handoff.CommandRecord(argv, code, stdout, stderr))
        return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr=stderr)

    def run(self, argv):
        argv = list(argv)
        if argv[:4] == ["gh", "release", "download", "catalog-latest"]:
            destination = Path(argv[argv.index("--dir") + 1])
            destination.mkdir(parents=True, exist_ok=True)
            if self.release_descriptor:
                (destination / "catalog.json").write_text("{}", encoding="utf-8")
                return self._complete(argv)
            return self._complete(argv, 1, stderr="release descriptor unavailable")
        if argv[:3] == ["gh", "run", "list"]:
            payload = [
                {
                    "databaseId": run_id,
                    "createdAt": "2026-08-18T00:00:00Z",
                    "headSha": f"sha-{run_id}",
                    "event": "schedule",
                    "status": "completed",
                    "conclusion": "success",
                }
                for run_id in self.successful_runs
            ]
            return self._complete(argv, stdout=json.dumps(payload))
        if argv[:3] == ["gh", "run", "download"]:
            run_id = int(argv[3])
            destination = Path(argv[argv.index("--dir") + 1])
            destination.mkdir(parents=True, exist_ok=True)
            if run_id not in self.downloadable_runs:
                return self._complete(argv, 1, stderr=f"artifact missing for {run_id}")
            (destination / "omega-catalog.sqlite").write_bytes(b"SQLite format 3\x00fixture")
            (destination / "catalog.json").write_text('{"schema":"fixture"}', encoding="utf-8")
            (destination / "catalog-report.json").write_text("{}", encoding="utf-8")
            return self._complete(argv)
        return self._complete(argv, 1, stderr="unexpected command")


class SigmascopeHandoffTests(unittest.TestCase):
    def _paths(self, root: Path):
        output = root / "security-input"
        previous = root / "previous-marketplace"
        evidence = root / "security-v2-current"
        diagnostics = root / "sigmascope-handoff-diagnostics.json"
        evidence.mkdir(parents=True)
        (evidence / "index.json").write_text("{}", encoding="utf-8")
        (evidence / "validation-report.json").write_text("{}", encoding="utf-8")
        return output, previous, evidence, diagnostics

    def test_scheduled_run_bootstraps_from_latest_successful_builder_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            output, previous, evidence, diagnostics = self._paths(Path(td))
            runner = FakeRunner(successful_runs=[300, 299], downloadable_runs={300}, release_descriptor=False)
            result = handoff.resolve_handoff(
                event_name="schedule",
                repository="dalagab/omega",
                upstream_run_id="",
                output_dir=output,
                previous_marketplace_dir=previous,
                current_evidence_dir=evidence,
                diagnostics_path=diagnostics,
                runner=runner,
            )
            self.assertTrue(result["success"])
            self.assertEqual(300, result["selectedCatalogRunId"])
            self.assertEqual("latest-successful-builder-run", result["sourceMode"])
            self.assertFalse(result["previousMarketplaceDescriptorAvailable"])
            self.assertTrue((output / "omega-catalog.sqlite").is_file())
            saved = json.loads(diagnostics.read_text(encoding="utf-8"))
            self.assertTrue(saved["success"])
            self.assertGreaterEqual(len(saved["commands"]), 3)

    def test_workflow_run_falls_back_when_triggering_artifact_is_unavailable(self):
        with tempfile.TemporaryDirectory() as td:
            output, previous, evidence, diagnostics = self._paths(Path(td))
            runner = FakeRunner(successful_runs=[401, 400], downloadable_runs={401})
            result = handoff.resolve_handoff(
                event_name="workflow_run",
                repository="dalagab/omega",
                upstream_run_id="999",
                output_dir=output,
                previous_marketplace_dir=previous,
                current_evidence_dir=evidence,
                diagnostics_path=diagnostics,
                runner=runner,
            )
            self.assertEqual(401, result["selectedCatalogRunId"])
            self.assertEqual("latest-successful-builder-run", result["sourceMode"])
            attempted_downloads = [r.argv[3] for r in runner.records if r.argv[:3] == ["gh", "run", "download"]]
            self.assertEqual(["999", "401"], attempted_downloads[:2])

    def test_failed_handoff_still_writes_downloadable_diagnostics(self):
        with tempfile.TemporaryDirectory() as td:
            output, previous, evidence, diagnostics = self._paths(Path(td))
            runner = FakeRunner(successful_runs=[501], downloadable_runs=set(), release_descriptor=False)
            with self.assertRaises(handoff.HandoffError):
                handoff.resolve_handoff(
                    event_name="schedule",
                    repository="dalagab/omega",
                    upstream_run_id="",
                    output_dir=output,
                    previous_marketplace_dir=previous,
                    current_evidence_dir=evidence,
                    diagnostics_path=diagnostics,
                    runner=runner,
                )
            saved = json.loads(diagnostics.read_text(encoding="utf-8"))
            self.assertFalse(saved["success"])
            self.assertIn("Could not download a valid", saved["error"])
            self.assertTrue(any(record["returnCode"] == 1 for record in saved["commands"]))

    def test_audit_failure_summary_is_bounded_and_player_debuggable(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.json"
            payload = {
                "counts": {"pass": 1, "warn": 0, "fail": 3},
                "items": [
                    {"status": "fail", "code": "one", "title": "First", "detail": "A", "plugin": "PluginA", "variant_id": 7},
                    {"status": "fail", "code": "two", "title": "Second", "detail": "B", "plugin": "", "variant_id": None},
                    {"status": "fail", "code": "three", "title": "Third", "detail": "C", "plugin": "PluginC", "variant_id": 9},
                ],
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            lines = audit_summary.summarize(path, limit=2)
            self.assertIn("3 failing check(s)", lines[0])
            self.assertIn("PluginA variant 7", lines[1])
            self.assertTrue(lines[-1].startswith("... 1 additional"))


if __name__ == "__main__":
    unittest.main()

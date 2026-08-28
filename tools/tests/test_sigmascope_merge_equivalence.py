from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import common

for root in (common.ROOT / "tools" / "security", common.ROOT / "tools" / "catalog"):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

import sigmascope_merge_equivalence  # noqa: E402
import test_production_sigmascope_v2_pipeline as production_tests  # noqa: E402
from migrate_security_evidence_v2 import migrate  # noqa: E402


class SigmascopeMergeEquivalenceTests(unittest.TestCase):
    def _json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def test_equivalence_accepts_same_semantics_despite_execution_timestamp_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-equivalence-") as td:
            root = Path(td)
            helper = production_tests.ProductionSecurityV2PipelineTests(methodName="test_bounded_batch_report_aggregates_multiple_queue_invocations")
            database, variant_id, _plugin_id = helper.make_catalog_with_security(root)
            serial = root / "serial"
            migrate(database, serial, reset=True)
            parallel = root / "parallel"
            shutil.copytree(serial, parallel)
            queue = {
                "schema": "omega.sigmascope.queue-state.v2", "queueSeedRevision": "seed", "catalogRevision": "cat",
                "catalogIdentityEpoch": "epoch", "definitionsRevision": "defs", "scannerRevision": "scanner",
                "scannerBundleSha256": "a" * 64, "artifactAnalysisRevision": "artifact", "sourceAnalysisRevision": "source",
                "sourceObservationRevision": "sourceobs", "ruleSetRevision": "rules", "srlRuleSetRevision": "srl",
                "advisoryRevision": "osv", "selectionPolicy": "coverage-first", "items": {
                    f"variant-{variant_id}": {"queueKey": f"variant-{variant_id}", "workType": "artifact", "variantId": variant_id,
                        "state": "complete", "targetFingerprint": "target", "scanId": 100, "completedAtUtc": "2026-08-26T05:00:00Z"}
                },
            }
            self._json(serial / "scanner-queue.json", queue)
            queue2 = json.loads(json.dumps(queue)); queue2["updatedAtUtc"] = "2026-08-26T05:01:00Z"; queue2["items"][f"variant-{variant_id}"]["scanId"] = 200
            queue2["items"][f"variant-{variant_id}"]["completedAtUtc"] = "2026-08-26T05:01:00Z"
            self._json(parallel / "scanner-queue.json", queue2)
            # Root scannerQueue descriptor is intentionally absent in this migrated fixture;
            # queue comparison is a separate shadow semantic gate.
            followups = {"schema": "omega.source-scan-followups.v3", "count": 0, "followups": []}
            self._json(root / "serial-followups.json", followups)
            self._json(root / "parallel-followups.json", followups)
            result = sigmascope_merge_equivalence.compare(
                parallel_evidence=parallel, serial_evidence=serial, variant_ids=[variant_id], output=root / "report.json",
                parallel_source_followups=root / "parallel-followups.json", serial_source_followups=root / "serial-followups.json",
            )
            self.assertTrue(result["equivalent"], result["mismatches"])
            self.assertEqual([], result["mismatches"])

    def test_normalize_ignores_transport_relational_identities(self) -> None:
        serial = {
            "scan_id": 2600, "scanId": 2600,
            "currentScanId": 2600, "current_scan_id": 2600,
            "comparison_id": 1349, "comparisonId": 1349,
            "semantic": "same",
        }
        parallel = {
            "scan_id": 2603, "scanId": 2603,
            "currentScanId": 2603, "current_scan_id": 2603,
            "comparison_id": 1352, "comparisonId": 1352,
            "semantic": "same",
        }
        self.assertEqual(
            sigmascope_merge_equivalence._normalize(serial),
            sigmascope_merge_equivalence._normalize(parallel),
        )

    def test_equivalence_detects_source_followup_semantic_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-equivalence-drift-") as td:
            root = Path(td)
            helper = production_tests.ProductionSecurityV2PipelineTests(methodName="test_bounded_batch_report_aggregates_multiple_queue_invocations")
            database, variant_id, _plugin_id = helper.make_catalog_with_security(root)
            serial = root / "serial"; parallel = root / "parallel"
            migrate(database, serial, reset=True); shutil.copytree(serial, parallel)
            self._json(root / "serial-followups.json", {"schema": "omega.source-scan-followups.v3", "count": 0, "followups": []})
            self._json(root / "parallel-followups.json", {"schema": "omega.source-scan-followups.v3", "count": 1, "followups": [{"key": "omega-source-followup:x"}]})
            result = sigmascope_merge_equivalence.compare(
                parallel_evidence=parallel, serial_evidence=serial, variant_ids=[variant_id], output=root / "report.json",
                parallel_source_followups=root / "parallel-followups.json", serial_source_followups=root / "serial-followups.json",
            )
            self.assertFalse(result["equivalent"])
            self.assertIn("source-followups", [item["area"] for item in result["mismatches"]])

    def test_mismatch_report_contains_bounded_field_level_difference_paths(self) -> None:
        serial = {
            "current": {"status": "complete", "source": {"commit": "a" * 40}},
            "items": [{"ruleId": "one"}, {"ruleId": "two"}],
        }
        parallel = {
            "current": {"status": "complete", "source": {"commit": "b" * 40}},
            "items": [{"ruleId": "one"}, {"ruleId": "three"}],
        }
        mismatches: list[dict[str, object]] = []
        sigmascope_merge_equivalence._append_mismatch(mismatches, "variant:1", serial, parallel)
        self.assertEqual(1, len(mismatches))
        differences = mismatches[0]["differences"]
        self.assertIsInstance(differences, list)
        paths = [item["path"] for item in differences]
        self.assertIn("current.source.commit", paths)
        self.assertIn("items[1].ruleId", paths)
        self.assertLessEqual(len(paths), sigmascope_merge_equivalence.MAX_DIFFERENCE_PATHS)

    def test_missing_assigned_variant_is_explicit_absence_not_file_error(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-equivalence-missing-") as td:
            root = Path(td)
            variant_id = 5017
            self.assertEqual(
                {"variantId": variant_id, "present": False},
                sigmascope_merge_equivalence._variant_semantic(root, variant_id),
            )

    def test_present_and_absent_variant_states_are_semantically_different(self) -> None:
        serial = {"variantId": 5017, "present": False}
        parallel = {
            "variantId": 5017,
            "present": True,
            "artifactSha256": "a" * 64,
        }
        mismatches: list[dict[str, object]] = []
        sigmascope_merge_equivalence._append_mismatch(
            mismatches, "variant:5017", serial, parallel
        )
        self.assertEqual(["variant:5017"], [item["area"] for item in mismatches])
        differences = mismatches[0]["differences"]
        self.assertIsInstance(differences, list)
        paths = [item["path"] for item in differences]
        self.assertIn("present", paths)

    def test_equivalence_accepts_requested_variant_absent_from_both_valid_snapshots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-equivalence-both-absent-") as td:
            root = Path(td)
            helper = production_tests.ProductionSecurityV2PipelineTests(
                methodName="test_bounded_batch_report_aggregates_multiple_queue_invocations"
            )
            database, variant_id, _plugin_id = helper.make_catalog_with_security(root)
            serial = root / "serial"
            migrate(database, serial, reset=True)
            parallel = root / "parallel"
            shutil.copytree(serial, parallel)
            missing_variant_id = variant_id + 1_000_000
            result = sigmascope_merge_equivalence.compare(
                parallel_evidence=parallel,
                serial_evidence=serial,
                variant_ids=[missing_variant_id],
                output=root / "report.json",
            )
            self.assertTrue(result["equivalent"], result["mismatches"])
            self.assertEqual([], result["mismatches"])


if __name__ == "__main__":
    unittest.main()

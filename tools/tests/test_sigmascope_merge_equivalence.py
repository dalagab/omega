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


if __name__ == "__main__":
    unittest.main()

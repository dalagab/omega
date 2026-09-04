from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest

import common

for root in (common.ROOT / "tools" / "security", common.ROOT / "tools" / "catalog"):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

import scan_queue  # noqa: E402
import sigmascope_parallel_drain_plan as drain_plan  # noqa: E402

NOW = dt.datetime(2026, 8, 28, 16, 0, tzinfo=dt.timezone.utc)


def artifact_item(index: int) -> dict:
    return {
        "queueKey": f"artifact:{index}", "variantId": index, "pluginId": index,
        "sourceId": 1, "workType": "artifact", "internalName": f"Plugin{index:03d}",
        "name": f"Plugin {index}", "sourceName": "fixture", "targetFingerprint": f"fp-{index}",
        "priority": 950, "primaryReason": "baseline_scan", "reasonCodes": ["baseline_scan"],
        "currentScanId": 0, "currentScannedAtUtc": "",
    }


def seed(items: list[dict], *, baseline: bool = True) -> dict:
    return {
        "schema": scan_queue.SEED_SCHEMA, "queueSeedRevision": "seed-fixture",
        "catalogRevision": "cat-fixture", "catalogIdentityEpoch": "omega-catalog-identity-v1",
        "definitionsRevision": "defs-fixture", "scannerRevision": "scanner-fixture",
        "scannerBundleSha256": "a" * 64, "artifactAnalysisRevision": "artifact-fixture",
        "sourceAnalysisRevision": "source-fixture", "sourceObservationRevision": "source-observation-fixture",
        "ruleSetRevision": "rules-fixture", "srlRuleSetRevision": "srl-fixture",
        "advisoryRevision": "osv-fixture", "baselineSecurityRebuild": baseline,
        "selectionPolicy": scan_queue.SELECTION_POLICY, "reasonContracts": scan_queue.REASON_CONTRACTS,
        "items": items,
    }


class SigmaScopeParallelDrainPlanTests(unittest.TestCase):
    def write_evidence(self, root: Path) -> Path:
        evidence = root / "evidence"
        evidence.mkdir(parents=True)
        (evidence / "index.json").write_text(json.dumps({
            "schema": "omega.security-evidence.v2",
            "revisions": {"evidenceRevision": "ev-fixture", "catalogIdentityEpoch": "omega-catalog-identity-v1"},
        }), encoding="utf-8")
        return evidence

    def test_baseline_rebuild_is_parallel_and_partitioned_four_by_ten(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-drain-plan-") as td:
            root = Path(td)
            seed_path = root / "seed.json"
            seed_path.write_text(json.dumps(seed([artifact_item(i) for i in range(1, 51)])), encoding="utf-8")
            result = drain_plan.build(seed_path, self.write_evidence(root), workers=4, items_per_worker=10,
                                      output=root / "plan.json", now=NOW)
            self.assertTrue(result["baselineSecurityRebuild"])
            self.assertEqual(40, result["assignmentCount"])
            self.assertEqual(4, result["activeWorkerCount"])
            self.assertEqual([10, 10, 10, 10], [row["assignmentCount"] for row in result["matrix"]["include"]])
            self.assertEqual(40, len({item["queueKey"] for item in result["assignments"]}))
            self.assertTrue(result["moreParallelEligible"])
            self.assertFalse(result["serialFallbackRequired"])
            self.assertEqual(50, result["queueSummaryBefore"]["eligibleNow"])
            self.assertEqual(0, result["queueSummaryBefore"]["retryDeferred"])

    def test_coverage_first_keeps_source_followup_behind_uncovered_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-drain-coverage-") as td:
            root = Path(td)
            source = {**artifact_item(999), "queueKey": "source:999", "workType": "source",
                      "priority": 1000, "primaryReason": "source_followup", "reasonCodes": ["source_followup"]}
            seed_path = root / "seed.json"
            seed_path.write_text(json.dumps(seed([source] + [artifact_item(i) for i in range(1, 6)])), encoding="utf-8")
            result = drain_plan.build(seed_path, self.write_evidence(root), workers=1, items_per_worker=5,
                                      output=root / "plan.json", now=NOW)
            self.assertEqual(5, result["assignmentCount"])
            self.assertTrue(all(item["workType"] == "artifact" for item in result["assignments"]))

    def test_global_advisory_yields_to_serial_worker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-drain-advisory-") as td:
            root = Path(td)
            advisory = {
                "queueKey": "advisory:osv", "variantId": 0, "pluginId": 0, "sourceId": 0,
                "workType": "advisory", "internalName": "", "name": "OSV", "sourceName": "",
                "targetFingerprint": "osv-fixture", "priority": 800, "primaryReason": "advisory_changed",
                "reasonCodes": ["advisory_changed"], "currentScanId": 0, "currentScannedAtUtc": "",
            }
            seed_path = root / "seed.json"
            seed_path.write_text(json.dumps(seed([advisory], baseline=False)), encoding="utf-8")
            result = drain_plan.build(seed_path, self.write_evidence(root), workers=4, items_per_worker=10,
                                      output=root / "plan.json", now=NOW)
            self.assertEqual(0, result["assignmentCount"])
            self.assertTrue(result["serialFallbackRequired"])
            self.assertIn("serialized-worker", result["blockedReason"])

    def plan_mixed(self, root: Path, *, workers=2, items=3, wave=1, updates=6, baselines=6):
        requests = [artifact_item(i) for i in range(1, baselines + 1)]
        requests += [{**artifact_item(100 + i), "releaseUpdate": True} for i in range(updates)]
        path = root / "seed.json"
        path.write_text(json.dumps(seed(requests, baseline=False)), encoding="utf-8")
        return drain_plan.build(path, self.write_evidence(root), workers=workers, items_per_worker=items,
                                wave=wave, output=root / "plan.json", now=NOW)

    def test_updates_and_baselines_each_have_reserved_workers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.plan_mixed(Path(directory), workers=4)
            by_key = {item["queueKey"]: item for item in result["assignments"]}
            self.assertEqual(12, len(by_key))
            for slot in result["matrix"]["include"]:
                self.assertEqual(3, slot["assignmentCount"])
                self.assertTrue(all(by_key[key]["releaseUpdate"] == (slot["lane"] == "updates") for key in slot["queueKeys"]))

    def test_empty_lane_lends_all_capacity(self) -> None:
        for updates, baselines in ((10, 0), (0, 10)):
            with self.subTest(updates=updates), tempfile.TemporaryDirectory() as directory:
                result = self.plan_mixed(Path(directory), updates=updates, baselines=baselines)
                self.assertEqual(6, result["assignmentCount"])
                self.assertEqual(6, len({item["queueKey"] for item in result["assignments"]}))

    def test_single_worker_single_item_waves_do_not_starve_either_lane(self) -> None:
        for wave, update in ((1, True), (2, False)):
            with self.subTest(wave=wave), tempfile.TemporaryDirectory() as directory:
                result = self.plan_mixed(Path(directory), workers=1, items=1, wave=wave)
                self.assertEqual(update, result["assignments"][0]["releaseUpdate"])


if __name__ == "__main__":
    unittest.main()

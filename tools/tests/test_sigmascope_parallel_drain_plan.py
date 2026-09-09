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


def source_item(index: int, *, reason: str = "source_analysis_changed") -> dict:
    item = artifact_item(index)
    item.update({
        "queueKey": f"source:{index}",
        "workType": "source",
        "pluginHasCurrentScan": True,
        "priority": scan_queue.REASON_PRIORITIES[reason],
        "primaryReason": reason,
        "reasonCodes": [reason],
        "reasons": [reason],
        "currentScanId": index,
        "currentScannedAtUtc": "2026-08-28T15:00:00Z",
    })
    return item


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

    def test_baseline_rebuild_defaults_to_eight_by_eight_and_caps_at_sixty_four(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-drain-plan-") as td:
            root = Path(td)
            seed_path = root / "seed.json"
            seed_path.write_text(json.dumps(seed([artifact_item(i) for i in range(1, 71)])), encoding="utf-8")
            result = drain_plan.build(seed_path, self.write_evidence(root),
                                      output=root / "plan.json", now=NOW)
            self.assertTrue(result["baselineSecurityRebuild"])
            self.assertEqual(64, result["assignmentCount"])
            self.assertEqual(8, result["activeWorkerCount"])
            self.assertEqual([8] * 8, [row["assignmentCount"] for row in result["matrix"]["include"]])
            self.assertEqual(64, len({item["queueKey"] for item in result["assignments"]}))
            self.assertTrue(result["moreParallelEligible"])
            self.assertFalse(result["serialFallbackRequired"])
            self.assertEqual(70, result["queueSummaryBefore"]["eligibleNow"])
            self.assertEqual(0, result["queueSummaryBefore"]["retryDeferred"])

    def test_large_artifact_retry_gets_one_dedicated_resource_slot_without_reducing_standard_capacity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-drain-large-") as td:
            root = Path(td)
            requests = [artifact_item(i) for i in range(1, 65)]
            large = artifact_item(900)
            large["resourceClass"] = scan_queue.LARGE_ARTIFACT_RESOURCE_CLASS
            seed_path = root / "seed.json"
            seed_path.write_text(json.dumps(seed(requests + [large])), encoding="utf-8")
            result = drain_plan.build(seed_path, self.write_evidence(root), output=root / "plan.json", now=NOW)

            self.assertEqual(65, result["assignmentCount"])
            self.assertEqual(9, result["activeWorkerCount"])
            standard = [row for row in result["matrix"]["include"] if row["resourceClass"] == "standard"]
            large_slots = [row for row in result["matrix"]["include"] if row["resourceClass"] == "large-artifact"]
            self.assertEqual([8] * 8, [row["assignmentCount"] for row in standard])
            self.assertEqual(1, len(large_slots))
            self.assertEqual(1, large_slots[0]["assignmentCount"])
            self.assertEqual(1024 * 1024 * 1024, large_slots[0]["maxArtifactBytes"])
            self.assertEqual(2 * 1024 * 1024 * 1024, large_slots[0]["maxArchiveUncompressedBytes"])
            self.assertEqual(["artifact:900"], large_slots[0]["queueKeys"])
            by_key = {item["queueKey"]: item for item in result["assignments"]}
            self.assertEqual("large-artifact", by_key["artifact:900"]["resourceClass"])

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

    def test_source_semantic_backfill_gets_one_reserved_standard_worker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-drain-source-semantic-") as td:
            root = Path(td)
            requests = [artifact_item(i) for i in range(1, 101)]
            requests += [source_item(1000 + i) for i in range(20)]
            seed_path = root / "seed.json"
            seed_path.write_text(json.dumps(seed(requests, baseline=False)), encoding="utf-8")
            result = drain_plan.build(seed_path, self.write_evidence(root),
                                      workers=8, items_per_worker=8, wave=1,
                                      output=root / "plan.json", now=NOW)

            self.assertEqual(64, result["assignmentCount"])
            reservation = result["sourceSemanticReservation"]
            self.assertTrue(reservation["enabled"])
            self.assertEqual(7, reservation["slot"])
            self.assertEqual("baseline", reservation["fallbackLane"])
            self.assertEqual(8, reservation["reservedCapacity"])
            self.assertEqual(8, reservation["assigned"])
            self.assertGreaterEqual(reservation["totalReasonAssignments"], 8)
            reserved = next(slot for slot in result["matrix"]["include"] if slot["slot"] == 7)
            self.assertEqual("source-semantic", reserved["lane"])
            by_key = {item["queueKey"]: item for item in result["assignments"]}
            self.assertTrue(all(by_key[key]["workType"] == "source" for key in reserved["queueKeys"]))

    def test_source_semantic_slot_lends_unused_capacity_back_to_normal_lane(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-drain-source-semantic-lend-") as td:
            root = Path(td)
            requests = [artifact_item(i) for i in range(1, 101)]
            requests += [source_item(1000), source_item(1001)]
            seed_path = root / "seed.json"
            seed_path.write_text(json.dumps(seed(requests, baseline=False)), encoding="utf-8")
            result = drain_plan.build(seed_path, self.write_evidence(root),
                                      workers=8, items_per_worker=8, wave=1,
                                      output=root / "plan.json", now=NOW)

            self.assertEqual(64, result["assignmentCount"])
            reservation = result["sourceSemanticReservation"]
            self.assertEqual(2, reservation["assigned"])
            reserved = next(slot for slot in result["matrix"]["include"] if slot["slot"] == 7)
            by_key = {item["queueKey"]: item for item in result["assignments"]}
            self.assertEqual(8, reserved["assignmentCount"])
            self.assertEqual(2, sum(1 for key in reserved["queueKeys"] if by_key[key]["workType"] == "source"))
            self.assertEqual(6, sum(1 for key in reserved["queueKeys"] if by_key[key]["workType"] == "artifact"))

    def test_source_semantic_reservation_alternates_donor_lane_by_wave(self) -> None:
        for wave, expected_slot, expected_fallback in ((1, 7, "baseline"), (2, 6, "updates")):
            with self.subTest(wave=wave), tempfile.TemporaryDirectory(prefix="omega-drain-source-fair-") as td:
                root = Path(td)
                requests = [artifact_item(i) for i in range(1, 101)] + [source_item(1000 + i) for i in range(20)]
                seed_path = root / "seed.json"
                seed_path.write_text(json.dumps(seed(requests, baseline=False)), encoding="utf-8")
                result = drain_plan.build(seed_path, self.write_evidence(root),
                                          workers=8, items_per_worker=8, wave=wave,
                                          output=root / "plan.json", now=NOW)
                reservation = result["sourceSemanticReservation"]
                self.assertEqual(expected_slot, reservation["slot"])
                self.assertEqual(expected_fallback, reservation["fallbackLane"])

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

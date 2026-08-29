from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1] / "security"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import deltascope_scan_queue


class DeltaScopeScanQueueTests(unittest.TestCase):
    def queue(self):
        return {
            "schema": "omega.sigmascope.queue-state.v2",
            "selectionPolicy": "coverage-first-v1",
            "baselineSecurityRebuild": False,
            "catalogIdentityEpoch": "omega-catalog-identity-v1",
            "artifactAnalysisRevision": "artifact-analysis-v3-new",
            "items": {
                "z": {"queueKey": "z", "variantId": 9, "workType": "artifact", "internalName": "Zulu", "priority": 900, "state": "pending", "currentScanId": 0, "currentScannedAtUtc": "", "attemptCount": 0, "primaryReason": "new_variant", "reasons": ["new_variant"]},
                "a": {"queueKey": "a", "variantId": 2, "workType": "artifact", "internalName": "AlphaPlugin", "priority": 900, "state": "pending", "currentScanId": 0, "currentScannedAtUtc": "", "attemptCount": 0, "primaryReason": "new_variant", "reasons": ["new_variant"]},
                "retry": {"queueKey": "retry", "variantId": 4, "workType": "artifact", "internalName": "BetaRetry", "priority": 950, "state": "retry", "currentScanId": 0, "currentScannedAtUtc": "", "attemptCount": 2, "primaryReason": "failed_retry", "reasons": ["failed_retry"]},
                "covered": {"queueKey": "covered", "variantId": 1, "workType": "artifact", "internalName": "AlreadyCovered", "priority": 1000, "state": "pending", "currentScanId": 44, "currentScannedAtUtc": "2026-08-20T10:00:00Z", "attemptCount": 0, "primaryReason": "artifact_analysis_changed", "reasons": ["artifact_analysis_changed"]},
            },
            "recentCompleted": [],
        }

    def test_explains_first_coverage_without_calling_it_reset(self):
        result = deltascope_scan_queue.project_scan_queue(self.queue(), current_variants=100)
        self.assertEqual("first-coverage", result["mode"])
        self.assertFalse(result["baselineSecurityRebuild"])
        self.assertIn("not a scan reset", result["headline"].lower())
        self.assertIn("InternalName", result["explanation"])
        self.assertEqual(2, result["counts"]["firstCoverage"])
        self.assertEqual(1, result["counts"]["firstCoverageRetry"])
        self.assertEqual(1, result["counts"]["coveredRefresh"])

    def test_exact_next_order_mirrors_coverage_first_then_alpha_tiebreak(self):
        result = deltascope_scan_queue.project_scan_queue(self.queue())
        self.assertEqual(["AlphaPlugin", "Zulu", "BetaRetry", "AlreadyCovered"], [row["internalName"] for row in result["nextItems"]])

    def test_baseline_rebuild_is_explicit(self):
        queue = self.queue()
        queue["baselineSecurityRebuild"] = True
        queue["items"]["a"]["primaryReason"] = "baseline_scan"
        queue["items"]["a"]["reasons"] = ["baseline_scan"]
        result = deltascope_scan_queue.project_scan_queue(queue)
        self.assertEqual("baseline-rebuild", result["mode"])
        self.assertIn("identity baseline", result["headline"].lower())

    def test_unknown_policy_refuses_to_claim_exact_order(self):
        queue = self.queue()
        queue["selectionPolicy"] = "future-policy-v9"
        result = deltascope_scan_queue.project_scan_queue(queue)
        self.assertFalse(result["selectionOrderExact"])
        self.assertEqual("unknown-policy", result["mode"])
        self.assertEqual([], result["lanes"])


    def test_complete_queue_is_projected_with_rank_and_next_marker(self):
        result = deltascope_scan_queue.project_scan_queue(self.queue())
        self.assertEqual(4, len(result["queueItems"]))
        self.assertEqual([1, 2, 3, 4], [row["rank"] for row in result["queueItems"]])
        self.assertTrue(result["queueItems"][0]["isNext"])
        self.assertFalse(any(row["isNext"] for row in result["queueItems"][1:]))

    def test_complete_queue_is_not_truncated_to_preview_limit(self):
        queue = self.queue()
        queue["items"] = {
            str(i): {
                "queueKey": str(i), "variantId": i + 1, "workType": "artifact",
                "internalName": f"Plugin{i:03d}", "priority": 900, "state": "pending",
                "currentScanId": 0, "currentScannedAtUtc": "", "attemptCount": 0,
                "primaryReason": "new_variant", "reasons": ["new_variant"],
            }
            for i in range(55)
        }
        result = deltascope_scan_queue.project_scan_queue(queue)
        self.assertEqual(55, len(result["queueItems"]))
        self.assertEqual(deltascope_scan_queue.MAX_NEXT_ITEMS, len(result["nextItems"]))
        self.assertEqual(55, result["queueItems"][-1]["rank"])

    def test_ruleset_change_is_not_an_artifact_scan_reason_by_itself(self):
        result = deltascope_scan_queue.project_scan_queue(self.queue())
        self.assertFalse(result["rulesetScanBoundary"]["rulesetChangeRequiresArtifactScan"])
        self.assertIn("not an artifact-scan reason", result["rulesetScanBoundary"]["explanation"])

    def test_operational_work_class_distinguishes_deep_source_and_reprojection(self):
        queue = self.queue()
        queue["items"] = {
            "deep": {"queueKey": "deep", "variantId": 1, "workType": "artifact", "internalName": "Deep", "priority": 1000, "state": "pending", "currentScanId": 9, "currentScannedAtUtc": "2026-08-20T00:00:00Z", "primaryReason": "srl_observation_missing", "reasons": ["srl_observation_missing"]},
            "advisory": {"queueKey": "advisory", "variantId": 2, "workType": "artifact", "internalName": "Advisory", "priority": 900, "state": "pending", "currentScanId": 8, "currentScannedAtUtc": "2026-08-20T00:00:00Z", "primaryReason": "advisory_changed", "reasons": ["advisory_changed"]},
            "source": {"queueKey": "source", "variantId": 3, "workType": "source", "internalName": "Source", "priority": 800, "state": "pending", "currentScanId": 7, "currentScannedAtUtc": "2026-08-20T00:00:00Z", "primaryReason": "source_followup", "reasons": ["source_followup"]},
        }
        rows = {row["queueKey"]: row for row in deltascope_scan_queue.project_scan_queue(queue)["queueItems"]}
        self.assertTrue(rows["deep"]["requiresArtifactScan"])
        self.assertIn("deep", rows["deep"]["operationalAction"].lower())
        self.assertFalse(rows["advisory"]["requiresArtifactScan"])
        self.assertIn("retained dependency evidence", rows["advisory"]["operationalAction"].lower())
        self.assertFalse(rows["source"]["requiresArtifactScan"])
        self.assertIn("source", rows["source"]["operationalAction"].lower())

    def test_projection_has_no_authority(self):
        result = deltascope_scan_queue.project_scan_queue(self.queue())
        self.assertTrue(result["readOnly"])
        self.assertEqual("none", result["mutationAuthority"])
        self.assertFalse(result["policyInput"])
        self.assertFalse(result["queueMutationAuthorized"])
        self.assertFalse(result["scanExecutionAuthorized"])
        self.assertFalse(result["publicationAuthorized"])


if __name__ == "__main__":
    unittest.main()

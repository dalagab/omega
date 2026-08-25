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

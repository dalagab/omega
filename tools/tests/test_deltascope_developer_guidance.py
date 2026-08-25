from __future__ import annotations

import sys
import unittest
from pathlib import Path

SECURITY = Path(__file__).resolve().parents[1] / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_developer_guidance as guidance


class DeveloperGuidanceTests(unittest.TestCase):
    def base(self):
        return {
            "identity": {"plugin_id": 10, "variant_id": 101, "highest_severity": "none"},
            "researcher": {"findings": []},
            "sourceCoverage": {"sourceCodeAvailable": True, "sourceToBinaryVerified": True},
            "secondarySecurity": {"engines": [{"engine": "YARA", "status": "complete"}]},
            "catalogContext": {"shownVariantCount": 1, "withoutCurrentEvidenceVariantCount": 0, "variants": [], "divergence": {"signals": []}},
            "versionHistory": [],
            "advisories": [],
        }

    def test_clear_plan_has_no_authority(self):
        result = guidance.project_developer_review_plan(self.base())
        self.assertEqual("omega.deltascope.developer-review-plan.v1", result["schema"])
        self.assertEqual("clear", result["state"])
        self.assertEqual([], result["actions"])
        self.assertEqual("none", result["mutationAuthority"])
        self.assertFalse(result["policyInput"])
        self.assertFalse(result["findingAuthority"])
        self.assertFalse(result["queueMutationAuthority"])

    def test_high_finding_is_prioritized(self):
        detail = self.base()
        detail["identity"]["highest_severity"] = "high"
        detail["researcher"]["findings"] = [{"finding_id": "x", "severity": "high"}]
        result = guidance.project_developer_review_plan(detail)
        self.assertEqual("review", result["state"])
        self.assertEqual("elevated-findings", result["actions"][0]["actionId"])
        self.assertEqual("findings", result["actions"][0]["targetTab"])

    def test_divergence_attention_becomes_exact_variant_review(self):
        detail = self.base()
        detail["catalogContext"] = {
            "shownVariantCount": 2,
            "withoutCurrentEvidenceVariantCount": 1,
            "variants": [{"variant_id": 101, "currentEvidence": True}, {"variant_id": 102, "currentEvidence": False}],
            "divergence": {"signals": [{"level": "attention", "label": "Same-version siblings differ", "variantIds": [101, 102]}]},
        }
        result = guidance.project_developer_review_plan(detail)
        action = next(a for a in result["actions"] if a["actionId"] == "compare-siblings")
        self.assertEqual([101, 102], action["variantIds"])
        self.assertEqual("overview", action["targetTab"])
        self.assertNotIn("unscanned-siblings", [a["actionId"] for a in result["actions"]])

    def test_source_and_secondary_gaps_route_to_existing_tabs(self):
        detail = self.base()
        detail["sourceCoverage"] = {"sourceCodeAvailable": False, "sourceToBinaryVerified": False}
        detail["secondarySecurity"] = {"engines": [{"engine": "ClamAV", "status": "unavailable"}]}
        result = guidance.project_developer_review_plan(detail)
        actions = {a["actionId"]: a for a in result["actions"]}
        self.assertEqual("supply", actions["source-attribution"]["targetTab"])
        self.assertEqual("malware", actions["secondary-coverage"]["targetTab"])

    def test_history_and_advisories_remain_bounded_navigation_cues(self):
        detail = self.base()
        detail["advisories"] = [{"id": "OSV-1"}]
        detail["versionHistory"] = [{"scan": 1}, {"scan": 2}]
        result = guidance.project_developer_review_plan(detail)
        actions = {a["actionId"]: a for a in result["actions"]}
        self.assertEqual("supply", actions["advisories"]["targetTab"])
        self.assertEqual("compare", actions["version-history"]["targetTab"])
        self.assertLessEqual(len(result["actions"]), 8)


if __name__ == "__main__":
    unittest.main()

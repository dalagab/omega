from __future__ import annotations

from pathlib import Path
import sys
import unittest

import common  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_plugin_divergence as divergence


class DeltaScopeLogicalPluginDivergenceTests(unittest.TestCase):
    def context(self, variants):
        return {
            "pluginId": 326,
            "catalogActive": True,
            "variantScope": "active",
            "variants": variants,
        }

    def test_partial_coverage_is_attention_without_becoming_finding(self) -> None:
        result = divergence.project_logical_plugin_divergence(self.context([
            {"variant_id": 1, "active": 1, "is_hide": 0, "assembly_version": "1.0.0", "dalamud_api_level": 15,
             "source_name": "Repo A", "currentEvidence": True, "evidenceHighestSeverity": "none", "evidenceArtifactSha256": "a" * 64},
            {"variant_id": 2, "active": 1, "is_hide": 0, "assembly_version": "1.0.0", "dalamud_api_level": 15,
             "source_name": "Repo B", "currentEvidence": False},
        ]))
        self.assertEqual("review", result["state"])
        self.assertFalse(result["findingAuthority"])
        self.assertFalse(result["policyInput"])
        kinds = {row["kind"] for row in result["signals"]}
        self.assertIn("coverage-gap", kinds)

    def test_same_version_artifact_and_security_difference_are_review_cues(self) -> None:
        result = divergence.project_logical_plugin_divergence(self.context([
            {"variant_id": 10, "active": 1, "is_hide": 0, "assembly_version": "2.0.0", "dalamud_api_level": 15,
             "source_url": "https://a.invalid", "currentEvidence": True, "evidenceArtifactSha256": "a" * 64,
             "evidenceHighestSeverity": "none", "evidenceFindingCounts": {"informational": 0, "caution": 0, "high": 0, "critical": 0}},
            {"variant_id": 11, "active": 1, "is_hide": 0, "assembly_version": "2.0.0", "dalamud_api_level": 15,
             "source_url": "https://b.invalid", "currentEvidence": True, "evidenceArtifactSha256": "b" * 64,
             "evidenceHighestSeverity": "caution", "evidenceFindingCounts": {"informational": 0, "caution": 1, "high": 0, "critical": 0}},
        ]))
        kinds = {row["kind"] for row in result["signals"]}
        self.assertEqual("review", result["state"])
        self.assertIn("same-version-artifact-difference", kinds)
        self.assertIn("same-version-security-difference", kinds)

    def test_different_versions_do_not_turn_different_hashes_into_artifact_warning(self) -> None:
        result = divergence.project_logical_plugin_divergence(self.context([
            {"variant_id": 20, "active": 1, "is_hide": 0, "assembly_version": "1.0.0", "dalamud_api_level": 15,
             "source_name": "Repo A", "currentEvidence": True, "evidenceArtifactSha256": "a" * 64,
             "evidenceHighestSeverity": "none"},
            {"variant_id": 21, "active": 1, "is_hide": 0, "assembly_version": "2.0.0", "dalamud_api_level": 15,
             "source_name": "Repo B", "currentEvidence": True, "evidenceArtifactSha256": "b" * 64,
             "evidenceHighestSeverity": "none"},
        ]))
        kinds = {row["kind"] for row in result["signals"]}
        self.assertEqual("mixed", result["state"])
        self.assertIn("version-skew", kinds)
        self.assertNotIn("same-version-artifact-difference", kinds)

    def test_hidden_active_variant_is_not_part_of_normal_comparison(self) -> None:
        result = divergence.project_logical_plugin_divergence(self.context([
            {"variant_id": 30, "active": 1, "is_hide": 0, "assembly_version": "1.0.0", "dalamud_api_level": 15,
             "source_name": "Visible", "currentEvidence": True},
            {"variant_id": 31, "active": 1, "is_hide": 1, "assembly_version": "9.0.0", "dalamud_api_level": 15,
             "source_name": "Hidden", "currentEvidence": False},
        ]))
        self.assertEqual(1, result["comparableVariantCount"])
        self.assertEqual("single", result["state"])

    def test_historical_scope_keeps_retained_siblings_comparable(self) -> None:
        result = divergence.project_logical_plugin_divergence({
            "pluginId": 4, "catalogActive": False, "variantScope": "historical",
            "variants": [
                {"variant_id": 40, "active": 0, "assembly_version": "1.0", "dalamud_api_level": 13, "source_name": "A", "currentEvidence": False},
                {"variant_id": 41, "active": 0, "assembly_version": "2.0", "dalamud_api_level": 14, "source_name": "B", "currentEvidence": False},
            ],
        })
        self.assertEqual("historical", result["variantScope"])
        self.assertEqual(2, result["comparableVariantCount"])
        self.assertIn("version-skew", {row["kind"] for row in result["signals"]})


if __name__ == "__main__":
    unittest.main()

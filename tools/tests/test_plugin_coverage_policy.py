from __future__ import annotations

import sys
import unittest
from pathlib import Path


CATALOG_TOOLS = Path(__file__).resolve().parents[1] / "catalog"
if str(CATALOG_TOOLS) not in sys.path:
    sys.path.insert(0, str(CATALOG_TOOLS))

import plugin_coverage_policy as policy


def _item(
    queue_key: str,
    *,
    plugin_id: int,
    variant_id: int,
    source_class: str,
    attempt_count: int = 0,
    plugin_has_current_scan: bool = False,
) -> dict:
    return {
        "queueKey": queue_key,
        "workType": "artifact",
        "pluginId": plugin_id,
        "variantId": variant_id,
        "internalName": f"Plugin{plugin_id}",
        "sourceName": source_class,
        "sourcePriorityClass": source_class,
        "artifactChannel": "stable",
        "priority": 950,
        "currentScanId": 0,
        "currentScannedAtUtc": "",
        "attemptCount": attempt_count,
        "pluginHasCurrentScan": plugin_has_current_scan,
        "state": "pending",
    }


class PluginCoveragePolicyTests(unittest.TestCase):
    def test_source_classes_are_provenance_not_trust_labels(self) -> None:
        self.assertEqual("official", policy.source_priority_class({"is_official": 1}))
        self.assertEqual("curated", policy.source_priority_class({"curated_id": "known-repo"}))
        self.assertEqual("curated", policy.source_priority_class({"discovered_by": "curated-sources.json"}))
        self.assertEqual("discovered", policy.source_priority_class({"discovered_by": "catalog-discovery"}))

    def test_one_representative_per_plugin_precedes_secondary_variants(self) -> None:
        p10_official = _item("variant-10", plugin_id=10, variant_id=10, source_class="official")
        p10_discovered = _item("variant-11", plugin_id=10, variant_id=11, source_class="discovered")
        p20_curated = _item("variant-20", plugin_id=20, variant_id=20, source_class="curated")
        p30_discovered = _item("variant-30", plugin_id=30, variant_id=30, source_class="discovered")
        items = [p10_discovered, p30_discovered, p20_curated, p10_official]

        covered: set[int] = set()
        first = min(items, key=lambda item: policy.selection_sort_key(item, covered))
        self.assertEqual(10, first["variantId"])
        covered.add(first["pluginId"])

        remaining = [item for item in items if item is not first]
        second = min(remaining, key=lambda item: policy.selection_sort_key(item, covered))
        self.assertEqual(20, second["variantId"])
        covered.add(second["pluginId"])

        remaining.remove(second)
        third = min(remaining, key=lambda item: policy.selection_sort_key(item, covered))
        self.assertEqual(30, third["variantId"])
        covered.add(third["pluginId"])

        remaining.remove(third)
        fourth = min(remaining, key=lambda item: policy.selection_sort_key(item, covered))
        self.assertEqual(11, fourth["variantId"])
        self.assertEqual(2, policy.selection_lane(fourth, covered))

    def test_existing_published_plugin_coverage_defers_secondary_variant(self) -> None:
        already_covered = _item(
            "variant-1", plugin_id=1, variant_id=1, source_class="official", plugin_has_current_scan=True,
        )
        uncovered_unknown = _item("variant-2", plugin_id=2, variant_id=2, source_class="discovered")
        covered = policy.covered_plugin_ids([already_covered, uncovered_unknown])
        self.assertEqual({1}, covered)
        selected = min(
            [already_covered, uncovered_unknown],
            key=lambda item: policy.selection_sort_key(item, covered),
        )
        self.assertEqual(2, selected["variantId"])

    def test_failed_representative_leaves_sibling_available_as_fallback(self) -> None:
        failed = _item(
            "variant-1", plugin_id=1, variant_id=1, source_class="official", attempt_count=1,
        )
        sibling = _item("variant-2", plugin_id=1, variant_id=2, source_class="discovered")
        self.assertEqual(1, policy.selection_lane(failed, set()))
        self.assertEqual(0, policy.selection_lane(sibling, set()))
        selected = min([failed, sibling], key=lambda item: policy.selection_sort_key(item, set()))
        self.assertEqual(2, selected["variantId"])

    def test_completed_artifact_marks_plugin_covered_inside_same_wave(self) -> None:
        completed = _item("variant-1", plugin_id=7, variant_id=1, source_class="curated")
        sibling = _item("variant-2", plugin_id=7, variant_id=2, source_class="discovered")
        completed["state"] = "complete"
        covered = policy.covered_plugin_ids([completed, sibling])
        self.assertEqual({7}, covered)
        self.assertEqual(2, policy.selection_lane(sibling, covered))

    def test_update_lane_does_not_promote_generic_reanalysis_or_source_work(self) -> None:
        base = {"workType": "artifact"}
        self.assertTrue(policy.is_release_update({**base, "reasons": ["artifact_version_changed"]}))
        self.assertTrue(policy.is_release_update({**base, "reasons": ["new_variant"], "pluginHasCurrentScan": True}))
        self.assertTrue(policy.is_release_update({**base, "releaseUpdate": True}))
        self.assertFalse(policy.is_release_update({**base, "reasons": ["new_variant"]}))
        self.assertFalse(policy.is_release_update({**base, "reasons": ["artifact_analysis_changed"], "pluginHasCurrentScan": True}))
        self.assertFalse(policy.is_release_update({"workType": "source", "releaseUpdate": True}))


if __name__ == "__main__":
    unittest.main()

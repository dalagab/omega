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
                "z": {"queueKey": "z", "variantId": 9, "pluginId": 9, "workType": "artifact", "internalName": "Zulu", "priority": 900, "state": "pending", "currentScanId": 0, "currentScannedAtUtc": "", "attemptCount": 0, "primaryReason": "new_variant", "reasons": ["new_variant"]},
                "a": {"queueKey": "a", "variantId": 2, "pluginId": 2, "workType": "artifact", "internalName": "AlphaPlugin", "priority": 900, "state": "pending", "currentScanId": 0, "currentScannedAtUtc": "", "attemptCount": 0, "primaryReason": "new_variant", "reasons": ["new_variant"]},
                "retry": {"queueKey": "retry", "variantId": 4, "pluginId": 4, "workType": "artifact", "internalName": "BetaRetry", "priority": 950, "state": "retry", "currentScanId": 0, "currentScannedAtUtc": "", "attemptCount": 2, "primaryReason": "failed_retry", "reasons": ["failed_retry"]},
                "covered": {"queueKey": "covered", "variantId": 1, "pluginId": 1, "workType": "artifact", "internalName": "AlreadyCovered", "priority": 1000, "state": "pending", "currentScanId": 44, "currentScannedAtUtc": "2026-08-20T10:00:00Z", "attemptCount": 0, "primaryReason": "artifact_analysis_changed", "reasons": ["artifact_analysis_changed"]},
            },
            "recentCompleted": [],
        }

    def v2_item(
        self,
        key: str,
        *,
        plugin_id: int,
        variant_id: int,
        source_class: str = "discovered",
        channel: str = "stable",
        attempts: int = 0,
        priority: int = 900,
        nudge: int = 0,
        scanned_at: str = "",
        plugin_has_current: bool = False,
        source_name: str = "",
        internal_name: str = "",
    ):
        return {
            "queueKey": key,
            "variantId": variant_id,
            "pluginId": plugin_id,
            "workType": "artifact",
            "internalName": internal_name or f"Plugin{plugin_id}",
            "sourceName": source_name or source_class,
            "sourcePriorityClass": source_class,
            "artifactChannel": channel,
            "priority": priority,
            "operatorNudgeScore": nudge,
            "state": "retry" if attempts else "pending",
            "currentScanId": 0,
            "currentScannedAtUtc": scanned_at,
            "attemptCount": attempts,
            "pluginHasCurrentScan": plugin_has_current,
            "primaryReason": "failed_retry" if attempts else "new_variant",
            "reasons": ["failed_retry" if attempts else "new_variant"],
        }

    def v2_queue(self, items):
        return {
            "schema": "omega.sigmascope.queue-state.v2",
            "selectionPolicy": "plugin-coverage-first-v2",
            "baselineSecurityRebuild": False,
            "items": {item["queueKey"]: item for item in items},
            "recentCompleted": [],
        }

    def test_explains_legacy_first_variant_coverage_without_calling_it_reset(self):
        result = deltascope_scan_queue.project_scan_queue(self.queue(), current_variants=100)
        self.assertEqual("first-coverage", result["mode"])
        self.assertFalse(result["baselineSecurityRebuild"])
        self.assertIn("not a scan reset", result["headline"].lower())
        self.assertIn("legacy", result["explanation"].lower())
        self.assertEqual(2, result["counts"]["firstCoverage"])
        self.assertEqual(1, result["counts"]["firstCoverageRetry"])
        self.assertEqual(1, result["counts"]["coveredRefresh"])

    def test_legacy_exact_next_order_remains_compatible(self):
        result = deltascope_scan_queue.project_scan_queue(self.queue())
        self.assertEqual("coverage-first-v1", result["selectionPolicy"])
        self.assertTrue(result["selectionOrderExact"])
        self.assertEqual(["AlphaPlugin", "Zulu", "BetaRetry", "AlreadyCovered"], [row["internalName"] for row in result["nextItems"]])
        self.assertEqual("First variant coverage", result["nextItems"][0]["laneLabel"])

    def test_v2_shadow_selection_promotes_one_representative_per_plugin(self):
        items = [
            self.v2_item("p10-discovered", plugin_id=10, variant_id=11, source_class="discovered"),
            self.v2_item("p30-discovered", plugin_id=30, variant_id=30, source_class="discovered"),
            self.v2_item("p20-curated", plugin_id=20, variant_id=20, source_class="curated"),
            self.v2_item("p10-official", plugin_id=10, variant_id=10, source_class="official"),
        ]
        result = deltascope_scan_queue.project_scan_queue(self.v2_queue(items))
        self.assertEqual("first-plugin-coverage", result["mode"])
        self.assertEqual(
            ["p10-official", "p20-curated", "p30-discovered", "p10-discovered"],
            [row["queueKey"] for row in result["queueItems"]],
        )
        self.assertEqual([0, 0, 0, 2], [row["lane"] for row in result["queueItems"]])
        self.assertEqual("First plugin coverage", result["queueItems"][0]["laneLabel"])
        self.assertEqual("Secondary variant / covered refresh / follow-up", result["queueItems"][-1]["laneLabel"])

    def test_v2_existing_plugin_coverage_defers_secondary_variant(self):
        covered = self.v2_item("covered", plugin_id=1, variant_id=1, source_class="official", plugin_has_current=True)
        uncovered = self.v2_item("uncovered", plugin_id=2, variant_id=2, source_class="discovered")
        result = deltascope_scan_queue.project_scan_queue(self.v2_queue([covered, uncovered]))
        self.assertEqual(["uncovered", "covered"], [row["queueKey"] for row in result["queueItems"]])
        self.assertEqual([0, 2], [row["lane"] for row in result["queueItems"]])

    def test_v2_untouched_sibling_is_fallback_before_retry_for_same_uncovered_plugin(self):
        retry = self.v2_item("retry", plugin_id=7, variant_id=70, source_class="official", attempts=1)
        untouched = self.v2_item("untouched", plugin_id=7, variant_id=71, source_class="discovered")
        result = deltascope_scan_queue.project_scan_queue(self.v2_queue([retry, untouched]))
        self.assertEqual(["untouched", "retry"], [row["queueKey"] for row in result["queueItems"]])
        self.assertEqual([0, 2], [row["lane"] for row in result["queueItems"]])
        self.assertEqual(1, result["counts"]["unscannedRetryPlugins"])
        self.assertEqual(1, result["counts"]["unscannedRetryVariants"])

    def test_v2_source_preference_precedes_channel_nudge_and_priority(self):
        discovered = self.v2_item("discovered", plugin_id=1, variant_id=1, source_class="discovered", priority=1000, nudge=100)
        curated = self.v2_item("curated", plugin_id=2, variant_id=2, source_class="curated", priority=1000, nudge=100)
        official_testing = self.v2_item("official-testing", plugin_id=3, variant_id=3, source_class="official", channel="testing", priority=1000, nudge=100)
        official_stable = self.v2_item("official-stable", plugin_id=4, variant_id=4, source_class="official", channel="stable", priority=100, nudge=0)
        result = deltascope_scan_queue.project_scan_queue(self.v2_queue([discovered, curated, official_testing, official_stable]))
        self.assertEqual(
            ["official-stable", "official-testing", "curated", "discovered"],
            [row["queueKey"] for row in result["queueItems"]],
        )

    def test_v2_operator_nudge_precedes_normal_priority_then_scan_time_and_tiebreaks(self):
        nudge = self.v2_item("nudge", plugin_id=1, variant_id=8, source_class="official", priority=100, nudge=10, internal_name="Zulu")
        priority = self.v2_item("priority", plugin_id=2, variant_id=7, source_class="official", priority=999, nudge=0, internal_name="Zulu")
        old = self.v2_item("old", plugin_id=3, variant_id=6, source_class="official", priority=999, nudge=0, scanned_at="", internal_name="Alpha", source_name="B")
        newer = self.v2_item("newer", plugin_id=4, variant_id=5, source_class="official", priority=999, nudge=0, scanned_at="2026-01-01T00:00:00Z", internal_name="Alpha", source_name="A")
        result = deltascope_scan_queue.project_scan_queue(self.v2_queue([newer, priority, nudge, old]))
        self.assertEqual(["nudge", "old", "priority", "newer"], [row["queueKey"] for row in result["queueItems"]])

    def test_v2_deterministic_internal_source_variant_tiebreak(self):
        a2 = self.v2_item("a2", plugin_id=2, variant_id=20, source_class="official", internal_name="Alpha", source_name="Zed")
        a1 = self.v2_item("a1", plugin_id=1, variant_id=11, source_class="official", internal_name="Alpha", source_name="Able")
        a1b = self.v2_item("a1b", plugin_id=3, variant_id=10, source_class="official", internal_name="Alpha", source_name="Able")
        result = deltascope_scan_queue.project_scan_queue(self.v2_queue([a2, a1, a1b]))
        self.assertEqual(["a1b", "a1", "a2"], [row["queueKey"] for row in result["queueItems"]])

    def test_v2_exposes_plugin_and_retry_coverage_metrics(self):
        untouched = self.v2_item("p1-a", plugin_id=1, variant_id=11)
        sibling = self.v2_item("p1-b", plugin_id=1, variant_id=12)
        retry = self.v2_item("p2-r", plugin_id=2, variant_id=21, attempts=2)
        covered = self.v2_item("p3", plugin_id=3, variant_id=31, plugin_has_current=True)
        result = deltascope_scan_queue.project_scan_queue(self.v2_queue([untouched, sibling, retry, covered]))
        counts = result["counts"]
        self.assertEqual(2, counts["unscannedPluginsPending"])
        self.assertEqual(1, counts["unscannedRetryPlugins"])
        self.assertEqual(1, counts["unscannedRetryVariants"])
        self.assertEqual(4, counts["unscannedVariantsPending"])
        self.assertEqual("derived-read-only-projection", result["coverageMetricsSource"])

    def test_published_v2_metrics_are_exposed_without_reinterpreting_them(self):
        queue = self.v2_queue([self.v2_item("p1", plugin_id=1, variant_id=1)])
        result = deltascope_scan_queue.project_scan_queue(
            queue,
            published_summary={
                "selectionPolicy": "plugin-coverage-first-v2",
                "unscannedPluginsPending": 48,
                "unscannedRetryPlugins": 43,
                "unscannedRetryVariants": 71,
                "unscannedVariantsPending": 1780,
                "coveredWorkPending": 2885,
            },
        )
        self.assertEqual(48, result["counts"]["unscannedPluginsPending"])
        self.assertEqual(43, result["counts"]["unscannedRetryPlugins"])
        self.assertEqual(71, result["counts"]["unscannedRetryVariants"])
        self.assertEqual(1780, result["counts"]["unscannedVariantsPending"])
        self.assertEqual(2885, result["counts"]["coveredWorkPending"])
        self.assertEqual("published-queue-summary", result["coverageMetricsSource"])

    def test_analysis_observation_requested_is_typed_broker_work_not_stigma_or_artifact(self):
        queue = self.v2_queue([])
        queue["items"] = {
            "typed": {
                "queueKey": "typed", "variantId": 1, "pluginId": 1, "workType": "typed",
                "internalName": "Typed", "priority": 845, "state": "pending",
                "currentScanId": 9, "currentScannedAtUtc": "2026-09-01T00:00:00Z",
                "primaryReason": "analysis_observation_requested",
                "reasons": ["analysis_observation_requested"],
            },
            "deep": {
                "queueKey": "deep", "variantId": 2, "pluginId": 2, "workType": "typed",
                "internalName": "Deep", "priority": 840, "state": "pending",
                "currentScanId": 8, "currentScannedAtUtc": "2026-09-01T00:00:00Z",
                "primaryReason": "srl_observation_missing",
                "reasons": ["srl_observation_missing"],
            },
        }
        rows = {row["queueKey"]: row for row in deltascope_scan_queue.project_scan_queue(queue)["queueItems"]}
        self.assertEqual("Broker-requested typed analysis", rows["typed"]["operationalAction"])
        self.assertIsNone(rows["typed"]["requiresArtifactScan"])
        self.assertIn("analysis broker", rows["typed"]["operationalExplanation"].lower())
        self.assertNotEqual(rows["typed"]["operationalAction"], rows["deep"]["operationalAction"])
        self.assertIn("stigma-1", rows["deep"]["operationalExplanation"].lower())

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
                "queueKey": str(i), "variantId": i + 1, "pluginId": i + 1, "workType": "artifact",
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
            "deep": {"queueKey": "deep", "variantId": 1, "pluginId": 1, "workType": "artifact", "internalName": "Deep", "priority": 1000, "state": "pending", "currentScanId": 9, "currentScannedAtUtc": "2026-08-20T00:00:00Z", "primaryReason": "srl_observation_missing", "reasons": ["srl_observation_missing"]},
            "advisory": {"queueKey": "advisory", "variantId": 2, "pluginId": 2, "workType": "artifact", "internalName": "Advisory", "priority": 900, "state": "pending", "currentScanId": 8, "currentScannedAtUtc": "2026-08-20T00:00:00Z", "primaryReason": "advisory_changed", "reasons": ["advisory_changed"]},
            "source": {"queueKey": "source", "variantId": 3, "pluginId": 3, "workType": "source", "internalName": "Source", "priority": 800, "state": "pending", "currentScanId": 7, "currentScannedAtUtc": "2026-08-20T00:00:00Z", "primaryReason": "source_followup", "reasons": ["source_followup"]},
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

    def test_consumer_does_not_import_sigmascope_production_policy_module(self):
        source = Path(deltascope_scan_queue.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import plugin_coverage_policy", source)
        self.assertNotIn("from plugin_coverage_policy", source)

    def test_queue_v2_ui_shim_uses_plugin_language_and_typed_filter(self):
        source = deltascope_scan_queue._QUEUE_UI_SCRIPT
        self.assertIn("plugin-coverage-first-v2", source)
        self.assertIn("First plugin coverage", source)
        self.assertIn("unscannedPluginsPending", source)
        self.assertIn("unscannedRetryPlugins", source)
        self.assertIn("unscannedRetryVariants", source)
        self.assertIn("Broker-requested typed analysis", source)
        self.assertIn("analysis_observation_requested", source)

    def test_queue_v2_ui_install_is_bounded_and_idempotent(self):
        import sys
        import types
        original = sys.modules.get("developer_view")
        fake = types.SimpleNamespace(HTML="<html><body>queue</body></html>")
        sys.modules["developer_view"] = fake
        previous = deltascope_scan_queue._INSTALLED
        try:
            deltascope_scan_queue._INSTALLED = False
            deltascope_scan_queue.install()
            deltascope_scan_queue.install()
            self.assertEqual(1, fake.HTML.count("deltascope-plugin-first-queue-ui"))
        finally:
            deltascope_scan_queue._INSTALLED = previous
            if original is None:
                sys.modules.pop("developer_view", None)
            else:
                sys.modules["developer_view"] = original

    def test_launcher_installs_queue_v2_ui_after_developer_view_import(self):
        launcher = (ROOT / "deltascope.py").read_text(encoding="utf-8")
        self.assertIn("import deltascope_scan_queue", launcher)
        self.assertIn("deltascope_scan_queue.install()", launcher)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / "tools" / "security", ROOT / "tools" / "catalog", ROOT / "tools" / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import analysis_broker
import observation_inventory
import rule_reprojection
import stigma_broker_bridge
from test_rule_reprojection import RuleReprojectionTests


class StigmaBrokerBridgeTests(unittest.TestCase):
    def helper(self) -> RuleReprojectionTests:
        return RuleReprojectionTests("test_compatible_retained_observations_reproject_without_legacy_findings")

    def test_missing_retained_collection_becomes_one_idempotent_sigmascope_work_item(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-stigma-broker-gap-") as td:
            root = Path(td)
            helper = self.helper()
            evidence = helper.evidence(root, include_static_observations=False)
            plan = rule_reprojection.plan_reprojection(evidence, helper.compiled())
            self.assertEqual(["staticPatternMatches"], plan["reanalysisRequests"][0]["missingCollections"])
            projection = root / "projection"
            rule_reprojection.materialize_projection_set(projection, plan)
            inventory = observation_inventory.build_inventory(evidence, generated_at="2026-08-24T20:00:00Z")
            state = analysis_broker.empty_state(now="2026-08-24T20:00:00Z")
            updated, report = stigma_broker_bridge.reconcile(
                state, projection_root=projection, evidence_root=evidence, inventory=inventory,
                now="2026-08-24T20:00:00Z",
            )
            self.assertEqual(1, report["candidateRequests"])
            self.assertEqual(1, report["enqueued"])
            self.assertEqual(1, len(updated["items"]))
            item = updated["items"][0]
            self.assertEqual("staticPatternMatches", item["observation"])
            self.assertEqual("omega.sigmascope", item["componentId"])
            self.assertEqual("queued", item["state"])

            updated_again, report_again = stigma_broker_bridge.reconcile(
                updated, projection_root=projection, evidence_root=evidence, inventory=inventory,
                now="2026-08-24T20:05:00Z",
            )
            self.assertEqual(1, len(updated_again["items"]))
            self.assertEqual(0, report_again["enqueued"])
            self.assertEqual(1, report_again["deduplicated"])
            self.assertEqual(item["workItemId"], updated_again["items"][0]["workItemId"])

    def test_observation_request_sidecar_is_bridged_with_stable_rule_bound_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-stigma-broker-observation-") as td:
            root = Path(td)
            helper = self.helper()
            evidence = helper.evidence(root)
            import srl
            compiled = srl.compile_ruleset({
                "schema": "omega.sigmascope.ruleset.v1",
                "rules": [{
                    "schema": "omega.sigmascope.rule.v1",
                    "id": "fixture.signature.followup",
                    "kind": "observation",
                    "status": "reviewed",
                    "requires": ["staticPatternMatches"],
                    "selectors": {
                        "process": {
                            "collection": "staticPatternMatches",
                            "where": {"pattern": {"equals": "Process.Start"}},
                        }
                    },
                    "condition": "process",
                    "emit": {"fact": "fixture.process-observed", "title": "Process capability observed", "confidence": "high"},
                    "observationRequest": {
                        "collection": "binarySignatureTrust",
                        "reason": "Collect signature trust evidence for this exact artifact.",
                        "priority": 880,
                    },
                }],
            })
            plan = rule_reprojection.plan_reprojection(evidence, compiled)
            self.assertEqual(1, len(plan["observationRequests"]))
            projection = root / "projection"
            index = rule_reprojection.materialize_projection_set(projection, plan)
            self.assertEqual(1, index["observationRequests"]["records"])
            self.assertTrue(rule_reprojection.verify_projection_set(projection)["ok"])

            state = analysis_broker.empty_state(now="2026-08-24T20:00:00Z")
            inventory = observation_inventory.build_inventory(evidence, generated_at="2026-08-24T20:00:00Z")
            updated, report = stigma_broker_bridge.reconcile(
                state, projection_root=projection, evidence_root=evidence, inventory=inventory,
                now="2026-08-24T20:00:00Z",
            )
            self.assertEqual(1, report["candidateRequests"])
            item = updated["items"][0]
            self.assertEqual("binarySignatureTrust", item["observation"])
            self.assertEqual("omega.sigmascope", item["componentId"])
            self.assertEqual("queued", item["state"])
            first_request = item["requestId"]
            updated_again, _ = stigma_broker_bridge.reconcile(
                updated, projection_root=projection, evidence_root=evidence, inventory=inventory,
                now="2026-08-24T20:30:00Z",
            )
            self.assertEqual(1, len(updated_again["items"]))
            self.assertEqual(first_request, updated_again["items"][0]["requestId"])


if __name__ == "__main__":
    unittest.main()

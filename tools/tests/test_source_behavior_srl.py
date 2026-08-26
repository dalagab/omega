from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import observation_projection
import rule_author_reference
import srl


class SourceBehaviorSRLTests(unittest.TestCase):
    def test_source_behavior_collections_are_raw_srl_inputs(self) -> None:
        expected = {
            "sourceOperations",
            "sourceFlowEdges",
            "sourceTriggers",
            "sourceConditions",
            "sourceDataFlow",
        }
        for name in expected:
            self.assertIn(name, observation_projection.COLLECTIONS)
            self.assertTrue(observation_projection.COLLECTIONS[name]["srlEligible"])
            self.assertEqual("source-behavior-observation", observation_projection.COLLECTIONS[name]["semanticClass"])
            self.assertIn(name, rule_author_reference.COLLECTIONS)


    def test_report_projection_exports_source_behavior_and_empty_contracts(self) -> None:
        report = {
            "source": {
                "dependencyIntelligence": {
                    "sourceBehavior": {
                        "contractVersion": 1,
                        "operations": [{"operation": "network.http.request", "serviceCapabilities": ["ffxiv.market-data"]}],
                        "flowEdges": [],
                        "triggers": [],
                        "conditions": [],
                        "dataFlow": [],
                    }
                }
            }
        }
        rows = observation_projection.report_observation_rows(report)
        self.assertEqual(1, len(rows["sourceOperations"]))
        self.assertEqual([], rows["sourceTriggers"])
        self.assertTrue(observation_projection.report_collection_complete(report, "sourceTriggers"))
        self.assertTrue(observation_projection.report_collection_complete(report, "sourceDataFlow"))

    def test_endpoint_reference_exposes_service_registry_fields(self) -> None:
        fields = rule_author_reference.COLLECTIONS["networkEndpoints"]["fields"]
        for field in (
            "serviceId",
            "serviceName",
            "serviceRecognition",
            "serviceCategories",
            "serviceCapabilities",
        ):
            self.assertIn(field, fields)

    def test_shipped_behavior_rules_compile_and_reason_over_raw_observations(self) -> None:
        rules = srl.compile_file(
            ROOT
            / "security-definitions"
            / "packs"
            / "omega-experimental-source-behavior"
            / "rules"
            / "source-behavior.yaml"
        )
        result = srl.evaluate_ruleset(
            rules,
            {
                "sourceOperations": [
                    {
                        "operation": "network.http.request",
                        "serviceCapabilities": ["ffxiv.market-data"],
                    }
                ],
                "sourceDataFlow": [
                    {
                        "relation": "value-used-by",
                        "fromServiceCapabilities": ["ffxiv.market-data"],
                        "toOperation": "game.marketboard.purchase",
                    }
                ],
                "sourceFlowEdges": [
                    {
                        "fromOperation": "game.character.move",
                        "toOperation": "game.marketboard.purchase",
                        "minimumDelayMs": 0,
                    },
                    {
                        "fromOperation": "time.delay",
                        "toOperation": "game.marketboard.purchase",
                        "minimumDelayMs": 500,
                    },
                ],
            },
        )
        self.assertTrue(result["evaluated"], result.get("replayAudit"))
        self.assertIn("behavior.market-data.retrieve", result["facts"])
        self.assertIn("behavior.marketboard.external-data-driven-purchase", result["facts"])
        self.assertIn("behavior.marketboard.navigation-before-purchase", result["facts"])
        self.assertIn("behavior.marketboard.delayed-purchase", result["facts"])


if __name__ == "__main__":
    unittest.main()

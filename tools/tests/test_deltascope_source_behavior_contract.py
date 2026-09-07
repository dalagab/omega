from __future__ import annotations

import unittest

from deltascope_sdk import observation_projection, rule_author_reference, srl


SOURCE_BEHAVIOR_COLLECTIONS = {
    "sourceOperations",
    "sourceFlowEdges",
    "sourceTriggers",
    "sourceConditions",
    "sourceDataFlow",
}


class DeltaScopeSourceBehaviorContractTests(unittest.TestCase):
    def test_source_behavior_collections_are_typed_srl_inputs(self) -> None:
        for name in sorted(SOURCE_BEHAVIOR_COLLECTIONS):
            self.assertIn(name, observation_projection.COLLECTIONS)
            self.assertTrue(observation_projection.COLLECTIONS[name]["srlEligible"])
            self.assertIn(name, rule_author_reference.COLLECTIONS)
            self.assertIn(name, srl.FIELD_REGISTRY)

    def test_published_source_operations_selector_compiles(self) -> None:
        document = {
            "schema": "omega.sigmascope.ruleset.v1",
            "rules": [{
                "schema": "omega.sigmascope.rule.v1",
                "id": "source-behavior.market-data-request",
                "kind": "observation",
                "status": "experimental",
                "requires": ["sourceOperations"],
                "selectors": {
                    "request": {
                        "collection": "sourceOperations",
                        "where": {
                            "operation": {"equals-ci": "network.http.request"},
                            "serviceCapabilities": {"contains-ci": "ffxiv.market-data"},
                        },
                    }
                },
                "condition": "request",
                "emit": {
                    "fact": "behavior.market-data.retrieve",
                    "confidence": "high",
                    "title": "FFXIV market data retrieval path observed",
                    "description": "Source contains a concrete HTTP operation tied to a registered service.",
                    "category": "source-behavior",
                },
            }],
        }
        compiled = srl.compile_ruleset(document)
        selector = compiled["rules"][0]["selectors"][0]
        self.assertEqual("sourceOperations", selector["collection"])
        self.assertEqual(
            {"operation", "serviceCapabilities"},
            {row["field"] for row in selector["predicates"]},
        )

    def test_flow_and_dataflow_collections_compile(self) -> None:
        for collection, fields in (
            ("sourceFlowEdges", {
                "relation": {"equals-ci": "triggers"},
                "toOperation": {"equals-ci": "game.marketboard.purchase"},
            }),
            ("sourceDataFlow", {
                "relation": {"equals-ci": "value-used-by"},
                "fromServiceCapabilities": {"contains-ci": "ffxiv.market-data"},
            }),
        ):
            rule = {
                "schema": "omega.sigmascope.rule.v1",
                "id": f"compat.{collection}",
                "kind": "observation",
                "status": "experimental",
                "requires": [collection],
                "selectors": {"source": {"collection": collection, "where": fields}},
                "condition": "source",
                "emit": {
                    "fact": f"compat.{collection}.fact",
                    "confidence": "high",
                    "title": "compatibility",
                    "description": "compatibility",
                    "category": "source-behavior",
                },
            }
            compiled = srl.compile_rule(rule)
            self.assertEqual(collection, compiled["selectors"][0]["collection"])

    def test_report_projection_retains_source_behavior_rows_and_empty_completeness(self) -> None:
        report = {
            "source": {
                "dependencyIntelligence": {
                    "sourceBehavior": {
                        "contractVersion": 1,
                        "operations": [{"operationId": "op-1", "operation": "network.http.request"}],
                        "flowEdges": [{"edgeId": "edge-1", "relation": "triggers"}],
                        "triggers": [],
                        "conditions": [],
                        "dataFlow": [{"edgeId": "df-1", "relation": "value-used-by"}],
                    }
                }
            }
        }
        rows = observation_projection.report_observation_rows(report)
        self.assertEqual("op-1", rows["sourceOperations"][0]["operationId"])
        self.assertEqual("edge-1", rows["sourceFlowEdges"][0]["edgeId"])
        self.assertEqual("df-1", rows["sourceDataFlow"][0]["edgeId"])
        for name in sorted(SOURCE_BEHAVIOR_COLLECTIONS):
            self.assertTrue(observation_projection.report_collection_complete(report, name))


if __name__ == "__main__":
    unittest.main()

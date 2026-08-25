from __future__ import annotations

import copy
import json
import threading
import unittest
import urllib.request

import deltascope_finding_lineage as lineage
import developer_view
from deltascope_sdk import srl


RULES = """
schema: omega.sigmascope.ruleset.v1
rules:
  - schema: omega.sigmascope.rule.v1
    id: process.observed
    kind: observation
    status: reviewed
    requires: [staticPatternMatches]
    selectors:
      process:
        collection: staticPatternMatches
        where:
          pattern: {equals-ci: Process.Start}
    condition: process
    emit:
      fact: behavior.process-start
  - schema: omega.sigmascope.rule.v1
    id: process.review
    kind: correlation
    status: reviewed
    requires: []
    selectors:
      process_fact:
        facts:
          any: [behavior.process-start]
    condition: process_fact
    emit:
      findingId: process.review.finding
      title: Process behavior requires review
      description: Fixture correlation.
      severity: caution
      category: process
"""


class DeltaScopeFindingLineageTests(unittest.TestCase):
    def detail(self):
        return {
            "identity": {
                "plugin_id": 1,
                "variant_id": 10,
                "scan_id": 20,
                "canonical_name": "Example Plugin",
                "internal_name": "Example.Plugin",
                "assembly_version": "1.2.3",
                "artifact_sha256": "a" * 64,
                "scanner_version": "2.15.0",
                "scanned_at_utc": "2026-08-24T08:00:00Z",
            },
            "observations": {
                "schema": "omega.sigmascope.observation-contract.v1",
                "collections": {
                    "staticPatternMatches": {
                        "records": 1,
                        "recordDigest": "d" * 64,
                        "backingDataset": "staticPatternMatches",
                        "collectionSchema": "omega.sigmascope.observation.static-pattern-matches.v1",
                        "completeness": "retained",
                    }
                },
            },
            "researcher": {
                "findings": [{
                    "ruleId": "process.review",
                    "findingId": "process.review.finding",
                    "title": "Process behavior requires review",
                    "description": "Fixture correlation.",
                    "severity": "caution",
                    "category": "process",
                    "evidence": [],
                }]
            },
        }

    def provenance(self):
        compiled = srl.compile_yaml_text(RULES)
        rows = [{**dict(rule), "ruleId": rule["id"], "packId": "fixture"} for rule in compiled["rules"]]
        return {
            "readOnly": True,
            "mutationAuthority": "none",
            "definitions": {"definitionsRevision": "defs-fixture"},
            "srl": {"ruleSetRevision": compiled["ruleSetRevision"]},
            "activeRules": rows,
        }

    def test_stigma_lineage_replays_fact_chain_from_retained_rows(self):
        observations = {
            "staticPatternMatches": [{
                "origin": "artifact",
                "pattern": "Process.Start",
                "evidenceLabel": "metadata:Plugin.dll",
                "evidence": ["metadata:Plugin.dll: Process.Start"],
            }]
        }
        result = lineage.project_finding_lineage(
            self.detail(), observations, self.provenance(), {}, finding_id="process.review.finding"
        )
        self.assertEqual(lineage.SCHEMA, result["schema"])
        self.assertTrue(result["readOnly"])
        self.assertEqual("none", result["mutationAuthority"])
        self.assertFalse(result["policyInput"])
        self.assertTrue(result["currentVersionOnly"])
        self.assertEqual("stigma-1", result["origin"])
        self.assertTrue(result["exactReplay"])
        kinds = {node["kind"] for node in result["graph"]["nodes"]}
        self.assertTrue({"collector", "collection", "observation-row", "selector", "fact", "stigma-rule", "finding", "published-evidence"}.issubset(kinds))
        relationships = {edge["relationship"] for edge in result["graph"]["edges"]}
        self.assertIn("matches-selector", relationships)
        self.assertIn("emits-fact", relationships)
        self.assertIn("emits-finding", relationships)
        self.assertIn("published-as-current-evidence", relationships)

    def test_stigma_lineage_refuses_exact_replay_when_collection_preview_is_bounded(self):
        detail = self.detail()
        detail["observations"]["collections"]["staticPatternMatches"]["completeness"] = "bounded-transport"
        result = lineage.project_finding_lineage(
            detail,
            {"staticPatternMatches": [{"pattern": "Process.Start"}]},
            self.provenance(),
            {},
            finding_id="process.review.finding",
        )
        self.assertFalse(result["exactReplay"])
        self.assertIn("bounded", result["replayReason"].casefold())

    def test_static_endpoint_finding_links_endpoint_collection_without_inventing_reputation(self):
        detail = self.detail()
        detail["researcher"]["findings"] = [{
            "ruleId": "network.endpoint.unrecognised-host.123",
            "findingId": "network.endpoint.unrecognised-host.123",
            "title": "Endpoint: api.unknown.test",
            "description": "Static literal only.",
            "severity": "caution",
            "category": "network-endpoint",
            "evidence": ["artifact:plugin.json: https://api.unknown.test/v1"],
        }]
        result = lineage.project_finding_lineage(
            detail,
            {"networkEndpoints": [{"host": "api.unknown.test", "classification": "unrecognised-host"}]},
            {"activeRules": []},
            {},
            rule_id="network.endpoint.unrecognised-host.123",
        )
        self.assertEqual("sigmascope-static", result["origin"])
        self.assertFalse(result["exactReplay"])
        self.assertIn("networkEndpoints", result["collections"])
        self.assertNotIn("reputation", result["collections"])
        self.assertTrue(any(node["kind"] == "static-rule" for node in result["graph"]["nodes"]))

    def test_projection_is_deterministic_for_observation_mapping_order(self):
        detail = self.detail()
        provenance = self.provenance()
        a = lineage.project_finding_lineage(detail, {"staticPatternMatches": [{"pattern": "Process.Start"}], "networkEndpoints": []}, provenance, {})
        b = lineage.project_finding_lineage(copy.deepcopy(detail), {"networkEndpoints": [], "staticPatternMatches": [{"pattern": "Process.Start"}]}, provenance, {})
        self.assertEqual(a["lineageProjectionId"], b["lineageProjectionId"])

    def test_http_finding_lineage_endpoint_is_read_only_and_uses_current_variant_context(self):
        owner = self

        class FakeInspector:
            def plugin_detail(self, variant_id):
                self.last_detail = variant_id
                return owner.detail()

            def workbench_observation_rows(self, variant_id, per_collection_limit=2500):
                self.last_observation = (variant_id, per_collection_limit)
                return {
                    "staticPatternMatches": [{
                        "origin": "artifact", "pattern": "Process.Start",
                        "evidenceLabel": "metadata:Example.Plugin.dll", "evidence": "Process.Start",
                    }]
                }

            def definition_provenance(self):
                return owner.provenance()

            def srl_projection_state(self, variant_id):
                self.last_projection = variant_id
                return {"available": False, "productionWriteBack": False}

        inspector = FakeInspector()
        handler = type("TestFindingLineageHandler", (developer_view.AppHandler,), {"inspector": inspector})
        server = developer_view.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{server.server_address[1]}/api/workbench/finding-lineage?variant_id=10&finding_id=process.review.finding",
                timeout=5,
            ) as response:
                payload = json.load(response)
            self.assertEqual(lineage.SCHEMA, payload["schema"])
            self.assertTrue(payload["readOnly"])
            self.assertEqual("none", payload["mutationAuthority"])
            self.assertTrue(payload["currentVersionOnly"])
            self.assertEqual("stigma-1", payload["origin"])
            self.assertEqual(10, inspector.last_detail)
            self.assertEqual((10, 2500), inspector.last_observation)
            self.assertEqual(10, inspector.last_projection)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

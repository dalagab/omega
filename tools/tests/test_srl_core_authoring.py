from __future__ import annotations

import json
import tempfile
import threading
import urllib.request
from pathlib import Path
import unittest

import sys

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import srl
import stigma1
import rule_lab
import deltascope_rule_store
import developer_view


RULE = """schema: omega.sigmascope.rule.v1
id: local.graph-demo
kind: observation
status: experimental
requires: [staticPatternMatches]
selectors:
  marker:
    collection: staticPatternMatches
    where:
      pattern:
        starts-with-ci: http
condition:
  all:
    - marker
emit:
  fact: local.graph.demo
  confidence: medium
  title: Graph demo
"""

CORRELATION = """schema: omega.sigmascope.rule.v1
id: local.correlation-demo
kind: correlation
status: experimental
requires: []
selectors:
  network:
    facts:
      any: [primitive.network.http, primitive.network.socket]
  execution:
    facts:
      all: [primitive.process.launch]
condition:
  all:
    - network
    - not: execution
emit:
  findingId: local.correlation-demo.finding
  title: Correlation demo
  description: Visual graph round trip
  severity: caution
  category: experimental
"""

DEEP_REQUEST_RULE = CORRELATION + """analysisRequest:
  profile: artifact-differential-v1
  compareWith: stable-artifact-baseline
  reason: Compare candidate and stable baseline.
"""


class SRLCoreAuthoringTests(unittest.TestCase):
    def test_rule_round_trips_through_authoring_graph(self) -> None:
        graph = srl.yaml_text_to_authoring_graph(RULE)
        self.assertEqual(srl.GRAPH_SCHEMA, graph["schema"])
        self.assertTrue(graph["readOnlyExecutionModel"])
        self.assertEqual({"collection-selector", "logic", "emit"}, {n["type"] for n in graph["nodes"]})
        rendered = srl.authoring_graph_to_yaml(graph)
        compiled = srl.compile_yaml_text(rendered)
        self.assertEqual(["local.graph-demo"], [r["id"] for r in compiled["rules"]])
        self.assertEqual("local.graph.demo", compiled["rules"][0]["emit"]["fact"])

    def test_correlation_graph_preserves_logic_and_fact_selectors(self) -> None:
        graph = srl.yaml_text_to_authoring_graph(CORRELATION)
        types = [n["type"] for n in graph["nodes"]]
        self.assertEqual(2, types.count("fact-selector"))
        self.assertGreaterEqual(types.count("logic"), 2)
        rendered = srl.authoring_graph_to_yaml(graph)
        parsed = srl.parse_yaml_text(rendered)
        self.assertEqual({"all": ["network", {"not": "execution"}]}, parsed["condition"])


    def test_visual_graph_preserves_deep_analysis_outcome(self) -> None:
        graph = srl.yaml_text_to_authoring_graph(DEEP_REQUEST_RULE)
        emit = next(node for node in graph["nodes"] if node["type"] == "emit")
        self.assertEqual("artifact-differential-v1", emit["config"]["analysisRequest"]["profile"])
        rebuilt = srl.parse_yaml_text(srl.authoring_graph_to_yaml(graph))
        self.assertEqual("stable-artifact-baseline", rebuilt["analysisRequest"]["compareWith"])
        self.assertIn("visualDeepProfile", developer_view.HTML)
        self.assertIn("Local rules only preview the queue request", developer_view.HTML)

    def test_visual_graph_rejects_missing_emit_connection(self) -> None:
        graph = srl.yaml_text_to_authoring_graph(RULE)
        graph["edges"] = [e for e in graph["edges"] if e["to"] != "emit:result"]
        with self.assertRaisesRegex(srl.SRLCompileError, "emit node requires exactly one condition input"):
            srl.authoring_graph_to_yaml(graph)

    def test_rule_lab_visual_bridge_uses_srl_core(self) -> None:
        visual = rule_lab.visual_graph_from_yaml(RULE)
        self.assertTrue(visual["ok"])
        rebuilt = rule_lab.yaml_from_visual_graph(visual["graph"])
        self.assertTrue(rebuilt["ok"])
        self.assertIn("local.graph-demo", rebuilt["yaml"])
        ref = rule_lab.reference()
        self.assertEqual("Stigma-1", ref["stigma1"]["component"])
        self.assertEqual("SRL Core", ref["stigma1"]["technicalName"])
        self.assertEqual("Stigma-1", ref["srlCore"]["component"])
        self.assertTrue(ref["srlCore"]["compatibilityAlias"])

    def test_stigma1_is_the_canonical_srl_core_facade(self) -> None:
        self.assertEqual("Stigma-1", stigma1.STIGMA_NAME)
        self.assertEqual("SRL Core", stigma1.STIGMA_TECHNICAL_NAME)
        self.assertEqual("omega.stigma-1", stigma1.STIGMA_COMPONENT_ID)
        engine = stigma1.engine_reference()
        self.assertEqual("Stigma-1", engine["component"])
        self.assertEqual("SRL Core", engine["technicalName"])
        self.assertEqual(srl.compile_yaml_text(RULE), stigma1.compile_yaml_text(RULE))

    def test_local_store_versions_validated_rules_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = deltascope_rule_store.LocalRuleStore(Path(td) / "rules-v1")
            first = store.save_rule(RULE)
            self.assertTrue(first["saved"])
            self.assertEqual(1, first["revision"])
            second = store.save_rule(RULE, expected_rule_id="local.graph-demo")
            self.assertFalse(second["saved"])
            self.assertTrue(second["unchanged"])
            changed = RULE.replace("Graph demo", "Graph demo changed")
            third = store.save_rule(changed, expected_rule_id="local.graph-demo")
            self.assertEqual(2, third["revision"])
            loaded = store.get_rule("local.graph-demo")
            self.assertEqual(2, loaded["metadata"]["revision"])
            self.assertEqual(2, len(loaded["revisions"]))
            self.assertEqual(1, store.list_rules()["ruleCount"])
            self.assertTrue((Path(td) / "rules-v1").exists())

    def test_local_store_rejects_id_change_when_editing_selected_rule(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = deltascope_rule_store.LocalRuleStore(Path(td))
            store.save_rule(RULE)
            changed_id = RULE.replace("local.graph-demo", "local.other", 1)
            with self.assertRaisesRegex(ValueError, "differs from the selected local rule"):
                store.save_rule(changed_id, expected_rule_id="local.graph-demo")


    def test_http_local_store_and_visual_endpoints_are_non_production(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = deltascope_rule_store.LocalRuleStore(Path(td) / "rules")
            class FakeInspector:
                evidence_path = Path(td) / "evidence"
            handler = type("TestRuleWorkspaceHandler", (developer_view.AppHandler,), {"inspector": FakeInspector(), "rule_store": store})
            server = developer_view.ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                req = urllib.request.Request(base + "/api/rule-lab/local/save", data=json.dumps({"yaml": RULE}).encode(), headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=5) as response:
                    saved = json.load(response)
                self.assertTrue(saved["saved"])
                with urllib.request.urlopen(base + "/api/rule-lab/local?rule_id=local.graph-demo", timeout=5) as response:
                    loaded = json.load(response)
                self.assertEqual("local.graph-demo", loaded["ruleId"])
                req = urllib.request.Request(base + "/api/rule-lab/graph", data=json.dumps({"yaml": RULE}).encode(), headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=5) as response:
                    graph = json.load(response)
                self.assertTrue(graph["ok"])
                req = urllib.request.Request(base + "/api/rule-lab/graph-yaml", data=json.dumps({"graph": graph["graph"]}).encode(), headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=5) as response:
                    rebuilt = json.load(response)
                self.assertTrue(rebuilt["ok"])
                self.assertFalse(rebuilt["productionWriteBack"])
            finally:
                server.shutdown()
                server.server_close()

    def test_fork_creates_independent_local_rule(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = deltascope_rule_store.LocalRuleStore(Path(td))
            forked = store.fork_rule(RULE, new_rule_id="local.forked")
            self.assertEqual("local.forked", forked["ruleId"])
            loaded = store.get_rule("local.forked")
            self.assertIn("id: local.forked", loaded["yaml"])
            self.assertEqual("experimental", loaded["rule"]["status"])


if __name__ == "__main__":
    unittest.main()

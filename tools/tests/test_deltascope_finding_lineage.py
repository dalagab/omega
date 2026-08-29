from __future__ import annotations

import copy
import json
import threading
import unittest
import urllib.request

import deltascope_finding_lineage as lineage
import developer_view
import evidence_v2_inspector
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


    def test_narrative_promotes_matched_rows_rule_trace_severity_and_provenance(self):
        observations = {
            "staticPatternMatches": [{
                "origin": "artifact",
                "pattern": "Process.Start",
                "evidenceLabel": "metadata:Plugin.dll",
                "evidence": ["metadata:Plugin.dll: Process.Start"],
            }]
        }
        result = lineage.project_finding_lineage(
            self.detail(), observations, self.provenance(), {},
            {
                "generatedAtUtc": "2026-08-24T09:00:00Z",
                "source": {"artifactAnalysisRevision": "artifact-analysis-v3-073"},
                "evidence": {"revisions": {"securityRevision": "security-revision-1"}},
            },
            finding_id="process.review.finding",
        )
        narrative = result["narrative"]
        self.assertEqual("omega.deltascope.finding-lineage-narrative.v1", narrative["schema"])
        triggering = narrative["whatWasFound"]["triggeringEvidence"]
        self.assertEqual(1, len(triggering))
        self.assertEqual("staticPatternMatches", triggering[0]["collection"])
        self.assertEqual("metadata:Plugin.dll", triggering[0]["label"])
        trace = narrative["whyItWasFound"]
        self.assertEqual("process.review", trace["ruleId"])
        self.assertTrue(any(row["ruleId"] == "process.observed" and row["matched"] for row in trace["conditions"]))
        self.assertTrue(any(row["ruleId"] == "process.review" and row["matched"] for row in trace["conditions"]))
        severity = narrative["whyThisSeverity"]
        self.assertTrue(severity["directRuleSeverity"])
        self.assertEqual("caution", severity["ruleSeverity"])
        self.assertIn("fixed caution", severity["whyNotHigher"])
        steps = {row["step"]: row for row in narrative["provenance"]}
        self.assertEqual("artifact-analysis-v3-073", steps["Collection"]["version"])
        self.assertEqual("security-revision-1", steps["Publication"]["version"])
        self.assertIn("Process.Start", narrative["developerExplanation"])

    def test_static_supporting_rule_maps_specific_evidence_and_keeps_zero_native_imports_as_context(self):
        rules = """
schema: omega.sigmascope.ruleset.v1
rules:
  - schema: omega.sigmascope.rule.v1
    id: primitive.game.hooking
    kind: observation
    status: reviewed
    requires: [staticPatternMatches]
    selectors:
      marker:
        collection: staticPatternMatches
        where:
          pattern:
            in-ci: [Dalamud.Hooking, HookFromAddress]
    condition: marker
    emit:
      fact: game.hooking
      confidence: high
      title: Game hooking/signature static marker observed
      description: Retained static markers reference Dalamud hooking APIs.
      category: game-memory
"""
        compiled = srl.compile_yaml_text(rules)
        provenance = {
            "definitions": {"definitionsRevision": "defs-hooking"},
            "srl": {"ruleSetRevision": compiled["ruleSetRevision"]},
            "activeRules": [{**dict(rule), "ruleId": rule["id"], "packId": "core-static"} for rule in compiled["rules"]],
        }
        detail = self.detail()
        detail["observations"]["collections"] = {
            "staticPatternMatches": {"records": 2, "completeness": "retained", "recordDigest": "a" * 64},
            "managedCallSites": {"records": 1, "completeness": "retained", "recordDigest": "b" * 64},
            "nativeImports": {"records": 0, "completeness": "retained", "recordDigest": "c" * 64},
        }
        detail["researcher"]["findings"] = [{
            "ruleId": "game.hooking",
            "findingId": "game.hooking",
            "title": "Game hooking APIs observed",
            "description": "Hooking behavior requires review.",
            "severity": "caution",
            "category": "game-memory",
            "evidence": [
                "metadata:KamiToolKit.dll:Dalamud.Hooking",
                "metadata:KamiToolKit.dll:HookFromAddress",
                "il:KamiToolKit.dll:KamiToolKit.NativeAddon.InitializeCloseCallback+0x2b",
            ],
        }]
        observations = {
            "staticPatternMatches": [
                {"origin": "artifact", "path": "KamiToolKit.dll", "pattern": "Dalamud.Hooking", "evidenceLabel": "metadata:KamiToolKit.dll:Dalamud.Hooking"},
                {"origin": "artifact", "path": "KamiToolKit.dll", "pattern": "HookFromAddress", "evidenceLabel": "metadata:KamiToolKit.dll:HookFromAddress"},
            ],
            "managedCallSites": [{
                "origin": "artifact", "path": "KamiToolKit.dll",
                "sourceDeclaringType": "KamiToolKit.NativeAddon", "sourceMethodName": "InitializeCloseCallback", "ilOffset": 43,
                "targetDeclaringType": "Dalamud.Plugin.Services.IGameInteropProvider", "targetName": "HookEx",
            }],
            "nativeImports": [],
        }
        result = lineage.project_finding_lineage(detail, observations, provenance, {}, rule_id="game.hooking")
        self.assertEqual("sigmascope-static", result["origin"])
        narrative = result["narrative"]
        trace = narrative["whyItWasFound"]
        self.assertEqual("primitive.game.hooking", trace["ruleId"])
        self.assertIn("supporting frozen rule", trace["relationship"])
        triggering = narrative["whatWasFound"]["triggeringEvidence"]
        labels = {row["label"] for row in triggering}
        self.assertIn("metadata:KamiToolKit.dll:Dalamud.Hooking", labels)
        self.assertIn("metadata:KamiToolKit.dll:HookFromAddress", labels)
        self.assertIn("KamiToolKit.NativeAddon.InitializeCloseCallback+0x2b", labels)
        native = next(row for row in narrative["whyThisSeverity"]["counterEvidence"] if row["label"] == "nativeImports")
        self.assertEqual("0 retained rows", native["observed"])
        self.assertFalse(native["causedSeverity"])
        self.assertIn("does not declare this collection as a severity modifier", native["explanation"])
        self.assertIn("cannot attribute", narrative["whyThisSeverity"]["explanation"])

    def test_rule_fanout_is_explicit_bounded_and_aggregates_evidence_patterns(self):
        inspector = evidence_v2_inspector.V2SigmascopeInspector.__new__(evidence_v2_inspector.V2SigmascopeInspector)
        inspector.current_entries = {
            10: {"scanId": 100, "summary": {"scanned_at_utc": "2026-08-24T08:00:00Z", "caution_count": 1}},
            11: {"scanId": 101, "summary": {"scanned_at_utc": "2026-08-24T09:00:00Z", "caution_count": 1}},
        }
        payloads = {
            10: {
                "plugin": {"canonical_name": "One", "internal_name": "One"}, "variant": {"assembly_version": "1.0"},
                "current": {"scan_id": 100, "scanned_at_utc": "2026-08-24T08:00:00Z", "findings_json": [{
                    "ruleId": "game.hooking", "findingId": "game.hooking", "title": "Hooking", "severity": "caution",
                    "evidence": ["metadata:KamiToolKit.dll:Dalamud.Hooking"],
                }]},
            },
            11: {
                "plugin": {"canonical_name": "Two", "internal_name": "Two"}, "variant": {"assembly_version": "2.0"},
                "current": {"scan_id": 101, "scanned_at_utc": "2026-08-24T09:00:00Z", "findings_json": [{
                    "ruleId": "game.hooking", "findingId": "game.hooking", "title": "Hooking", "severity": "caution",
                    "evidence": ["metadata:KamiToolKit.dll:HookFromAddress"],
                }]},
            },
        }
        inspector._payload = lambda variant_id: payloads[variant_id]
        result = inspector.rule_match_fanout(["game.hooking"], limit=10, max_candidates=10)
        self.assertTrue(result["explicitAcquisition"])
        self.assertEqual(2, len(result["matches"]))
        pattern = next(item for item in result["patterns"] if item["pattern"] == "metadata:KamiToolKit.dll")
        self.assertEqual(2, pattern["variants"])
        self.assertIn("not loaded by page navigation", result["note"])
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

            def rule_match_fanout(self, rule_ids, *, limit=40, max_candidates=80):
                self.fanout_calls = getattr(self, "fanout_calls", 0) + 1
                self.last_fanout = (list(rule_ids), limit, max_candidates)
                return {
                    "schema": "omega.deltascope.rule-fanout.v1", "readOnly": True,
                    "mutationAuthority": "none", "explicitAcquisition": True,
                    "matches": [], "patterns": [], "searchedVariants": 0, "candidateVariants": 0,
                }

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
            self.assertEqual(0, getattr(inspector, "fanout_calls", 0))
            with urllib.request.urlopen(
                f"http://127.0.0.1:{server.server_address[1]}/api/workbench/rule-fanout?rule_id=process.review&finding_id=process.review.finding",
                timeout=5,
            ) as response:
                fanout = json.load(response)
            self.assertTrue(fanout["explicitAcquisition"])
            self.assertEqual(1, inspector.fanout_calls)
            self.assertEqual((["process.review", "process.review.finding"], 40, 80), inspector.last_fanout)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

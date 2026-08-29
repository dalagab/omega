from __future__ import annotations

import json
import threading
import unittest
import urllib.request

import deltascope_behaviors as behaviors
import developer_view
import evidence_v2_inspector


class DeltaScopeBehaviorsTests(unittest.TestCase):
    def detail(self) -> dict:
        return {
            "identity": {
                "plugin_id": 1,
                "variant_id": 10,
                "scan_id": 20,
                "canonical_name": "Example Plugin",
                "internal_name": "Example.Plugin",
                "assembly_version": "1.2.3",
                "scanned_at_utc": "2026-08-28T12:00:00Z",
            },
            "observations": {
                "collections": {
                    "staticPatternMatches": {"records": 2, "completeness": "retained"},
                    "managedCallSites": {"records": 1, "completeness": "retained"},
                }
            },
            "sourceCoverage": {"sourceCodeAvailable": False},
            "researcher": {
                "findings": [{
                    "ruleId": "filesystem.external-path",
                    "findingId": "filesystem.external-path.1",
                    "title": "Hard-coded external file path",
                    "description": "External path literal retained in artifact evidence.",
                    "severity": "caution",
                    "category": "filesystem",
                    "confidence": "high",
                    "evidence": [
                        "il:Example.dll:Example.IO.ConfigLoader..ctor+0x42",
                        "C:/Users/Public/example-sync.cache",
                    ],
                }],
                "capabilities": [
                    {"capabilityId": "filesystem.external-path", "label": "Hard-coded external file path"},
                    {"capabilityId": "dynamic.assembly", "label": "Dynamic code loading"},
                ],
                "capabilityIds": ["filesystem.external-path", "dynamic.assembly"],
            },
            "networkEndpoints": [{
                "host": "api.example.net",
                "url": "https://api.example.net/v1/update",
                "classification": "unrecognised-host",
                "originPath": "Example.dll",
            }],
            "componentSummary": {
                "components": [{"name": "KamiToolKit", "version": "2.0.0"}],
            },
            "advisories": [],
        }

    def observations(self) -> dict:
        return {
            "staticPatternMatches": [{
                "origin": "artifact",
                "path": "Example.dll",
                "pattern": "C:/Users/Public/example-sync.cache",
                "evidenceLabel": "C:/Users/Public/example-sync.cache",
            }],
            "managedCallSites": [{
                "origin": "artifact",
                "path": "Example.dll",
                "sourceDeclaringType": "Example.IO.ConfigLoader",
                "sourceMethodName": ".ctor",
                "ilOffset": 66,
                "literal": "C:/Users/Public/example-sync.cache",
                "targetDeclaringType": "System.IO.File",
                "targetName": "ReadAllText",
            }],
        }

    def test_behavior_projection_promotes_observed_value_and_location(self):
        result = behaviors.project_plugin_behaviors(self.detail(), self.observations(), {}, {}, {})
        self.assertEqual(behaviors.SCHEMA, result["schema"])
        self.assertTrue(result["readOnly"])
        self.assertEqual("none", result["mutationAuthority"])
        group = next(row for row in result["behaviors"] if row["behaviorKey"] == "filesystem.external-path")
        self.assertGreaterEqual(group["evidenceRowCount"], 1)
        values = {row["value"] for row in group["evidenceRows"]}
        self.assertIn("C:/Users/Public/example-sync.cache", values)
        callsite = next(row for row in group["evidenceRows"] if row["collection"] == "managedCallSites")
        self.assertEqual("il", callsite["kind"])
        self.assertEqual("Example.IO.ConfigLoader..ctor+0x42", callsite["location"])
        self.assertEqual("not available (artifact-only evidence)", callsite["sourceLocation"])

    def test_unmapped_capability_stays_visible_with_explicit_zero_row_state(self):
        result = behaviors.project_plugin_behaviors(self.detail(), self.observations(), {}, {}, {})
        group = next(row for row in result["behaviors"] if row["behaviorKey"] == "dynamic.assembly")
        self.assertEqual(0, group["evidenceRowCount"])
        self.assertEqual("collection-or-summary-derived", group["evidenceMapping"])
        self.assertIn("does not publish a specific matched callsite", group["note"])

    def test_capability_pivot_filters_behavior_without_dropping_context(self):
        result = behaviors.project_plugin_behaviors(
            self.detail(), self.observations(), {}, {}, {},
            pivot_kind="capability", pivot_key="filesystem.external-path", pivot_label="Hard-coded external file path",
        )
        self.assertTrue(result["pivotContext"]["active"])
        self.assertEqual(1, result["counts"]["visible"])
        self.assertEqual("filesystem.external-path", result["visibleBehaviors"][0]["behaviorKey"])

    def test_endpoint_and_component_pivots_have_direct_relationship_evidence(self):
        empty_projection = {"visibleBehaviors": []}
        endpoint = behaviors.project_pivot_asset_evidence(
            self.detail(), empty_projection, kind="endpoint", key="api.example.net"
        )
        self.assertEqual("https://api.example.net/v1/update", endpoint["evidenceRows"][0]["value"])
        self.assertEqual("endpoint", endpoint["evidenceRows"][0]["kind"])
        component = behaviors.project_pivot_asset_evidence(
            self.detail(), empty_projection, kind="component", key="KamiToolKit"
        )
        self.assertEqual("KamiToolKit", component["evidenceRows"][0]["value"])
        self.assertEqual("component", component["evidenceRows"][0]["kind"])

    def test_evidence_value_fanout_is_explicit_bounded_and_exact_first(self):
        inspector = evidence_v2_inspector.V2SigmascopeInspector.__new__(evidence_v2_inspector.V2SigmascopeInspector)
        inspector.current_entries = {
            10: {"scanId": 100, "summary": {"scanned_at_utc": "2026-08-28T10:00:00Z"}},
            11: {"scanId": 101, "summary": {"scanned_at_utc": "2026-08-28T11:00:00Z"}},
        }
        payloads = {
            10: {
                "plugin": {"canonical_name": "One", "internal_name": "One"},
                "variant": {"assembly_version": "1.0"},
                "current": {"scan_id": 100, "scanned_at_utc": "2026-08-28T10:00:00Z", "findings_json": [{
                    "ruleId": "filesystem.external-path", "findingId": "one", "evidence": ["C:/Users/Public/example-sync.cache"]
                }]},
            },
            11: {
                "plugin": {"canonical_name": "Two", "internal_name": "Two"},
                "variant": {"assembly_version": "2.0"},
                "current": {"scan_id": 101, "scanned_at_utc": "2026-08-28T11:00:00Z", "findings_json": [{
                    "ruleId": "filesystem.external-path", "findingId": "two", "evidence": ["path=C:/Users/Public/example-sync.cache"]
                }]},
            },
        }
        inspector._payload = lambda variant_id: payloads[variant_id]
        result = inspector.evidence_value_fanout(
            "C:/Users/Public/example-sync.cache", rule_ids=["filesystem.external-path"], limit=10, max_candidates=10
        )
        self.assertTrue(result["explicitAcquisition"])
        self.assertEqual("none", result["mutationAuthority"])
        self.assertEqual(2, len(result["matches"]))
        semantics = {row["plugin"]: row["matchSemantics"] for row in result["matches"]}
        self.assertEqual("exact", semantics["One"])
        self.assertEqual("contained", semantics["Two"])
        self.assertIn("Similar-looking values are not treated as equal evidence", result["note"])


    def test_http_behaviors_and_fanout_endpoints_are_read_only_and_explicit(self):
        owner = self

        class FakeInspector:
            def plugin_detail(self, variant_id):
                self.last_detail = variant_id
                return owner.detail()

            def workbench_observation_rows(self, variant_id, per_collection_limit=2500):
                self.last_observation = (variant_id, per_collection_limit)
                return owner.observations()

            def definition_provenance(self):
                return {}

            def srl_projection_state(self, variant_id):
                return {}

            def workbench_system_context(self):
                return {}

            def evidence_value_fanout(self, value, *, rule_ids=(), limit=40, max_candidates=80):
                self.last_fanout = (value, list(rule_ids), limit, max_candidates)
                return {
                    "schema": "omega.deltascope.evidence-value-fanout.v1",
                    "readOnly": True, "mutationAuthority": "none", "explicitAcquisition": True,
                    "value": value, "matches": [], "searchedVariants": 0, "candidateVariants": 0,
                }

        inspector = FakeInspector()
        handler = type("TestBehaviorsHandler", (developer_view.AppHandler,), {"inspector": inspector})
        server = developer_view.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            with urllib.request.urlopen(base + "/api/workbench/behaviors?variant_id=10&pivot_kind=capability&pivot_key=filesystem.external-path", timeout=5) as response:
                payload = json.load(response)
            self.assertEqual(behaviors.SCHEMA, payload["schema"])
            self.assertTrue(payload["readOnly"])
            self.assertEqual("none", payload["mutationAuthority"])
            self.assertEqual((10, 2500), inspector.last_observation)
            with urllib.request.urlopen(base + "/api/workbench/evidence-fanout?value=C%3A%2FUsers%2FPublic%2Fexample-sync.cache&rule_id=filesystem.external-path", timeout=5) as response:
                fanout = json.load(response)
            self.assertTrue(fanout["explicitAcquisition"])
            self.assertEqual("none", fanout["mutationAuthority"])
            self.assertEqual(
                ("C:/Users/Public/example-sync.cache", ["filesystem.external-path"], 40, 120),
                inspector.last_fanout,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

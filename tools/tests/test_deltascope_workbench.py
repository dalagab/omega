from __future__ import annotations

import copy
import json
import threading
import unittest
import urllib.request

import deltascope_workbench as workbench
import developer_view


class DeltaScopeWorkbenchTests(unittest.TestCase):
    def row(self, **updates):
        row = {
            "plugin_id": 1,
            "variant_id": 10,
            "scan_id": 20,
            "internal_name": "Example.Plugin",
            "canonical_name": "Example Plugin",
            "name": "Example Plugin",
            "author": "Developer",
            "assembly_version": "1.2.3",
            "source_name": "Example source",
            "source_url": "https://example.invalid/repo",
            "scan_status": "complete",
            "highest_severity": "none",
            "critical_count": 0,
            "high_count": 0,
            "caution_count": 0,
            "informational_count": 0,
            "scanned_at_utc": "2026-08-21T10:00:00Z",
            "knownAdvisoryCount": 0,
            "knownAdvisoryHighestSeverity": "none",
        }
        row.update(updates)
        return row

    def test_projection_is_read_only_and_has_github_authority_boundary(self):
        result = workbench.project_workbench([self.row()])
        self.assertEqual(workbench.WORKBENCH_SCHEMA, result["schema"])
        self.assertTrue(result["readOnly"])
        self.assertEqual("none", result["mutationAuthority"])
        self.assertEqual("github-permission-ci-review-normal-pr", result["authoritativeChangeBoundary"])

    def test_clean_asset_has_event_but_no_incident(self):
        result = workbench.project_workbench([self.row()])
        self.assertEqual([], result["incidents"])
        self.assertEqual(1, len(result["events"]))
        self.assertEqual("Security analysis completed", result["events"][0]["label"])

    def test_elevated_finding_creates_stable_incident(self):
        row = self.row(highest_severity="high", high_count=2)
        first = workbench.project_workbench([row])["incidents"][0]
        second = workbench.project_workbench([copy.deepcopy(row)])["incidents"][0]
        self.assertEqual(first["incidentId"], second["incidentId"])
        self.assertEqual("review", first["priority"])
        self.assertEqual(2, first["findingCount"])
        self.assertIn("elevated-findings", [reason["code"] for reason in first["reasons"]])
        self.assertEqual("none", first["mutationAuthority"])

    def test_failed_analysis_creates_incident_without_finding(self):
        incident = workbench.project_workbench([self.row(scan_status="failed")])["incidents"][0]
        self.assertEqual("failed", incident["priority"])
        self.assertEqual(0, incident["findingCount"])
        self.assertIn("analysis-incomplete", [reason["code"] for reason in incident["reasons"]])

    def test_advisory_creates_intelligence_and_incident(self):
        result = workbench.project_workbench([self.row(knownAdvisoryCount=2, knownAdvisoryHighestSeverity="critical")])
        self.assertEqual(1, len(result["intelligence"]))
        self.assertEqual(2, result["intelligence"][0]["advisoryCount"])
        self.assertEqual("critical", result["intelligence"][0]["highestSeverity"])
        self.assertIn("known-advisory", [reason["code"] for reason in result["incidents"][0]["reasons"]])

    def test_projection_revision_is_independent_of_input_row_order(self):
        a = self.row(variant_id=11, scan_id=21, canonical_name="A")
        b = self.row(variant_id=12, scan_id=22, canonical_name="B", highest_severity="high", high_count=1)
        self.assertEqual(
            workbench.project_workbench([a, b])["projectionRevision"],
            workbench.project_workbench([b, a])["projectionRevision"],
        )

    def test_incident_identity_changes_when_security_state_changes(self):
        clean = self.row(highest_severity="caution", caution_count=1)
        changed = self.row(highest_severity="high", high_count=1)
        self.assertNotEqual(
            workbench.project_workbench([clean])["incidents"][0]["incidentId"],
            workbench.project_workbench([changed])["incidents"][0]["incidentId"],
        )

    def test_invalid_variant_rows_are_ignored(self):
        result = workbench.project_workbench([self.row(variant_id=0), self.row(variant_id="bad")])
        self.assertEqual([], result["assets"])
        self.assertEqual([], result["events"])


    def detail(self):
        return {
            "identity": {
                "plugin_id": 1, "variant_id": 10, "scan_id": 20,
                "internal_name": "Example.Plugin", "canonical_name": "Example Plugin",
                "author": "Developer", "assembly_version": "1.2.3",
                "source_name": "Example source", "source_url": "https://example.invalid/repo",
                "scan_status": "complete", "scanned_at_utc": "2026-08-21T10:00:00Z",
            },
            "researcher": {
                "findingCounts": {"critical": 0, "high": 1, "caution": 0, "informational": 0},
                "findings": [{
                    "ruleId": "compound.network-execute", "findingId": "compound.network-execute",
                    "severity": "high", "category": "compound", "title": "Network + execution",
                    "description": "fixture", "evidence": ["fixture evidence"],
                }],
                "signals": [{"kind": "compound", "level": "high", "label": "Network + process execution compound capability"}],
            },
            "advisories": [{"id": "GHSA-test", "severity": "high", "package": "Example.Package"}],
            "advisorySummary": {"count": 1, "highestSeverity": "high", "points": 0},
        }

    def test_asset_journey_reconstructs_evidence_backed_vertical_stages(self):
        detail = self.detail()
        detail.update({
            "sourceCoverage": {
                "artifactAvailable": True, "sourceCodeAvailable": True,
                "repository": "https://github.com/example/plugin", "commit": "abc123",
                "attributionConfidence": 92, "sourceToBinaryVerified": False,
            },
            "artifactIdentity": {"sha256": "aa" * 32},
            "manifestObservation": {"internalName": "Example.Plugin"},
            "package": {"files": 4},
            "secondarySecurity": {"engines": [
                {"engine": "yara", "status": "complete", "matches": []},
                {"engine": "clamav", "status": "complete", "matches": []},
            ]},
            "analysis": {"path": "artifacts/aa/analysis"},
            "networkEndpoints": [{"host": "api.example.test"}],
            "dependencies": [{"name": "Example.Dependency"}],
        })
        detail["identity"]["artifact_sha256"] = "aa" * 32
        detail["identity"]["artifact_url"] = "https://example.invalid/plugin.zip"
        detail["identity"]["scanner_version"] = "2.15.0"
        projection_state = {
            "available": True, "ruleSetRevision": "rules-1", "productionWriteBack": False,
            "projection": {
                "projectionRevision": "proj-1", "matchedRuleIds": ["compound.network-execute"],
                "findings": [{"findingId": "compound.network-execute"}],
            },
            "analysisRequest": {
                "variantId": 10, "profile": "artifact-differential-v1", "depth": "extended",
                "compareWith": "stable-artifact-baseline", "ruleId": "provenance.deep",
                "reason": "artifact diverges from stable baseline",
            },
        }
        result = workbench.project_asset_journey(detail, {
            "staticPatternMatches": [{"pattern": "HttpWebRequest"}],
            "networkEndpoints": [{"host": "api.example.test"}],
        }, projection_state)
        self.assertEqual(workbench.JOURNEY_SCHEMA, result["schema"])
        self.assertTrue(result["readOnly"])
        self.assertEqual("none", result["mutationAuthority"])
        stages = {item["stageId"]: item for item in result["stages"]}
        self.assertEqual("complete", stages["artifact-acquisition"]["status"])
        self.assertEqual("complete", stages["source-attribution"]["status"])
        self.assertEqual("complete", stages["sigmascope-static"]["status"])
        self.assertEqual("complete", stages["stigma-rules"]["status"])
        self.assertEqual("requested", stages["deep-analysis"]["status"])
        self.assertIn("artifact-differential-v1", stages["deep-analysis"]["details"][0])
        self.assertEqual("current", stages["deltascope-view"]["status"])

    def test_asset_journey_does_not_invent_missing_source_or_deep_scan(self):
        detail = self.detail()
        detail["sourceCoverage"] = {"artifactAvailable": False, "sourceCodeAvailable": False}
        result = workbench.project_asset_journey(detail, {}, {"available": False})
        stages = {item["stageId"]: item for item in result["stages"]}
        self.assertEqual("skipped", stages["source-attribution"]["status"])
        self.assertEqual("not-requested", stages["deep-analysis"]["status"])
        self.assertNotIn("retrieved", stages["source-attribution"]["summary"].casefold())

    def test_asset_journey_projection_is_deterministic_for_observation_order(self):
        detail = self.detail()
        a = workbench.project_asset_journey(detail, {"networkEndpoints": [{"host": "a"}, {"host": "b"}]})
        b = workbench.project_asset_journey(detail, {"networkEndpoints": [{"host": "b"}, {"host": "a"}]})
        self.assertEqual(a["journeyProjectionId"], b["journeyProjectionId"])

    def test_incident_case_composes_findings_observations_intelligence_and_reprojection(self):
        projection_state = {
            "available": True,
            "projectionSetRevision": "set-1",
            "ruleSetRevision": "rules-1",
            "productionWriteBack": False,
            "queueMutationAuthorized": False,
            "projection": {
                "projectionRevision": "projection-1", "ruleSetRevision": "rules-1",
                "matchedRuleIds": ["compound.network-execute"], "facts": ["network.http", "process.launch"],
                "findings": [{"ruleId": "compound.network-execute", "findingId": "compound.network-execute", "severity": "high"}],
                "productionWriteBack": False,
            },
        }
        result = workbench.project_incident_case(
            self.detail(),
            {
                "staticPatternMatches": [{"origin": "artifact", "pattern": "HttpWebRequest", "evidenceLabel": "metadata:Fixture.dll"}],
                "networkEndpoints": [{"host": "api.example.test", "url": "https://api.example.test"}],
            },
            projection_state,
        )
        self.assertEqual(workbench.CASE_SCHEMA, result["schema"])
        self.assertTrue(result["readOnly"])
        self.assertEqual("none", result["mutationAuthority"])
        self.assertEqual("github-permission-ci-review-normal-pr", result["authoritativeChangeBoundary"])
        self.assertEqual(["compound.network-execute"], result["contributingFindingIds"])
        event_types = [item["eventType"] for item in result["timeline"]["events"]]
        self.assertIn("finding-projected", event_types)
        self.assertIn("observation", event_types)
        self.assertIn("intelligence-advisory", event_types)
        self.assertIn("srl-rule-reprojection", event_types)
        self.assertFalse(result["timeline"]["observationEventsTruncated"])
        self.assertFalse(result["ruleProjection"]["productionWriteBack"])

    def test_incident_case_is_deterministic_when_observation_order_changes(self):
        rows = [
            {"origin": "artifact", "pattern": "HttpWebRequest"},
            {"origin": "artifact", "pattern": "Process.Start"},
        ]
        first = workbench.project_incident_case(self.detail(), {"staticPatternMatches": rows})
        second = workbench.project_incident_case(self.detail(), {"staticPatternMatches": list(reversed(rows))})
        self.assertEqual(first["caseProjectionId"], second["caseProjectionId"])
        self.assertEqual(
            [item["eventId"] for item in first["timeline"]["events"]],
            [item["eventId"] for item in second["timeline"]["events"]],
        )

    def test_incident_case_marks_bounded_observation_preview(self):
        rows = [{"origin": "artifact", "pattern": f"marker-{idx}"} for idx in range(5)]
        result = workbench.project_incident_case(self.detail(), {"staticPatternMatches": rows}, max_observation_events=2)
        self.assertTrue(result["timeline"]["observationEventsTruncated"])
        self.assertEqual(2, result["timeline"]["observationEventsEmitted"])
        self.assertEqual(5, result["timeline"]["observationCounts"]["staticPatternMatches"])

    def test_reanalysis_request_is_timeline_relationship_not_queue_mutation(self):
        result = workbench.project_incident_case(self.detail(), {}, {
            "available": True, "queueMutationAuthorized": False, "productionWriteBack": False,
            "reanalysisRequest": {
                "variantId": 10, "ruleSetRevision": "rules-2",
                "reason": "missing observation collection staticPatternMatches",
                "queueMutationAuthorized": False,
            },
        })
        events = [item for item in result["timeline"]["events"] if item["eventType"] == "srl-reanalysis-required"]
        self.assertEqual(1, len(events))
        self.assertEqual("requires-observation-refresh", events[0]["relationship"])
        self.assertFalse(result["ruleProjection"]["queueMutationAuthorized"])

    def test_http_asset_journey_endpoint_reconstructs_selected_variant_read_only(self):
        detail = self.detail()
        detail["sourceCoverage"] = {"artifactAvailable": True, "sourceCodeAvailable": False}
        detail["identity"]["artifact_sha256"] = "bb" * 32

        class FakeInspector:
            def plugin_detail(self, variant_id):
                self.last_detail = variant_id
                return detail

            def workbench_observation_rows(self, variant_id):
                self.last_observation = variant_id
                return {"networkEndpoints": [{"host": "api.example.test"}]}

            def srl_projection_state(self, variant_id):
                self.last_projection = variant_id
                return {"available": False, "productionWriteBack": False}

        inspector = FakeInspector()
        handler = type("TestAssetJourneyHandler", (developer_view.AppHandler,), {"inspector": inspector})
        server = developer_view.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_address[1]}/api/workbench/journey?variant_id=10", timeout=5) as response:
                payload = json.load(response)
            self.assertEqual(workbench.JOURNEY_SCHEMA, payload["schema"])
            self.assertEqual("none", payload["mutationAuthority"])
            self.assertEqual(10, inspector.last_detail)
            self.assertEqual(10, inspector.last_observation)
            self.assertEqual(10, inspector.last_projection)
            self.assertEqual("current", payload["stages"][-1]["status"])
        finally:
            server.shutdown()
            server.server_close()

    def test_http_workbench_case_endpoint_is_read_only_and_composed_lazily(self):
        detail = self.detail()

        class FakeInspector:
            def plugin_detail(self, variant_id):
                self.last_detail = variant_id
                return detail

            def workbench_observation_rows(self, variant_id):
                self.last_observation = variant_id
                return {"networkEndpoints": [{"host": "api.example.test"}]}

            def srl_projection_state(self, variant_id):
                self.last_projection = variant_id
                return {"available": False, "productionWriteBack": False, "queueMutationAuthorized": False}

        inspector = FakeInspector()
        handler = type("TestWorkbenchCaseHandler", (developer_view.AppHandler,), {"inspector": inspector})
        server = developer_view.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_address[1]}/api/workbench/case?variant_id=10", timeout=5) as response:
                payload = json.load(response)
            self.assertEqual(workbench.CASE_SCHEMA, payload["schema"])
            self.assertEqual("none", payload["mutationAuthority"])
            self.assertEqual(10, inspector.last_detail)
            self.assertEqual(10, inspector.last_observation)
            self.assertEqual(10, inspector.last_projection)
            self.assertTrue(any(item["eventType"] == "observation" for item in payload["timeline"]["events"]))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_http_workbench_endpoint_returns_derived_read_only_objects(self):
        row = self.row(highest_severity="high", high_count=1)

        class FakeInspector:
            def list_plugins(self, **_kwargs):
                return [row]

            def summary(self):
                return {"counts": {"plugins": 1, "findings": 1}}

        handler = type("TestWorkbenchHandler", (developer_view.AppHandler,), {"inspector": FakeInspector()})
        server = developer_view.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_address[1]}/api/workbench?limit=10", timeout=5) as response:
                payload = json.load(response)
            self.assertEqual(workbench.WORKBENCH_SCHEMA, payload["schema"])
            self.assertTrue(payload["readOnly"])
            self.assertEqual("none", payload["mutationAuthority"])
            self.assertEqual(1, len(payload["incidents"]))
            self.assertEqual(10, payload["incidents"][0]["asset"]["variantId"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


    def relationship_index(self):
        return {
            "schema": "omega.security-evidence.workbench-relationships.v1",
            "relationshipRevision": "workbench-rel-v1-test",
            "readOnly": True, "mutationAuthority": "none", "policyInput": False,
            "counts": {"endpoints": 1, "components": 1, "advisories": 1},
            "endpoints": [{
                "endpointKey": "host:api.example.test", "host": "api.example.test",
                "urlSamples": ["https://api.example.test/v1"], "classifications": ["api"],
                "purposes": ["service"], "origins": ["artifact"], "variantIds": [10, 11],
                "pluginIds": [1, 2], "variantCount": 2, "pluginCount": 2, "observations": 3,
            }],
            "components": [{
                "componentKey": "nuget:example.package", "kind": "nuget", "displayName": "Example.Package",
                "versions": ["1.0.0"], "variantCount": 2, "pluginCount": 2, "versionDivergence": "none",
                "usage": [
                    {"variantId": 10, "pluginId": 1, "scanId": 20, "observedVersion": "1.0.0", "requirement": "required"},
                    {"variantId": 11, "pluginId": 2, "scanId": 21, "observedVersion": "1.0.0", "requirement": "observed"},
                ],
            }],
            "advisories": [{
                "advisoryId": "GHSA-test", "componentKey": "nuget:example.package", "componentKind": "nuget",
                "componentName": "Example.Package", "affectedVersion": "1.0.0", "fixedVersion": "1.0.1",
                "severity": "high", "title": "Example advisory", "url": "https://example.invalid/GHSA-test",
                "source": "OSV", "affectedAssets": [
                    {"variantId": 10, "pluginId": 1, "scanId": 20, "observedVersion": "1.0.0"},
                    {"variantId": 11, "pluginId": 2, "scanId": 21, "observedVersion": "1.0.0"},
                ],
            }],
        }

    def test_intelligence_catalog_projects_endpoint_component_and_advisory_pivots_read_only(self):
        result = workbench.project_intelligence_catalog(self.relationship_index())
        self.assertEqual(workbench.INTELLIGENCE_CATALOG_SCHEMA, result["schema"])
        self.assertTrue(result["readOnly"])
        self.assertEqual("none", result["mutationAuthority"])
        self.assertFalse(result["policyInput"])
        self.assertEqual("api.example.test", result["endpoints"][0]["label"])
        self.assertEqual("Example.Package", result["components"][0]["label"])
        self.assertEqual("GHSA-test", result["advisories"][0]["advisoryId"])

    def test_intelligence_pivot_resolves_all_affected_assets_without_deep_evidence(self):
        assets = [
            self.row(variant_id=10, plugin_id=1, canonical_name="Example Plugin"),
            self.row(variant_id=11, plugin_id=2, canonical_name="Other Plugin", internal_name="Other.Plugin"),
        ]
        result = workbench.project_intelligence_pivot(self.relationship_index(), "endpoint", "host:api.example.test", assets)
        self.assertEqual(workbench.INTELLIGENCE_PIVOT_SCHEMA, result["schema"])
        self.assertEqual([10, 11], sorted(item["variantId"] for item in result["assets"]))
        self.assertEqual(2, result["relationship"]["variantCount"])
        self.assertEqual("none", result["mutationAuthority"])

    def test_asset_relationship_projection_links_plugin_variant_artifact_source_components_endpoints(self):
        row = self.row(
            artifact_sha256="a" * 64,
            source_repository="https://example.invalid/repo.git",
        )
        result = workbench.project_asset_relationships(self.relationship_index(), 10, row)
        self.assertEqual(workbench.ASSET_RELATIONSHIP_SCHEMA, result["schema"])
        kinds = {node["kind"] for node in result["graph"]["nodes"]}
        self.assertTrue({"plugin", "variant", "artifact", "source", "component", "endpoint", "advisory"}.issubset(kinds))
        relationships = {edge["relationship"] for edge in result["graph"]["edges"]}
        self.assertIn("has-variant", relationships)
        self.assertIn("analyzed-from-artifact", relationships)
        self.assertIn("attributed-to-source", relationships)
        self.assertIn("uses-component", relationships)
        self.assertIn("observes-endpoint", relationships)
        self.assertTrue(result["readOnly"])

    def test_relationship_variant_ids_fail_closed_for_unknown_kind_or_key(self):
        with self.assertRaises(ValueError):
            workbench.relationship_variant_ids(self.relationship_index(), "other", "x")
        with self.assertRaises(ValueError):
            workbench.relationship_variant_ids(self.relationship_index(), "endpoint", "host:missing.test")

    def test_http_relationship_catalog_pivot_and_asset_graph_are_read_only(self):
        relationship_index = self.relationship_index()
        rows = [self.row(variant_id=10), self.row(variant_id=11, plugin_id=2, canonical_name="Other Plugin")]

        class FakeInspector:
            def workbench_relationship_index(self):
                return relationship_index

            def workbench_assets_for_variants(self, variant_ids):
                wanted = {int(v) for v in variant_ids}
                return [row for row in rows if int(row["variant_id"]) in wanted]

        handler = type("TestWorkbenchRelationshipHandler", (developer_view.AppHandler,), {"inspector": FakeInspector()})
        server = developer_view.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            with urllib.request.urlopen(base + "/api/workbench/relationships", timeout=5) as response:
                catalog = json.load(response)
            self.assertEqual(workbench.INTELLIGENCE_CATALOG_SCHEMA, catalog["schema"])
            with urllib.request.urlopen(base + "/api/workbench/pivot?kind=component&key=nuget%3Aexample.package", timeout=5) as response:
                pivot = json.load(response)
            self.assertEqual(2, len(pivot["assets"]))
            with urllib.request.urlopen(base + "/api/workbench/asset-relations?variant_id=10", timeout=5) as response:
                graph = json.load(response)
            self.assertEqual(workbench.ASSET_RELATIONSHIP_SCHEMA, graph["schema"])
            self.assertEqual("none", graph["mutationAuthority"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

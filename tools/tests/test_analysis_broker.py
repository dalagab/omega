from __future__ import annotations
import unittest

import common  # noqa: F401
import analysis_broker
import collector_contracts


class AnalysisBrokerTests(unittest.TestCase):
    def discovery_request(self) -> dict:
        return {
            "schema": analysis_broker.ANALYSIS_REQUEST_SCHEMA,
            "observation": "catalogRepositoryCandidates",
            "subject": {"type": "catalog"},
            "reason": "Resolve repository candidates for a newly observed plugin.",
            "priority": 700,
            "requestedBy": {"componentId": "omega.stigma-1", "ruleId": "catalog.repository-needed"},
            "requestedAtUtc": "2026-08-24T20:00:00Z",
        }

    def test_resolution_groups_aggregate_collectors_by_component(self) -> None:
        resolved = analysis_broker.resolve_request(self.discovery_request())
        self.assertTrue(resolved["satisfiable"])
        self.assertTrue(resolved["dispatchable"])
        self.assertEqual("aggregate", resolved["providerStrategy"])
        self.assertEqual(1, len(resolved["dispatchPlan"]))
        plan = resolved["dispatchPlan"][0]
        self.assertEqual("omega.discovery", plan["componentId"])
        self.assertIn("omega.collector.discovery.project-page", plan["collectors"])
        self.assertEqual("main-control-plane-only", resolved["executionAuthority"])
        self.assertFalse(resolved["brokerExecutesComponents"])

    def test_authenticode_contract_is_active_and_dispatchable(self) -> None:
        request = {
            "observation": "binarySignatureTrust",
            "subject": {"type": "artifact", "artifactSha256": "a" * 64},
            "reason": "Need signature trust evidence.",
            "requestedAtUtc": "2026-08-24T20:00:00Z",
        }
        resolved = analysis_broker.resolve_request(request)
        self.assertTrue(resolved["satisfiable"])
        self.assertTrue(resolved["dispatchable"])
        self.assertEqual("omega.collector.sigmascope.authenticode", resolved["providerCandidates"][0]["collectorId"])
        self.assertEqual("active", resolved["providerCandidates"][0]["collectorStatus"])
        self.assertEqual("omega.sigmascope", resolved["dispatchPlan"][0]["componentId"])
        self.assertEqual("ttl", resolved["request"]["freshness"]["model"])
        self.assertEqual(604800, resolved["request"]["freshness"]["ttlSeconds"])

    def test_external_rift_provider_can_be_satisfiable_without_being_dispatchable_here(self) -> None:
        request = {
            "observation": "riftRuntimeEvents",
            "subject": {"type": "variant", "variantId": 42, "artifactSha256": "b" * 64, "profile": "post-init-safe-v1"},
            "reason": "Need runtime observations.",
            "requestedAtUtc": "2026-08-24T20:00:00Z",
        }
        resolved = analysis_broker.resolve_request(request)
        self.assertTrue(resolved["satisfiable"])
        self.assertFalse(resolved["dispatchable"])
        self.assertEqual("omega.rift", resolved["providerCandidates"][0]["componentId"])

    def test_rules_cannot_bind_generic_requests_to_implementations(self) -> None:
        bad = self.discovery_request()
        bad["collectorId"] = "omega.collector.discovery.project-page"
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            analysis_broker.compile_request(bad)

    def test_stigma_observation_request_converts_to_generic_request(self) -> None:
        stigma = collector_contracts.resolve_observation_request({
            "collection": "catalogRepositoryCandidates",
            "reason": "Need repository candidate",
            "priority": 650,
        })
        stigma["ruleId"] = "catalog.need-repository"
        stigma["ruleRevision"] = "rule-v1"
        generic = analysis_broker.from_observation_request(
            stigma, {"type": "catalog"}, requested_at="2026-08-24T20:00:00Z", evaluation_id="eval-1"
        )
        self.assertEqual("catalogRepositoryCandidates", generic["observation"])
        self.assertEqual("omega.stigma-1", generic["requestedBy"]["componentId"])
        self.assertEqual("catalog.need-repository", generic["requestedBy"]["ruleId"])
        self.assertNotIn("collectorId", generic)
        self.assertNotIn("componentId", generic)

    def test_durable_state_lifecycle_is_bounded_and_deterministic(self) -> None:
        state = analysis_broker.empty_state(now="2026-08-24T20:00:00Z")
        state, resolution = analysis_broker.enqueue(state, self.discovery_request(), now="2026-08-24T20:00:01Z")
        self.assertTrue(resolution["enqueued"])
        selected = analysis_broker.select_next(state)
        self.assertIsNotNone(selected)
        self.assertEqual("queued", selected["state"])
        work_id = selected["workItemId"]
        state = analysis_broker.transition(state, work_id, "running", now="2026-08-24T20:00:02Z")
        state = analysis_broker.transition(state, work_id, "completed", now="2026-08-24T20:00:03Z", result_detail={"observationBundle": "sha256:fixture"})
        summary = analysis_broker.summary(state)
        self.assertEqual(1, summary["states"]["completed"])
        self.assertIsNone(summary["next"])
        with self.assertRaisesRegex(ValueError, "invalid broker transition"):
            analysis_broker.transition(state, work_id, "running")

    def test_non_dispatchable_request_is_retained_as_requested_not_dropped(self) -> None:
        request = {
            "observation": "sourceArtifactBuildProof",
            "subject": {"type": "source", "sourceRepository": "https://github.com/example/plugin", "sourceCommit": "abc", "artifactSha256": "c" * 64},
            "reason": "Need reproducible build proof.",
            "requestedAtUtc": "2026-08-24T20:00:00Z",
        }
        state, resolved = analysis_broker.enqueue(analysis_broker.empty_state(), request)
        self.assertFalse(resolved["dispatchable"])
        self.assertEqual("requested", state["items"][0]["state"])
        self.assertEqual("", state["items"][0]["componentId"])


    def test_fresh_inventory_satisfies_request_without_dispatch(self) -> None:
        request = self.discovery_request()
        compiled = analysis_broker.compile_request(request)
        inventory = {
            "schema": analysis_broker.INVENTORY_SCHEMA,
            "records": [{
                "observation": compiled["observation"], "subjectKey": compiled["subjectKey"],
                "observedAtUtc": "2026-08-24T19:00:00Z", "expiresAtUtc": "2026-08-25T01:00:00Z",
                "collectorId": "omega.collector.discovery.project-page", "componentId": "omega.discovery",
                "reference": "catalog-discovery:fixture", "recordDigest": "abc",
            }],
        }
        resolved = analysis_broker.resolve_request(request, inventory=inventory, now="2026-08-24T20:00:00Z")
        self.assertTrue(resolved["reuseSatisfied"])
        self.assertFalse(resolved["needsDispatch"])
        self.assertEqual([], resolved["dispatchPlan"])
        state, enqueued = analysis_broker.enqueue(analysis_broker.empty_state(), request, inventory=inventory, now="2026-08-24T20:00:00Z")
        self.assertTrue(enqueued["reused"])
        self.assertEqual("completed", state["items"][0]["state"])

    def test_expired_ttl_inventory_does_not_suppress_dispatch(self) -> None:
        request = self.discovery_request()
        compiled = analysis_broker.compile_request(request)
        inventory = {
            "schema": analysis_broker.INVENTORY_SCHEMA,
            "records": [{
                "observation": compiled["observation"], "subjectKey": compiled["subjectKey"],
                "observedAtUtc": "2026-08-23T00:00:00Z", "expiresAtUtc": "2026-08-23T06:00:00Z",
                "collectorId": "omega.collector.discovery.project-page", "componentId": "omega.discovery",
            }],
        }
        resolved = analysis_broker.resolve_request(request, inventory=inventory, now="2026-08-24T20:00:00Z")
        self.assertFalse(resolved["reuseSatisfied"])
        self.assertTrue(resolved["needsDispatch"])
        self.assertTrue(resolved["dispatchable"])

    def test_broker_state_revision_detects_tampering(self) -> None:
        state = analysis_broker.empty_state(now="2026-08-24T20:00:00Z")
        state["items"].append({"state": "queued"})
        with self.assertRaisesRegex(ValueError, "revision does not match"):
            analysis_broker.summary(state)

if __name__ == "__main__":
    unittest.main()

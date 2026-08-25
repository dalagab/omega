from __future__ import annotations
import unittest
from unittest.mock import patch

import common  # noqa: F401
import analysis_broker
import analysis_dispatcher


class AnalysisDispatcherTests(unittest.TestCase):
    def request(self, *, priority: int = 700, reason: str = "Need repository candidates") -> dict:
        return {
            "observation": "catalogRepositoryCandidates",
            "subject": {"type": "catalog"},
            "reason": reason,
            "priority": priority,
            "requestedBy": {"componentId": "omega.stigma-1", "ruleId": "catalog.repository-needed"},
            "requestedAtUtc": "2026-08-24T20:00:00Z",
        }

    def queued_state(self, *, count: int = 1) -> dict:
        state = analysis_broker.empty_state(now="2026-08-24T20:00:00Z")
        for index in range(count):
            request = self.request(priority=700-index, reason=f"Need repository candidates {index}")
            request["requestId"] = f"request-{index}"
            state, resolution = analysis_broker.enqueue(state, request, now=f"2026-08-24T20:00:0{index+1}Z")
            self.assertTrue(resolution["dispatchable"])
        return state

    def test_claim_marks_exactly_one_item_running_with_lease(self) -> None:
        state = self.queued_state(count=2)
        updated, claim, recovery = analysis_dispatcher.claim_next(
            state, dispatcher_id="main-dispatcher", now="2026-08-24T20:01:00Z", lease_seconds=1200
        )
        self.assertEqual([], recovery["requeued"])
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertEqual("omega.analysis-dispatch-claim.v1", claim["schema"])
        self.assertEqual("omega.discovery", claim["componentId"])
        self.assertEqual("reusable-workflow", claim["launch"]["launchMode"])
        self.assertEqual(".github/workflows/catalog-discovery.yml", claim["launch"]["workflow"])
        self.assertEqual(1, claim["attempt"])
        states = [item["state"] for item in updated["items"]]
        self.assertEqual(1, states.count("running"))
        self.assertEqual(1, states.count("queued"))
        running = next(item for item in updated["items"] if item["state"] == "running")
        self.assertEqual(claim["claimToken"], running["claim"]["claimToken"])

    def test_claim_does_not_trust_queued_workflow_path(self) -> None:
        state = self.queued_state()
        state["items"][0]["launch"]["workflow"] = ".github/workflows/evil.yml"
        analysis_broker._stamp_state(state)
        updated, claim, _ = analysis_dispatcher.claim_next(
            state, dispatcher_id="main-dispatcher", now="2026-08-24T20:01:00Z"
        )
        assert claim is not None
        self.assertEqual(".github/workflows/catalog-discovery.yml", claim["launch"]["workflow"])
        self.assertEqual(".github/workflows/catalog-discovery.yml", updated["items"][0]["launch"]["workflow"])

    def test_settlement_requires_matching_claim_token(self) -> None:
        state, claim, _ = analysis_dispatcher.claim_next(
            self.queued_state(), dispatcher_id="main-dispatcher", now="2026-08-24T20:01:00Z"
        )
        assert claim is not None
        with self.assertRaisesRegex(ValueError, "claim token mismatch"):
            analysis_dispatcher.settle_claim(
                state, work_item_id=claim["workItemId"], claim_token="claim-wrong",
                outcome="completed", now="2026-08-24T20:02:00Z",
            )
        settled, result = analysis_dispatcher.settle_claim(
            state, work_item_id=claim["workItemId"], claim_token=claim["claimToken"],
            outcome="completed", now="2026-08-24T20:02:00Z",
            result_detail={"dispatcherRunId": "123"},
        )
        self.assertEqual("completed", result["state"])
        self.assertFalse(result["retryScheduled"])
        self.assertNotIn("claim", settled["items"][0])
        self.assertEqual("123", settled["items"][0]["result"]["dispatcherRunId"])

    def test_failed_dispatch_requeues_until_attempt_bound(self) -> None:
        state, claim, _ = analysis_dispatcher.claim_next(
            self.queued_state(), dispatcher_id="main-dispatcher", now="2026-08-24T20:01:00Z", max_attempts=2
        )
        assert claim is not None
        state, result = analysis_dispatcher.settle_claim(
            state, work_item_id=claim["workItemId"], claim_token=claim["claimToken"], outcome="failed",
            now="2026-08-24T20:02:00Z", max_attempts=2,
        )
        self.assertEqual("queued", result["state"])
        self.assertTrue(result["retryScheduled"])
        state, claim2, _ = analysis_dispatcher.claim_next(
            state, dispatcher_id="main-dispatcher", now="2026-08-24T20:03:00Z", max_attempts=2
        )
        assert claim2 is not None
        self.assertEqual(2, claim2["attempt"])
        state, result2 = analysis_dispatcher.settle_claim(
            state, work_item_id=claim2["workItemId"], claim_token=claim2["claimToken"], outcome="failed",
            now="2026-08-24T20:04:00Z", max_attempts=2,
        )
        self.assertEqual("failed", result2["state"])
        self.assertFalse(result2["retryScheduled"])

    def test_expired_lease_is_recovered_and_reclaimed(self) -> None:
        state, claim, _ = analysis_dispatcher.claim_next(
            self.queued_state(), dispatcher_id="dead-runner", now="2026-08-24T20:01:00Z",
            lease_seconds=60, max_attempts=3,
        )
        assert claim is not None
        state, claim2, recovery = analysis_dispatcher.claim_next(
            state, dispatcher_id="replacement-runner", now="2026-08-24T20:03:00Z",
            lease_seconds=60, max_attempts=3,
        )
        self.assertEqual([claim["workItemId"]], recovery["requeued"])
        assert claim2 is not None
        self.assertEqual(claim["workItemId"], claim2["workItemId"])
        self.assertEqual(2, claim2["attempt"])
        self.assertNotEqual(claim["claimToken"], claim2["claimToken"])


    def test_batch_respects_component_concurrency_limit(self) -> None:
        state = self.queued_state(count=4)
        updated, batch, recovery = analysis_dispatcher.claim_batch(
            state, dispatcher_id="runner-a", now="2026-08-24T20:01:00Z",
            lease_seconds=1200, max_claims=4, max_in_flight=4,
        )
        self.assertEqual([], recovery["requeued"])
        self.assertEqual("omega.analysis-dispatch-batch.v1", batch["schema"])
        self.assertEqual(1, batch["claimedCount"])
        self.assertEqual(1, batch["activeAfter"])
        self.assertEqual(1, sum(1 for item in updated["items"] if item["state"] == "running"))
        self.assertEqual(3, sum(1 for item in updated["items"] if item["state"] == "queued"))

        updated2, batch2, _ = analysis_dispatcher.claim_batch(
            updated, dispatcher_id="runner-b", now="2026-08-24T20:01:30Z",
            lease_seconds=1200, max_claims=4, max_in_flight=4,
        )
        self.assertEqual(1, batch2["activeBefore"])
        self.assertEqual(0, batch2["claimedCount"])
        self.assertEqual(1, sum(1 for item in updated2["items"] if item["state"] == "running"))

    def test_batch_fills_freed_capacity_with_different_work(self) -> None:
        state = self.queued_state(count=3)
        state, batch, _ = analysis_dispatcher.claim_batch(
            state, dispatcher_id="runner-a", now="2026-08-24T20:01:00Z",
            max_claims=3, max_in_flight=3,
        )
        self.assertEqual(1, batch["claimedCount"])
        first = batch["claims"][0]
        state, settlement = analysis_dispatcher.settle_claim(
            state, work_item_id=first["workItemId"], claim_token=first["claimToken"],
            outcome="completed", now="2026-08-24T20:02:00Z",
        )
        self.assertEqual("completed", settlement["state"])
        state, second_batch, _ = analysis_dispatcher.claim_batch(
            state, dispatcher_id="runner-b", now="2026-08-24T20:03:00Z",
            max_claims=3, max_in_flight=3,
        )
        self.assertEqual(0, second_batch["activeBefore"])
        self.assertEqual(1, second_batch["claimedCount"])
        self.assertNotEqual(first["workItemId"], second_batch["claims"][0]["workItemId"])

    def test_batch_can_claim_parallel_work_from_different_components(self) -> None:
        state = self.queued_state(count=4)
        for index, item in enumerate(state["items"]):
            item["componentId"] = "omega.discovery" if index % 2 == 0 else "omega.synthetic-second"
        analysis_broker._stamp_state(state)

        def fake_dispatch(item):
            component = item["componentId"]
            return ({
                "componentId": component, "dispatchable": True, "launchMode": "reusable-workflow",
                "workflow": ".github/workflows/fixed.yml", "requestMode": "test",
                "collectors": list(item.get("collectors") or []), "maxConcurrent": 2,
            }, "")

        with patch.object(analysis_dispatcher, "_current_dispatch", side_effect=fake_dispatch):
            updated, batch, _ = analysis_dispatcher.claim_batch(
                state, dispatcher_id="runner-parallel", now="2026-08-24T20:01:00Z",
                max_claims=4, max_in_flight=4,
            )
        self.assertEqual(4, batch["claimedCount"])
        self.assertEqual(4, sum(1 for item in updated["items"] if item["state"] == "running"))
        self.assertEqual({"omega.discovery": 2, "omega.synthetic-second": 2}, analysis_dispatcher.active_claims_by_component(updated, now="2026-08-24T20:01:30Z"))


    def test_batch_allow_list_prevents_old_main_runner_from_claiming_new_component(self) -> None:
        state = analysis_broker.empty_state(now="2026-08-24T20:00:00Z")
        sigma_request = {
            "requestId": "sigma-request",
            "observation": "managedCallSites",
            "subject": {"type": "variant", "variantId": 42},
            "reason": "Need managed call sites",
            "priority": 900,
            "requestedBy": {"componentId": "omega.stigma-1"},
            "requestedAtUtc": "2026-08-24T20:00:00Z",
        }
        state, sigma_resolution = analysis_broker.enqueue(state, sigma_request, now="2026-08-24T20:00:01Z")
        self.assertTrue(sigma_resolution["dispatchable"])
        discovery = self.request(priority=700, reason="Need repository candidates")
        discovery["requestId"] = "discovery-request"
        state, _ = analysis_broker.enqueue(state, discovery, now="2026-08-24T20:00:02Z")
        updated, batch, _ = analysis_dispatcher.claim_batch(
            state, dispatcher_id="old-main", now="2026-08-24T20:01:00Z",
            max_claims=4, max_in_flight=4, allowed_components={"omega.discovery"},
        )
        self.assertEqual(1, batch["claimedCount"])
        self.assertEqual("omega.discovery", batch["claims"][0]["componentId"])
        sigma_item = next(item for item in updated["items"] if item["requestId"] == "sigma-request")
        self.assertEqual("queued", sigma_item["state"])

    def test_new_main_runner_can_claim_sigmascope_but_component_limit_is_one(self) -> None:
        state = analysis_broker.empty_state(now="2026-08-24T20:00:00Z")
        for index in range(2):
            request = {
                "requestId": f"sigma-{index}",
                "observation": "managedCallSites",
                "subject": {"type": "variant", "variantId": 40 + index},
                "reason": f"Need managed call sites {index}",
                "priority": 800 - index,
                "requestedAtUtc": f"2026-08-24T20:00:0{index + 1}Z",
            }
            state, resolution = analysis_broker.enqueue(state, request)
            self.assertTrue(resolution["dispatchable"])
        updated, batch, _ = analysis_dispatcher.claim_batch(
            state, dispatcher_id="new-main", now="2026-08-24T20:01:00Z",
            max_claims=4, max_in_flight=4, allowed_components={"omega.sigmascope"},
        )
        self.assertEqual(1, batch["claimedCount"])
        self.assertEqual("omega.sigmascope", batch["claims"][0]["componentId"])
        self.assertEqual(1, sum(1 for item in updated["items"] if item["state"] == "running"))
        self.assertEqual(1, sum(1 for item in updated["items"] if item["state"] == "queued"))

    def test_non_dispatchable_requested_work_is_not_claimed(self) -> None:
        request = {
            "observation": "sourceArtifactBuildProof",
            "subject": {"type": "source", "sourceRepository": "https://github.com/example/plugin", "sourceCommit": "abc", "artifactSha256": "c" * 64},
            "reason": "Need build proof",
            "requestedAtUtc": "2026-08-24T20:00:00Z",
        }
        state, _ = analysis_broker.enqueue(analysis_broker.empty_state(), request, now="2026-08-24T20:00:01Z")
        updated, claim, _ = analysis_dispatcher.claim_next(
            state, dispatcher_id="main-dispatcher", now="2026-08-24T20:01:00Z"
        )
        self.assertIsNone(claim)
        self.assertEqual("requested", updated["items"][0]["state"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import sys

import common

ORCHESTRATION = common.ROOT / "tools" / "orchestration"
if str(ORCHESTRATION) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATION))
import work_queue  # noqa: E402
import reconcile_work  # noqa: E402


class WorkQueueTests(unittest.TestCase):
    def test_enqueue_is_idempotent_for_same_subject_and_required_revision(self) -> None:
        queue = work_queue.new_queue("threat-intelligence", "omega.sigmascope.threat-intelligence", now="2026-08-25T20:00:00Z")
        queue, first, created = work_queue.enqueue(
            queue,
            kind="refresh-threat-intelligence",
            subject={"type": "endpoint-inventory"},
            reason=["ttl"],
            priority=450,
            required_revision="cadence-v1-a",
            now="2026-08-25T20:00:00Z",
        )
        self.assertTrue(created)
        queue2, second, created2 = work_queue.enqueue(
            queue,
            kind="refresh-threat-intelligence",
            subject={"type": "endpoint-inventory"},
            reason=["other-reason"],
            priority=900,
            required_revision="cadence-v1-a",
            now="2026-08-25T20:01:00Z",
        )
        self.assertFalse(created2)
        self.assertEqual(first["workId"], second["workId"])
        self.assertEqual(len(queue2["items"]), 1)

    def test_claim_and_settle_retry_then_complete(self) -> None:
        queue = work_queue.new_queue("catalog-discovery", "omega.catalog.discovery", now="2026-08-25T20:00:00Z")
        queue, item, _ = work_queue.enqueue(
            queue, kind="refresh", subject={"type": "catalog"}, reason=["due"], priority=300,
            required_revision="cadence-v1-x", now="2026-08-25T20:00:00Z",
        )
        queue, claim = work_queue.claim(queue, owner="worker-a", lease_seconds=600, now="2026-08-25T20:01:00Z")
        self.assertIsNotNone(claim)
        self.assertEqual(claim["state"], "leased")
        queue, retried = work_queue.settle(
            queue, work_id=item["workId"], claim_token=claim["lease"]["claimToken"], outcome="retry",
            reason="temporary upstream failure", retry_after_seconds=300, now="2026-08-25T20:02:00Z",
        )
        self.assertEqual(retried["state"], "pending")
        queue, none = work_queue.claim(queue, owner="worker-b", now="2026-08-25T20:04:00Z")
        self.assertIsNone(none)
        queue, claim2 = work_queue.claim(queue, owner="worker-b", now="2026-08-25T20:08:00Z")
        self.assertIsNotNone(claim2)
        queue, done = work_queue.settle(
            queue, work_id=item["workId"], claim_token=claim2["lease"]["claimToken"], outcome="complete",
            result_revision="result-v1-a", result_sha256="a" * 64, now="2026-08-25T20:09:00Z",
        )
        self.assertEqual(done["state"], "completed")
        self.assertEqual(done["attempts"], 2)
        self.assertEqual(queue["counts"]["completed"], 1)

    def test_expired_lease_is_recovered(self) -> None:
        queue = work_queue.new_queue("q", "component", now="2026-08-25T20:00:00Z")
        queue, _, _ = work_queue.enqueue(queue, kind="k", subject={"type": "catalog"}, reason=["due"], priority=1, required_revision="r", now="2026-08-25T20:00:00Z")
        queue, claim = work_queue.claim(queue, owner="worker", lease_seconds=60, now="2026-08-25T20:00:00Z")
        self.assertIsNotNone(claim)
        queue, recovered = work_queue.recover_expired(queue, now="2026-08-25T20:02:00Z")
        self.assertEqual(recovered, 1)
        self.assertEqual(queue["items"][0]["state"], "pending")
        self.assertEqual(queue["items"][0]["settlement"]["outcome"], "lease-expired")

    def test_reconciler_creates_one_item_per_cadence_bucket_and_never_requests_client_build(self) -> None:
        policy = {
            "schema": "omega.orchestration-policy.v1",
            "version": 1,
            "queues": [{
                "queueId": "threat-intelligence", "component": "omega.threat-intelligence",
                "kind": "refresh-threat-intelligence", "cadenceSeconds": 14400, "priority": 450,
                "subject": {"type": "endpoint-inventory"}, "reason": ["ttl"],
            }],
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first_root = root / "first"
            first = reconcile_work.reconcile(policy=policy, previous_root=None, output_root=first_root, now="2026-08-25T20:01:00Z")
            self.assertFalse(first["clientDatabaseBuildRequested"])
            self.assertFalse(first["securityAuthority"])
            self.assertEqual(first["createdWorkItems"], 1)
            second_root = root / "second"
            second = reconcile_work.reconcile(policy=policy, previous_root=first_root, output_root=second_root, now="2026-08-25T23:59:00Z")
            self.assertEqual(second["createdWorkItems"], 0)
            third_root = root / "third"
            third = reconcile_work.reconcile(policy=policy, previous_root=second_root, output_root=third_root, now="2026-08-26T00:01:00Z")
            self.assertEqual(third["createdWorkItems"], 1)
            queue = json.loads((third_root / "queues" / "threat-intelligence.json").read_text())
            self.assertEqual(len(queue["items"]), 2)

    def test_policy_contains_no_automatic_catalog_freeze(self) -> None:
        policy = json.loads((common.ROOT / "security-definitions" / "orchestration" / "work-policy.json").read_text(encoding="utf-8"))
        value = reconcile_work.validate_policy(policy)
        self.assertGreaterEqual(len(value["queues"]), 6)
        self.assertNotIn("catalog-freeze", {row["queueId"] for row in value["queues"]})
        self.assertTrue(any(row["queueId"] == "threat-intelligence" and row["cadenceSeconds"] == 14400 for row in value["queues"]))


if __name__ == "__main__":
    unittest.main()

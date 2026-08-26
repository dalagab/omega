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
import work_result  # noqa: E402
import reconcile_work  # noqa: E402


class WorkResultTests(unittest.TestCase):
    def leased_item(self, *, queue_id: str = "lane", component: str = "omega.catalog"):
        queue = work_queue.new_queue(queue_id, component, now="2026-08-26T06:00:00Z")
        queue, item, _ = work_queue.enqueue(
            queue, kind="refresh", subject={"type": "fixture"}, reason=["due"], priority=100,
            required_revision="cadence-v1-fixture", now="2026-08-26T06:00:00Z",
        )
        queue, claim = work_queue.claim(queue, owner="omega.worker.fixture", lease_seconds=3600, now="2026-08-26T06:01:00Z")
        self.assertIsNotNone(claim)
        return queue, claim

    def test_result_reproduces_and_detects_payload_tampering(self) -> None:
        _queue, claim = self.leased_item()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "payload.json").write_text('{"ok":true}\n', encoding="utf-8")
            result = work_result.build_result(
                queue_id="lane", item=claim, root=root, files=["payload.json"], payload_revision="payload-v1",
                worker_image="ghcr.io/dalagab/omega-fixture@sha256:" + "a" * 64,
            )
            self.assertEqual("ghcr.io/dalagab/omega-fixture@sha256:" + "a" * 64, result["execution"]["workerImage"])
            (root / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            valid = work_result.validate_result(root, expected_queue_id="lane", expected_work_id=claim["workId"], expected_owner="omega.worker.fixture", expected_claim_token=claim["lease"]["claimToken"])
            self.assertEqual(result["resultRevision"], valid["resultRevision"])
            (root / "payload.json").write_text('{"ok":false}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not reproduce"):
                work_result.validate_result(root)

    def test_result_rejects_mutable_worker_image_tag(self) -> None:
        _queue, claim = self.leased_item()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "payload.json").write_text('{}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "immutable digest reference"):
                work_result.build_result(
                    queue_id="lane", item=claim, root=root, files=["payload.json"],
                    worker_image="ghcr.io/dalagab/omega-fixture:latest",
                )

    def test_reconciler_settles_exact_lease_result(self) -> None:
        policy = {
            "schema": "omega.orchestration-policy.v1", "version": 9,
            "queues": [{
                "queueId": "lane", "component": "omega.catalog", "kind": "refresh",
                "cadenceSeconds": 86400, "priority": 100, "subject": {"type": "fixture"}, "reason": ["due"],
                "consumer": {"implemented": True, "leaseOwner": "omega.worker.fixture", "workflow": "fixture.yml", "resultBranch": "fixture-state", "leaseSeconds": 3600},
            }],
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first_root = root / "first"
            first = reconcile_work.reconcile(policy=policy, previous_root=None, results_root=None, output_root=first_root, now="2026-08-26T06:00:00Z")
            self.assertEqual(1, first["claimedWorkItems"])
            queue = work_queue.validate_queue(json.loads((first_root / "queues" / "lane.json").read_text()))
            claim = next(item for item in queue["items"] if item["state"] == "leased")
            lane = root / "results" / "lane"; lane.mkdir(parents=True)
            (lane / "payload.json").write_text('{"fixture":1}\n')
            result = work_result.build_result(queue_id="lane", item=claim, root=lane, files=["payload.json"])
            (lane / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
            second_root = root / "second"
            second = reconcile_work.reconcile(policy=policy, previous_root=first_root, results_root=root / "results", output_root=second_root, now="2026-08-26T06:05:00Z")
            self.assertEqual(1, second["settledWorkItems"])
            queue2 = work_queue.validate_queue(json.loads((second_root / "queues" / "lane.json").read_text()))
            self.assertEqual("completed", queue2["items"][-1]["state"])
            self.assertEqual(result["resultRevision"], queue2["items"][-1]["settlement"]["resultRevision"])

    def test_prerequisite_queue_is_not_leased_until_dependency_settles(self) -> None:
        policy = {
            "schema": "omega.orchestration-policy.v1", "version": 1,
            "queues": [
                {"queueId": "a", "component": "omega.catalog", "kind": "a", "cadenceSeconds": 86400, "priority": 100, "subject": {"type": "a"}, "reason": ["due"], "consumer": {"implemented": True, "leaseOwner": "worker-a", "workflow": "a.yml", "resultBranch": "a-state", "leaseSeconds": 3600}},
                {"queueId": "b", "component": "omega.catalog", "kind": "b", "cadenceSeconds": 86400, "priority": 100, "subject": {"type": "b"}, "reason": ["due"], "prerequisites": ["a"], "consumer": {"implemented": True, "leaseOwner": "worker-b", "workflow": "b.yml", "resultBranch": "b-state", "leaseSeconds": 3600}},
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); first=root/'first'
            reconcile_work.reconcile(policy=policy, previous_root=None, results_root=None, output_root=first, now='2026-08-26T06:00:00Z')
            qa=work_queue.validate_queue(json.loads((first/'queues/a.json').read_text())); qb=work_queue.validate_queue(json.loads((first/'queues/b.json').read_text()))
            self.assertEqual(1, qa['counts']['leased']); self.assertEqual(1, qb['counts']['pending']); self.assertEqual(0, qb['counts']['leased'])
            claim=next(i for i in qa['items'] if i['state']=='leased')
            lane=root/'results/a'; lane.mkdir(parents=True); (lane/'payload.json').write_text('{}\n')
            r=work_result.build_result(queue_id='a',item=claim,root=lane,files=['payload.json']); (lane/'result.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
            second=root/'second'; reconcile_work.reconcile(policy=policy,previous_root=first,results_root=root/'results',output_root=second,now='2026-08-26T06:05:00Z')
            qb2=work_queue.validate_queue(json.loads((second/'queues/b.json').read_text())); self.assertEqual(1,qb2['counts']['leased'])


if __name__ == "__main__":
    unittest.main()

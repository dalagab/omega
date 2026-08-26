from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.orchestration import work_state_readiness as readiness


class WorkStateReadinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({"schema": "omega.orchestration-policy.v1", "version": 1, "queues": []}))

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def policy_value():
        def queue(queue_id):
            return {
                "queueId": queue_id,
                "component": "component-x",
                "kind": "collect",
                "cadenceSeconds": 3600,
                "priority": 10,
                "subject": {"scope": "all"},
                "reason": ["test"],
                "prerequisites": [],
                "consumer": {
                    "implemented": True,
                    "leaseOwner": f"owner.{queue_id}",
                    "workflow": f"{queue_id}.yml",
                    "resultBranch": f"{queue_id}-state",
                    "leaseSeconds": 1800,
                },
            }
        return {"schema": "omega.orchestration-policy.v1", "version": 1, "queues": [queue("one"), queue("two")]}

    def write_queues(self, states):
        qdir = self.root / "queues"
        qdir.mkdir(exist_ok=True)
        descriptors = []
        for queue_id, state in states.items():
            path = qdir / f"{queue_id}.json"
            payload = {
                "queueId": queue_id,
                "items": [{"workId": f"work-{queue_id}", "createdAtUtc": "2026-08-26T00:00:00Z", "state": state}],
            }
            path.write_text(json.dumps(payload))
            descriptors.append({"queueId": queue_id, "path": f"queues/{queue_id}.json"})
        return descriptors

    def test_completed_implemented_queues_are_ready(self):
        descriptors = self.write_queues({"one": "completed", "two": "completed"})
        with mock.patch.object(readiness.reconcile_work, "validate_work_state", return_value={"workStateRevision": "rev", "queues": descriptors}), \
             mock.patch.object(readiness.reconcile_work, "validate_policy", return_value=self.policy_value()), \
             mock.patch.object(readiness.work_queue, "validate_queue", side_effect=lambda value: value):
            code, report = readiness.evaluate(work_state=self.root, policy_path=self.policy)
        self.assertEqual(readiness.READY, code)
        self.assertTrue(report["ready"])

    def test_pending_or_leased_queues_wait(self):
        descriptors = self.write_queues({"one": "completed", "two": "leased"})
        with mock.patch.object(readiness.reconcile_work, "validate_work_state", return_value={"workStateRevision": "rev", "queues": descriptors}), \
             mock.patch.object(readiness.reconcile_work, "validate_policy", return_value=self.policy_value()), \
             mock.patch.object(readiness.work_queue, "validate_queue", side_effect=lambda value: value):
            code, report = readiness.evaluate(work_state=self.root, policy_path=self.policy)
        self.assertEqual(readiness.WAITING, code)
        self.assertFalse(report["ready"])
        self.assertFalse(report["terminal"])

    def test_blocked_or_terminal_queue_fails_closed(self):
        descriptors = self.write_queues({"one": "completed", "two": "blocked"})
        with mock.patch.object(readiness.reconcile_work, "validate_work_state", return_value={"workStateRevision": "rev", "queues": descriptors}), \
             mock.patch.object(readiness.reconcile_work, "validate_policy", return_value=self.policy_value()), \
             mock.patch.object(readiness.work_queue, "validate_queue", side_effect=lambda value: value):
            code, report = readiness.evaluate(work_state=self.root, policy_path=self.policy)
        self.assertEqual(readiness.TERMINAL, code)
        self.assertTrue(report["terminal"])


if __name__ == "__main__":
    unittest.main()

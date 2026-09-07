from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import omega_actions_telemetry as telemetry
import sigmascope_worker_batch


class OmegaActionsProducerTelemetryTests(unittest.TestCase):
    def test_helper_emits_consumer_contract_and_redacts_credentials(self):
        stream = io.StringIO()
        payload = telemetry.emit_event(
            "scan.progress",
            stream=stream,
            component="sigmascope",
            message="token=github_pat_abcdefghijklmnopqrstuvwxyz123456",
            worker={"roleId": "sigmascope", "state": "scanning"},
            subject={"variantId": 42, "internalName": "Example.Plugin", "unknown": "discard"},
            progress={"current": 2, "total": 4, "unit": "stages"},
        )
        self.assertEqual(telemetry.SCHEMA, payload["schema"])
        self.assertEqual(50.0, payload["progress"]["percent"])
        self.assertNotIn("github_pat_", stream.getvalue())
        self.assertNotIn("unknown", payload["subject"])

    def test_planned_selector_emits_exact_queue_subject_before_scan(self):
        captured = []
        original = sigmascope_worker_batch.actions_telemetry.emit_event
        sigmascope_worker_batch.actions_telemetry.emit_event = lambda event, **fields: captured.append((event, fields)) or {}
        try:
            selector = sigmascope_worker_batch.planned_selector(
                lambda _state, key: {
                    "queueKey": key,
                    "variantId": 8291,
                    "internalName": "Example.Plugin",
                    "version": "1.2.3",
                    "workType": "artifact",
                    "reason": "first-plugin-coverage",
                    "sourceName": "example",
                },
                ["q-1", "q-2"],
            )
            selected = selector({})
        finally:
            sigmascope_worker_batch.actions_telemetry.emit_event = original
        self.assertEqual("q-1", selected["queueKey"])
        self.assertEqual(["queue.claimed", "scan.started"], [row[0] for row in captured])
        self.assertEqual(8291, captured[0][1]["subject"]["variantId"])
        self.assertEqual("Example.Plugin", captured[0][1]["subject"]["internalName"])
        self.assertEqual(1, captured[0][1]["queue"]["remaining"])

    def test_merger_publisher_and_stigma_sources_adopt_contract(self):
        merger = (SECURITY / "sigmascope_result_merger.py").read_text(encoding="utf-8")
        publisher = (SECURITY / "publish_security_evidence_v2.py").read_text(encoding="utf-8")
        stigma = (SECURITY / "stigma_broker_bridge.py").read_text(encoding="utf-8")
        self.assertRegex(merger, r'emit_event\(\s*"bundle\.accepted"')
        self.assertIn("build_plan_with_validated_bundles", merger)
        self.assertNotIn("docs = [sigmascope_result_bundle.validate", merger)
        self.assertRegex(publisher, r'emit_event\(\s*"publication\.started"')
        self.assertRegex(publisher, r'emit_event\(\s*"publication\.completed"')
        self.assertRegex(stigma, r'emit_event\(\s*"analysis\.completed"')


if __name__ == "__main__":
    unittest.main()

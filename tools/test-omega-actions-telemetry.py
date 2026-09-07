from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import omega_actions_telemetry as telemetry


class RiftActionsTelemetryTests(unittest.TestCase):
    def test_runtime_marker_matches_deltascope_contract(self):
        stream = io.StringIO()
        payload = telemetry.emit_event(
            "scan.started",
            stream=stream,
            component="rift",
            worker={"roleId": "rift", "label": "Rift worker", "state": "scanning"},
            subject={"variantId": 8291, "workType": "runtime"},
        )
        self.assertEqual("omega.actions.telemetry.v1", payload["schema"])
        self.assertIn("@@omega ", stream.getvalue())
        self.assertEqual(8291, payload["subject"]["variantId"])

    def test_workflows_emit_selection_execution_bundle_and_completion(self):
        runtime = (TOOLS.parent / ".github" / "workflows" / "rift-runtime.yml").read_text(encoding="utf-8")
        production = (TOOLS.parent / ".github" / "workflows" / "rift.yml").read_text(encoding="utf-8")
        for event in ("plugin.selected", "scan.started", "scan.completed", "bundle.created", "workflow.completed"):
            self.assertIn(event, runtime)
        for event in ("plugin.selected", "scan.started", "scan.completed", "bundle.created", "workflow.completed"):
            self.assertIn(event, production)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_operations_history as history


def _event(*, when: str = "2026-09-08T05:50:00Z", message: str = "ok") -> dict:
    return {
        "schema": "omega.actions.telemetry.v1",
        "event": "scan.progress",
        "emittedAtUtc": when,
        "component": "sigmascope",
        "message": message,
        "subject": {"variantId": 8291, "internalName": "Example.Plugin"},
        "progress": {"current": 3, "total": 10, "unit": "stages"},
        "ignored": {"token": "must-not-persist"},
    }


class OperationsHistoryStoreTests(unittest.TestCase):
    def test_persists_only_sanitized_events_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = history.OperationsHistoryStore("dalagab/omega", Path(tmp))
            row = {
                **_event(message="token=super-secret-value"),
                "runId": 101,
                "runNumber": 88,
                "jobId": 201,
                "jobName": "Artifact worker",
                "runnerName": "sigma-private-03",
                "workflow": "SigmaScope",
                "workflowPath": ".github/workflows/sigmascope.yml",
            }
            store.append_events([row, row])
            events = store.events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["runId"], 101)
            self.assertEqual(events[0]["subject"]["variantId"], 8291)
            self.assertNotIn("ignored", events[0])
            self.assertIn("[REDACTED]", events[0]["message"])

            raw = json.loads(store.path.read_text(encoding="utf-8"))
            self.assertEqual(len(raw["entries"]), 1)
            self.assertNotIn("must-not-persist", store.path.read_text(encoding="utf-8"))
            self.assertNotIn("super-secret-value", store.path.read_text(encoding="utf-8"))

            reopened = history.OperationsHistoryStore("dalagab/omega", Path(tmp))
            self.assertEqual(reopened.events()[0]["jobId"], 201)
            self.assertNotIn("runnerName", reopened.events()[0])

    def test_completed_run_scan_marker_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = history.OperationsHistoryStore("dalagab/omega", Path(tmp))
            self.assertFalse(store.completed_run_scanned(1234))
            store.mark_completed_run_scanned(1234)
            reopened = history.OperationsHistoryStore("dalagab/omega", Path(tmp))
            self.assertTrue(reopened.completed_run_scanned(1234))
            self.assertFalse(reopened.descriptor()["containsRawLogs"])
            self.assertFalse(reopened.descriptor()["containsCredentials"])

    def test_invalid_journal_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = history.OperationsHistoryStore("dalagab/omega", Path(tmp))
            store.root.mkdir(parents=True, exist_ok=True)
            store.path.write_text('{"schema":"wrong","entries":[]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                store.events()


if __name__ == "__main__":
    unittest.main()

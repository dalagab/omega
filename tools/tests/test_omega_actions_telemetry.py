from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import omega_actions_telemetry as telemetry


class OmegaActionsTelemetryTests(unittest.TestCase):
    def test_emit_and_parse_round_trip(self):
        stream = io.StringIO()
        emitted = telemetry.emit_event(
            "scan.started",
            stream=stream,
            component="sigmascope",
            worker={"roleId": "sigmascope", "label": "SigmaScope worker", "state": "scanning"},
            subject={"variantId": 8291, "internalName": "Example.Plugin", "workType": "artifact"},
            queue={"reason": "first-plugin-coverage", "remaining": 1284},
        )
        self.assertEqual(telemetry.SCHEMA, emitted["schema"])
        parsed = telemetry.parse_log("prefix\n" + stream.getvalue())
        self.assertEqual(1, parsed["eventCount"])
        event = parsed["events"][0]
        self.assertEqual("scan.started", event["event"])
        self.assertEqual(8291, event["subject"]["variantId"])
        self.assertEqual(1284, event["queue"]["remaining"])

    def test_unknown_fields_are_not_propagated(self):
        event = telemetry.sanitize_event({
            "schema": telemetry.SCHEMA,
            "event": "queue.progress",
            "component": "sigmascope",
            "environment": {"GITHUB_TOKEN": "secret"},
            "worker": {"roleId": "sigmascope", "password": "nope"},
        })
        self.assertNotIn("environment", event)
        self.assertNotIn("password", event["worker"])

    def test_obvious_credentials_are_redacted_from_allowed_strings(self):
        event = telemetry.sanitize_event({
            "schema": telemetry.SCHEMA,
            "event": "workflow.progress",
            "message": "Authorization: Bearer github_pat_abcdefghijklmnopqrstuvwxyz0123456789",
        })
        self.assertNotIn("github_pat_", event["message"])
        self.assertIn("[REDACTED]", event["message"])

    def test_unknown_event_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported telemetry event"):
            telemetry.sanitize_event({"schema": telemetry.SCHEMA, "event": "shell.dump_environment"})

    def test_malformed_markers_are_counted_without_leaking_raw_content(self):
        parsed = telemetry.parse_log(
            '@@omega {"schema":"omega.actions.telemetry.v1","event":"scan.started"}\n'
            '@@omega {"schema": nope}\n'
            '@@omega {"schema":"omega.actions.telemetry.v1","event":"unknown.event","message":"github_pat_secret"}\n'
        )
        self.assertEqual(1, parsed["eventCount"])
        self.assertEqual(2, parsed["invalidCount"])
        self.assertNotIn("github_pat_secret", json.dumps(parsed))

    def test_progress_percentage_is_derived_but_bounded(self):
        event = telemetry.sanitize_event({
            "schema": telemetry.SCHEMA,
            "event": "scan.progress",
            "progress": {"current": 18, "total": 31, "unit": "analysis stages"},
        })
        self.assertEqual(58.1, event["progress"]["percent"])

    def test_parser_accepts_timestamp_prefix_before_marker(self):
        parsed = telemetry.parse_log(
            '2026-09-08T10:01:02.123Z worker stdout @@omega '
            '{"schema":"omega.actions.telemetry.v1","event":"worker.started","component":"rift"}'
        )
        self.assertEqual(1, parsed["eventCount"])
        self.assertEqual("rift", parsed["events"][0]["component"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import common  # noqa: F401

import deltascope_casework
import deltascope_detection_coverage as coverage
import deltascope_operations_correlation as correlation
from deltascope_case_store import LocalInvestigatorCaseStore


class FakeInspector:
    def summary(self):
        return {"generatedAtUtc": "2026-09-08T06:00:00Z", "meta": {}}

    def workbench_system_context(self):
        return {
            "generatedAtUtc": "2026-09-08T06:00:00Z",
            "evidence": {"revisions": {
                "evidenceRevision": "ev-current",
                "definitionsRevision": "defs-current",
                "artifactAnalysisRevision": "artifact-current",
                "sourceAnalysisRevision": "source-current",
                "ruleSetRevision": "rules-current",
            }},
            "source": {},
            "queue": {"available": True, "summary": {}},
        }

    def definition_provenance(self):
        return {
            "available": True,
            "activeRules": [{
                "active": True,
                "ruleId": "network.rule",
                "packId": "core",
                "kind": "observation",
                "requires": ["networkEndpoints"],
            }],
        }

    def plugin_detail(self, variant_id: int):
        if variant_id != 8291:
            raise KeyError(f"Unknown variant_id {variant_id}")
        return {
            "identity": {
                "variant_id": 8291,
                "plugin_id": 42,
                "canonical_name": "Example Plugin",
                "internal_name": "Example.Plugin",
                "assembly_version": "1.2.3",
                "scan_status": "complete",
                "scanned_at_utc": "2026-09-08T05:50:00Z",
                "source_available": 1,
                "report_json": (
                    '{"artifactAnalysisRevision":"artifact-current",'
                    '"sourceAnalysisRevision":"source-current",'
                    '"scanProvenance":{}}'
                ),
            },
        }


class DeltaScopeOperationsCorrelationTests(unittest.TestCase):
    def test_activity_correlation_targets_exact_variant(self):
        event = {
            "schema": "omega.actions.telemetry.v1",
            "event": "scan.progress",
            "emittedAtUtc": "2026-09-08T05:55:00Z",
            "component": "sigmascope",
            "stage": "managed analysis",
            "runId": 101,
            "runNumber": 88,
            "jobId": 201,
            "subject": {
                "pluginId": 42,
                "variantId": 8291,
                "internalName": "Example.Plugin",
                "version": "1.2.3",
            },
        }
        payload = correlation.correlate_activity({
            "timeline": [event],
            "currentWork": [{
                "runId": 101,
                "jobId": 201,
                "event": "scan.progress",
                "telemetrySource": "structured",
                "subject": dict(event["subject"]),
            }],
        })
        correlated = payload["timeline"][0]["correlation"]
        self.assertEqual(8291, correlated["variantId"])
        self.assertEqual(42, correlated["pluginId"])
        self.assertTrue(correlated["targets"]["asset"])
        self.assertTrue(correlated["targets"]["detectionCoverage"])
        self.assertTrue(correlated["targets"]["evidence"])
        self.assertTrue(correlated["targets"]["casework"])
        self.assertEqual(
            correlated["correlationId"],
            payload["currentWork"][0]["correlation"]["correlationId"],
        )
        self.assertNotIn("message", correlated)
        self.assertFalse(correlated["securityAuthority"])

    def test_variant_coverage_is_exact_to_requested_subject(self):
        payload = coverage.project_variant_coverage(FakeInspector(), 8291)
        self.assertEqual(coverage.VARIANT_SCHEMA, payload["schema"])
        self.assertEqual(8291, payload["identity"]["variantId"])
        self.assertEqual(42, payload["identity"]["pluginId"])
        self.assertGreater(payload["summary"]["current"], 0)
        self.assertTrue(all(row["targetVariants"] in {0, 1} for row in payload["collections"]))
        self.assertFalse(any(
            int(gap.get("variantId") or 0) not in {0, 8291}
            for row in payload["collections"]
            for gap in row.get("gapPreview") or []
        ))
        network = next(row for row in payload["collections"] if row["collection"] == "networkEndpoints")
        self.assertEqual("current", network["variantState"])
        self.assertEqual("network.rule", network["rules"][0]["ruleId"])
        with self.assertRaises(ValueError):
            coverage.project_variant_coverage(FakeInspector(), 9999)

    def test_operations_event_is_local_casework_only(self):
        with tempfile.TemporaryDirectory() as td:
            store = LocalInvestigatorCaseStore(Path(td))
            case = store.create_case("Operations follow-up")
            pinned = store.add_item(
                case["caseId"],
                kind="operations-event",
                label="Example.Plugin · scan.progress",
                reference={
                    "operationsEventId": "operation-0123456789abcdef01234567",
                    "runId": 101,
                    "runNumber": 88,
                    "jobId": 201,
                    "event": "scan.progress",
                    "emittedAtUtc": "2026-09-08T05:55:00Z",
                    "component": "sigmascope",
                    "stage": "managed analysis",
                    "variantId": 8291,
                    "pluginId": 42,
                    "internalName": "Example.Plugin",
                    "version": "1.2.3",
                    "token": "must-not-persist",
                },
            )
            self.assertTrue(pinned["saved"])
            self.assertNotIn("token", pinned["item"]["reference"])
            projected = deltascope_casework.project_casework(pinned["case"], object())
            item = projected["items"][0]
            self.assertEqual("retained", item["state"])
            self.assertFalse(item["securityAuthority"])
            operation = next(row for row in projected["timeline"] if row["kind"] == "operations-event")
            self.assertEqual("2026-09-08T05:55:00Z", operation["atUtc"])
            self.assertIn("scan.progress", operation["detail"])

    def test_browser_extension_exposes_all_correlation_actions(self):
        self.assertIn("data-operation-target=asset", correlation._CORRELATION_JS)
        self.assertIn("data-operation-target=coverage", correlation._CORRELATION_JS)
        self.assertIn("data-operation-target=evidence", correlation._CORRELATION_JS)
        self.assertIn("operations-event", correlation._CORRELATION_JS)
        self.assertIn("/api/operations/variant-coverage", correlation._CORRELATION_JS)


if __name__ == "__main__":
    unittest.main()

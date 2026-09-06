from __future__ import annotations

import io
import json
import sys
import threading
import unittest
import zipfile
from pathlib import Path

SECURITY = Path(__file__).resolve().parents[1] / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_scan_queue
import deltascope_scan_report as report


class FakeClient:
    def __init__(self, authenticated: bool = False) -> None:
        self.authenticated = authenticated
        self.calls = 0

    def access_status(self):
        return {"tokenConfigured": self.authenticated, "statusMode": "authenticated" if self.authenticated else "public"}


class _Response(io.BytesIO):
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


class AcquisitionClient:
    repository = "dalagab/omega"
    def __init__(self, archive: bytes) -> None:
        self.archive = archive
        self._lock = threading.RLock()
        self._workflow_cache = {}
        self.requested_urls = []
        self.log_jobs = []
    def access_status(self):
        return {"tokenConfigured": True, "statusMode": "authenticated"}
    def _headers(self, *, accept="application/vnd.github+json"):
        return {"Accept": accept, "Authorization": "Bearer github_pat_private"}
    def _request_json(self, url, maximum=None):
        self.requested_urls.append(url)
        return {"workflow_runs": [{
            "id": 123, "run_number": 34000001, "name": "Omega SigmaScope · production parallel queue drain",
            "path": ".github/workflows/sigmascope-parallel-drain.yml", "status": "in_progress", "conclusion": None,
            "created_at": "2026-09-06T08:00:00Z", "updated_at": "2026-09-06T08:10:00Z",
            "html_url": "https://github.com/dalagab/omega/actions/runs/123",
        }]}
    def _request_jobs(self, run_id):
        return [
            {"id": 101, "name": "Scan updates slot 0 (1 exact queue keys)", "status": "in_progress", "conclusion": None, "started_at": "2026-09-06T08:00:00Z", "html_url": "https://github.com/dalagab/omega/actions/runs/123/job/101"},
            {"id": 102, "name": "One-writer publish merged Evidence and deferred security state", "status": "completed", "conclusion": "success", "started_at": "2026-09-06T08:00:00Z", "completed_at": "2026-09-06T08:05:00Z", "html_url": "https://github.com/dalagab/omega/actions/runs/123/job/102"},
        ]
    def _request_artifacts(self, run_id):
        return [
            {"id": 1, "name": "unrelated-build-output", "size_in_bytes": 20, "archive_download_url": "https://api.github.com/repos/dalagab/omega/actions/artifacts/1/zip"},
            {"id": 2, "name": "omega-sigmascope-drain-plan", "size_in_bytes": len(self.archive), "archive_download_url": "https://api.github.com/repos/dalagab/omega/actions/artifacts/2/zip"},
        ]
    def _opener(self, request, timeout=0):
        self.requested_urls.append(request.full_url)
        if not request.full_url.endswith('/artifacts/2/zip'):
            raise AssertionError('attempted to download a non-allow-listed artifact')
        return _Response(self.archive)
    def _request_job_log(self, job_id):
        self.log_jobs.append(job_id)
        return "Stale parallel candidate discarded because authoritative Evidence moved."


class FakeInspector:
    def __init__(self, *, scan_id: int = 10, queue: bool = True, historical: bool = False) -> None:
        self.scan_id = scan_id
        self.queue = queue
        self.historical = historical

    def plugin_detail(self, variant_id: int):
        return {
            "identity": {
                "canonical_name": "Example Plugin", "internal_name": "ExamplePlugin",
                "plugin_id": 7, "variant_id": variant_id, "assembly_version": "1.4.2",
                "dalamud_api_level": 13, "artifact_sha256": "a" * 64,
                "artifact_channel": "stable", "scan_id": self.scan_id,
                "scan_status": "complete", "scanned_at_utc": "2026-09-05T06:32:00Z",
                "scanner_version": "sigmascope-test", "highest_severity": "high",
                "source_name": "Example source", "source_url": "https://github.com/example/plugin",
            },
            "snapshotKind": "current",
            "variantPath": "variants/42.json",
            "artifactIdentity": {"sha256": "a" * 64},
            "sourceCoverage": {
                "artifactAvailable": True, "sourceCodeAvailable": True,
                "sourceToBinaryVerified": True, "repository": "https://github.com/example/plugin",
                "attributionConfidence": 95,
            },
            "sourceProvenance": {"sourceToBinaryVerified": True},
            "sourceArtifactComparison": {"state": "match"},
            "networkEndpoints": [{"host": "api.example.invalid", "purpose": "update check"}],
            "advisories": [{"id": "OSV-TEST", "severity": "informational", "summary": "Test advisory"}],
            "secondarySecurity": {"engines": [{"engine": "YARA", "status": "complete", "matches": []}]},
            "researcher": {
                "findingCounts": {"critical": 0, "high": 1, "caution": 0, "informational": 0},
                "findings": [{
                    "findingId": "f-1", "ruleId": "network.http-client", "severity": "high",
                    "title": "Outbound HTTPS capability", "description": "The package can make outbound HTTPS requests.",
                    "reason": "HttpClient call retained", "evidence": {"call": "System.Net.Http.HttpClient.SendAsync"},
                    "origin": "artifact",
                }],
                "automationCapabilities": [],
            },
            "datasetCatalog": [{"name": "dependencies", "records": 2}, {"name": "ipc", "records": 1}],
        }

    def summary(self):
        return {
            "counts": {"variants": 1},
            "revisions": {
                "evidenceRevision": "evidence-r1", "definitionsRevision": "defs-r1",
                "artifactAnalysisRevision": "artifact-r1", "sourceAnalysisRevision": "source-r1",
                "ruleSetRevision": "rules-r1",
            },
        }

    def scan_queue_state(self):
        if not self.queue:
            return {"selectionPolicy": "coverage-first-v1", "items": {}}
        return {
            "selectionPolicy": "coverage-first-v1",
            "items": {
                "artifact:42": {
                    "queueKey": "artifact:42", "variantId": 42, "pluginId": 7,
                    "workType": "artifact", "state": "pending", "attemptCount": 0,
                    "currentScanId": 10, "currentScannedAtUtc": "2026-09-05T06:32:00Z",
                    "primaryReason": "artifact_version_changed", "reasons": ["artifact_version_changed"],
                }
            },
        }

    def variant_snapshots(self, variant_id: int):
        if not self.historical:
            return [{"snapshotKind": "current", "variantId": variant_id, "variantPath": "variants/42.json"}]
        return [
            {"snapshotKind": "current", "variantId": variant_id, "variantPath": "variants/42.json"},
            {"snapshotKind": "superseded", "variantId": variant_id, "variantPath": "archive/42-old.json"},
        ]

    def snapshot_detail(self, path: str):
        detail = self.plugin_detail(42)
        detail["identity"] = dict(detail["identity"])
        detail["identity"]["artifact_sha256"] = "b" * 64
        detail["identity"]["scan_id"] = 9
        detail["snapshotKind"] = "superseded"
        return detail

    def workbench_observation_rows(self, variant_id: int, per_collection_limit: int = 40):
        return {"networkEndpoints": [{"host": "api.example.invalid"}]}

    def srl_projection_state(self, variant_id: int):
        return {"available": True, "projection": {"matchedRuleIds": ["network.http-client"], "findings": []}}


def make_plan(*, variant_id: int = 42, queue_key: str = "artifact:42", slot: int = 0):
    return {
        "schema": report.PLAN_SCHEMA,
        "authority": report.PLAN_AUTHORITY,
        "queueSeedRevision": "queue-r1", "catalogRevision": "catalog-r1",
        "catalogIdentityEpoch": "epoch-r1", "evidenceRevision": "evidence-r1",
        "evidenceCatalogIdentityEpoch": "epoch-r1", "baselineSecurityRebuild": False,
        "selectionPolicy": "coverage-first-v1", "workerAllocationPolicy": "release-and-baseline-lanes-v1",
        "wave": 12, "workers": 1, "itemsPerWorker": 8, "capacity": 8,
        "assignments": [{
            "queueKey": queue_key, "workType": "artifact", "variantId": variant_id,
            "internalName": "ExamplePlugin", "sourceName": "Example source", "targetFingerprint": "fp",
            "priority": 1, "primaryReason": "artifact_version_changed", "selectionLane": 2,
            "workerLane": "updates", "releaseUpdate": True,
        }],
        "matrix": {"include": [{"slot": slot, "lane": "updates", "queueKeys": [queue_key], "assignmentCount": 1}]},
        "assignmentCount": 1, "activeWorkerCount": 1, "moreParallelEligible": True,
        "serialFallbackRequired": False, "blockedReason": "",
        "queueSummaryBefore": {"eligibleNow": 17, "retryDeferred": 2, "archiveDeferred": 3},
        "planRevision": "sigmascope-drain-plan-v1-test",
    }


def operation(*, worker_status="in_progress", conclusion="", variant_id=42, queue_key="artifact:42"):
    plan = report.validate_drain_plan(make_plan(variant_id=variant_id, queue_key=queue_key))
    jobs = [{
        "jobId": 101, "name": "Scan updates slot 0 (1 exact queue keys)", "status": worker_status,
        "conclusion": conclusion, "startedAtUtc": "2026-09-06T08:00:00Z", "completedAtUtc": "2026-09-06T08:30:00Z" if worker_status == "completed" else "",
        "elapsedSeconds": 1800, "url": "https://github.com/dalagab/omega/actions/runs/123/job/101",
    }]
    return {
        "schema": report.OPERATION_SCHEMA, "available": True, "authenticated": True,
        "readOnly": True, "mutationAuthority": "none", "securityAuthority": False,
        "fetchedAtUtc": "2026-09-06T08:30:00Z",
        "run": {"runId": 123, "runNumber": 34000001, "status": "in_progress", "url": "https://github.com/dalagab/omega/actions/runs/123"},
        "jobs": jobs, "plan": plan, "planAvailable": True,
    }


def zip_with(files):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    return target.getvalue()


class DeltaScopeScanReportTests(unittest.TestCase):
    def test_signed_out_still_projects_published_evidence_without_github(self):
        client = FakeClient(False)
        result = report.project_scan_report(FakeInspector(), client, 42)
        self.assertFalse(result["operation"]["authenticated"])
        self.assertEqual("published-security-evidence-v2", result["securityAuthority"])
        self.assertEqual(10, result["lastPublishedEvidence"]["scanId"])
        self.assertEqual(0, client.calls)

    def test_signed_in_exact_plan_correlation_exposes_worker_without_authority(self):
        result = report.project_scan_report(FakeInspector(), FakeClient(True), 42, operational=operation())
        self.assertEqual("Scanning", result["currentStatus"]["state"])
        self.assertEqual("artifact:42", result["operation"]["assignment"]["queueKey"])
        self.assertEqual(1, result["operation"]["assignment"]["workerAssignmentPosition"])
        self.assertEqual("assignment-position-only", result["operation"]["assignment"]["completionSemantics"])
        self.assertFalse(result["operationalMetadataAuthority"])
        self.assertFalse(result["publicationAuthority"])

    def test_scan_queue_overlay_marks_exact_worker_scanning_and_preserves_published_state(self):
        queue = deltascope_scan_queue.project_scan_queue(FakeInspector().scan_queue_state(), current_variants=1)
        result = report.project_scan_queue_operation(queue, operation())
        row = result["queueItems"][0]
        self.assertEqual("pending", row["state"])
        self.assertEqual("pending", row["publishedQueueState"])
        self.assertEqual("Scanning", row["liveState"])
        self.assertTrue(row["liveOperation"]["correlated"])
        self.assertEqual(0, row["liveOperation"]["slot"])
        self.assertEqual(1, result["operationalOverlay"]["counts"]["Scanning"])
        self.assertEqual("none", result["operationalOverlay"]["mutationAuthority"])
        self.assertFalse(result["operationalOverlay"]["securityAuthority"])

    def test_scan_queue_overlay_never_correlates_by_name_when_identity_differs(self):
        queue = deltascope_scan_queue.project_scan_queue(FakeInspector().scan_queue_state(), current_variants=1)
        result = report.project_scan_queue_operation(queue, operation(variant_id=99))
        row = result["queueItems"][0]
        self.assertEqual("Queued", row["liveState"])
        self.assertFalse(row["liveOperation"]["correlated"])

    def test_scan_queue_overlay_is_unknown_when_live_state_was_not_acquired(self):
        queue = deltascope_scan_queue.project_scan_queue(FakeInspector().scan_queue_state(), current_variants=1)
        op = {
            "schema": report.OPERATION_SCHEMA, "available": False, "authenticated": True,
            "refreshRequired": True, "state": "not-acquired", "notice": "Acquire live state explicitly.",
            "run": {}, "jobs": [], "plan": {}, "planAvailable": False,
        }
        row = report.project_scan_queue_operation(queue, op)["queueItems"][0]
        self.assertEqual("Unknown", row["liveState"])
        self.assertIn("Acquire live state explicitly", row["liveExplanation"])
        self.assertEqual("pending", row["publishedQueueState"])

    def test_scan_queue_overlay_distinguishes_worker_done_from_wave_done(self):
        op = operation(worker_status="completed", conclusion="success")
        op["jobs"].append({
            "jobId": 202, "name": "Scan baseline slot 1 (1 exact queue keys)", "status": "in_progress",
            "conclusion": "", "startedAtUtc": "2026-09-06T08:05:00Z", "completedAtUtc": "",
            "elapsedSeconds": 1500, "url": "https://github.com/dalagab/omega/actions/runs/123/job/202",
        })
        queue = deltascope_scan_queue.project_scan_queue(FakeInspector().scan_queue_state(), current_variants=1)
        row = report.project_scan_queue_operation(queue, op)["queueItems"][0]
        self.assertEqual("Waiting for other workers", row["liveState"])
        self.assertEqual("pending", row["publishedQueueState"])

    def test_exact_queue_key_and_variant_are_both_required(self):
        plan = report.validate_drain_plan(make_plan(variant_id=99))
        self.assertIsNone(report.correlate_plan(plan, "artifact:42", 42))
        self.assertIsNone(report.correlate_plan(plan, "artifact:missing", 99))
        self.assertIsNotNone(report.correlate_plan(plan, "artifact:42", 99))

    def test_worker_completion_does_not_imply_evidence_publication(self):
        result = report.project_scan_report(FakeInspector(scan_id=10), FakeClient(True), 42, operational=operation(worker_status="completed", conclusion="success"))
        self.assertEqual("Worker completed", result["currentStatus"]["state"])
        self.assertFalse(result["mergePublication"]["authoritativeEvidenceAdvanced"])
        self.assertIn("authoritative Evidence has not been published", result["currentStatus"]["explanation"])

    def test_published_evidence_advance_wins_over_completed_worker(self):
        result = report.project_scan_report(FakeInspector(scan_id=11), FakeClient(True), 42, operational=operation(worker_status="completed", conclusion="success"))
        self.assertEqual("Published", result["currentStatus"]["state"])
        self.assertTrue(result["mergePublication"]["authoritativeEvidenceAdvanced"])
        self.assertEqual(11, result["lastPublishedEvidence"]["scanId"])

    def test_queue_reason_explanation_is_deterministic(self):
        result = report.project_scan_report(FakeInspector(), FakeClient(False), 42)
        selected = result["queue"]["selected"]
        self.assertEqual("Plugin version changed", selected["reasonDetails"][0]["label"])
        self.assertIn("artifact version changed", selected["reasonDetails"][0]["explanation"])

    def test_human_summary_is_deterministic_and_has_no_runtime_ai(self):
        inspector = FakeInspector()
        a = report.project_scan_report(inspector, FakeClient(False), 42)
        b = report.project_scan_report(inspector, FakeClient(False), 42)
        self.assertEqual(a["executiveSummary"], b["executiveSummary"])
        self.assertEqual(a["findingReport"], b["findingReport"])
        self.assertFalse(a["runtimeAI"])
        self.assertIn("Outbound HTTPS capability", json.dumps(a["findingReport"]))

    def test_existing_asset_journey_is_reused_and_deep_linked(self):
        result = report.project_scan_report(FakeInspector(), FakeClient(False), 42)
        self.assertEqual("existing-asset-journey", result["journey"]["integration"])
        self.assertFalse(result["journey"]["competingPipeline"])
        self.assertTrue(all(row.get("scanReportSection") for row in result["journey"]["stages"]))

    def test_previous_comparable_evidence_unavailable_is_explicit(self):
        result = report.project_scan_report(FakeInspector(historical=False), FakeClient(False), 42)
        self.assertFalse(result["changesSincePrevious"]["available"])
        self.assertEqual("Previous comparable Evidence unavailable.", result["changesSincePrevious"]["explanation"])

    def test_previous_evidence_uses_existing_semantic_compare(self):
        result = report.project_scan_report(FakeInspector(historical=True), FakeClient(False), 42)
        self.assertTrue(result["changesSincePrevious"]["available"])
        self.assertEqual("Installable artifact changed", result["changesSincePrevious"]["changes"][0]["label"])

    def test_allow_list_rejects_unknown_operational_artifact(self):
        archive = zip_with({"sigmascope-drain-plan.json": json.dumps(make_plan())})
        with self.assertRaisesRegex(ValueError, "not allow-listed"):
            report.parse_operational_artifact("some-other-artifact", archive)

    def test_parser_rejects_oversized_archive(self):
        with self.assertRaisesRegex(ValueError, "exceeded"):
            report.parse_operational_artifact("omega-sigmascope-drain-plan", b"x" * (report.MAX_OPERATIONAL_ARCHIVE_BYTES + 1))

    def test_parser_rejects_unsafe_paths(self):
        archive = zip_with({"../sigmascope-drain-plan.json": json.dumps(make_plan())})
        with self.assertRaisesRegex(ValueError, "unsafe path"):
            report.parse_operational_artifact("omega-sigmascope-drain-plan", archive)

    def test_parser_rejects_oversized_member_even_when_archive_is_small(self):
        archive = zip_with({"sigmascope-drain-plan.json": "x" * (report.MAX_OPERATIONAL_FILE_BYTES + 1)})
        self.assertLess(len(archive), report.MAX_OPERATIONAL_ARCHIVE_BYTES)
        with self.assertRaisesRegex(ValueError, "member exceeded"):
            report.parse_operational_artifact("omega-sigmascope-drain-plan", archive)

    def test_parser_rejects_malformed_planning_json(self):
        archive = zip_with({"sigmascope-drain-plan.json": "{not-json"})
        with self.assertRaisesRegex(ValueError, "malformed"):
            report.parse_operational_artifact("omega-sigmascope-drain-plan", archive)

    def test_parser_accepts_only_current_bounded_plan_schema(self):
        archive = zip_with({"sigmascope-drain-plan.json": json.dumps(make_plan())})
        parsed = report.parse_operational_artifact("omega-sigmascope-drain-plan", archive)
        self.assertEqual(report.PLAN_SCHEMA, parsed["schema"])
        self.assertEqual("artifact:42", parsed["assignments"][0]["queueKey"])

    def test_token_like_input_is_never_reflected_in_report_payload(self):
        op = operation()
        op["token"] = "github_pat_secret_should_never_escape"
        result = report.project_scan_report(FakeInspector(), FakeClient(True), 42, operational=op)
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("github_pat_secret_should_never_escape", encoded)
        self.assertNotIn('"token"', encoded)

    def test_token_like_error_text_is_redacted_before_api_projection(self):
        op = operation()
        op["available"] = False
        op["error"] = "request failed for github_pat_secret_should_never_escape"
        result = report.project_scan_report(FakeInspector(), FakeClient(True), 42, operational=op)
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("github_pat_secret_should_never_escape", encoded)
        self.assertIn("redacted-github-token", encoded)

    def test_ui_patch_registers_scan_report_surface_and_endpoint(self):
        patched = report._patch_html("<html><body><script>function placeholder(){}</script></body></html>")
        self.assertIn("data-research-tab=scan-report", patched)
        self.assertIn("/api/plugin-scan-report", patched)
        self.assertIn("Assignment position only", patched)
        self.assertIn("published Security Evidence v2", patched)
        self.assertIn("queueLiveFilter", patched)
        self.assertIn("Refresh live state", patched)
        self.assertIn("/api/workbench/scan-queue?refresh=1", patched)

    def test_missing_operational_state_does_not_gain_mutation_authority(self):
        result = report.project_scan_report(FakeInspector(queue=False), FakeClient(False), 42)
        self.assertEqual("Published", result["currentStatus"]["state"])
        self.assertEqual("none", result["mutationAuthority"])
        self.assertFalse(result["queueMutationAuthority"])
        self.assertFalse(result["scanExecutionAuthority"])
        self.assertFalse(result["publicationAuthority"])

    def test_explicit_acquisition_downloads_only_allow_listed_planning_artifact(self):
        archive = zip_with({"sigmascope-drain-plan.json": json.dumps(make_plan())})
        client = AcquisitionClient(archive)
        result = report.acquire_sigmascope_operation(client, refresh=True)
        self.assertTrue(result["available"])
        self.assertTrue(result["planAvailable"])
        self.assertEqual("artifact:42", result["plan"]["assignments"][0]["queueKey"] )
        self.assertTrue(any(url.endswith('/artifacts/2/zip') for url in client.requested_urls))
        self.assertFalse(any(url.endswith('/artifacts/1/zip') for url in client.requested_urls))
        self.assertNotIn("github_pat_private", json.dumps(result))

    def test_navigation_acquisition_is_snapshot_only(self):
        archive = zip_with({"sigmascope-drain-plan.json": json.dumps(make_plan())})
        client = AcquisitionClient(archive)
        result = report.acquire_sigmascope_operation(client, refresh=False)
        self.assertTrue(result["refreshRequired"])
        self.assertEqual([], client.requested_urls)

    def test_merge_publication_logs_are_reduced_to_bounded_operational_signals(self):
        archive = zip_with({"sigmascope-drain-plan.json": json.dumps(make_plan())})
        client = AcquisitionClient(archive)
        result = report.acquire_sigmascope_operation(client, refresh=True)
        self.assertEqual([102], client.log_jobs)
        self.assertEqual("stale-candidate-discarded", result["signals"][0]["code"] )
        self.assertNotIn("Stale parallel candidate discarded because", json.dumps(result))

    def test_plan_parser_fails_closed_on_negative_or_oversized_worker_contract(self):
        bad = make_plan(); bad["matrix"]["include"][0]["slot"] = -1
        with self.assertRaisesRegex(ValueError, "matrix slot"):
            report.validate_drain_plan(bad)
        bad = make_plan(); bad["workers"] = report.MAX_PLAN_WORKERS + 1
        with self.assertRaisesRegex(ValueError, "workers"):
            report.validate_drain_plan(bad)

    def test_signed_out_system_health_does_not_invent_live_zeroes(self):
        result = report.project_scan_report(FakeInspector(), FakeClient(False), 42)
        self.assertIsNone(result["systemHealth"]["activeWorkerCount"])
        self.assertIsNone(result["systemHealth"]["immediatelyEligibleCount"])
        self.assertIsNone(result["systemHealth"]["archiveDeferredCount"])



if __name__ == "__main__":
    unittest.main()

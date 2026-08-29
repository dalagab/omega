from __future__ import annotations

import base64
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
CATALOG = ROOT / "tools" / "catalog"
for path in (SECURITY, CATALOG):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import deltascope_0015_compat
import deltascope_operations
import deltascope_workflow_center
import developer_view


class _Response(io.BytesIO):
    def __init__(self, data=b"", status=200):
        super().__init__(data)
        self.status = status
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


class WorkflowCenterTests(unittest.TestCase):
    def test_projection_uses_only_acquired_snapshots(self) -> None:
        calls = []

        def opener(request, timeout=0):
            calls.append(request.full_url)
            raise AssertionError("projection must not perform network I/O")

        client = deltascope_operations.GitHubOperationsClient("dalagab/omega", opener=opener, token="")
        client._workflow_cache[("workflows",)] = (1.0, {
            "schema": "omega.deltascope.github-workflows.v1",
            "available": True,
            "repository": "dalagab/omega",
            "fetchedAtUtc": "2026-08-27T19:00:00Z",
            "workflows": [
                {"id": 10, "name": "Omega Sigmascope continuous worker", "path": ".github/workflows/sigmascope.yml", "state": "active", "url": "https://github.com/dalagab/omega/actions/workflows/10"},
                {"id": 11, "name": "Omega Discovery", "path": ".github/workflows/catalog-discovery.yml", "state": "active", "url": "https://github.com/dalagab/omega/actions/workflows/11"},
            ],
        })
        client._cache = deltascope_operations.project_runs("dalagab/omega", [{
            "id": 42, "run_number": 7, "run_attempt": 1,
            "name": "Omega Sigmascope continuous worker", "path": ".github/workflows/sigmascope.yml",
            "display_title": "scan batch", "event": "workflow_dispatch", "head_branch": "sigmascope", "head_sha": "a" * 40,
            "status": "in_progress", "conclusion": None, "created_at": "2026-08-27T18:59:00Z", "updated_at": "2026-08-27T19:00:00Z",
            "html_url": "https://github.com/dalagab/omega/actions/runs/42",
        }], fetched_at_utc="2026-08-27T19:00:00Z")

        center = deltascope_workflow_center.project_workflow_center(client)
        self.assertEqual([], calls)
        self.assertEqual(2, center["workflowCount"])
        self.assertEqual(1, center["runningCount"])
        by_id = {row["workflowId"]: row for row in center["workflows"]}
        self.assertEqual("Security scanning", by_id[10]["family"])
        self.assertEqual("Catalog & discovery", by_id[11]["family"])
        self.assertEqual("running", by_id[10]["state"])
        self.assertFalse(by_id[10]["detailLoaded"])

    def test_acquire_detail_fetches_definition_history_jobs_artifacts_and_logs_explicitly(self) -> None:
        requests = []
        workflow_source = """name: scan\non:\n  workflow_dispatch:\n    inputs:\n      internal_names:\n        type: string\n        required: false\n""".encode("utf-8")

        def opener(request, timeout=0):
            url = request.full_url
            requests.append((url, request.get_method()))
            if "/actions/workflows?" in url:
                return _Response(json.dumps({"workflows": [{"id": 10, "name": "Omega Sigmascope continuous worker", "path": ".github/workflows/sigmascope.yml", "state": "active", "html_url": "https://github.com/dalagab/omega/actions/workflows/10"}]}).encode())
            if "/contents/.github/workflows/sigmascope.yml" in url:
                return _Response(json.dumps({"encoding": "base64", "content": base64.b64encode(workflow_source).decode()}).encode())
            if "/actions/workflows/sigmascope.yml/runs" in url:
                return _Response(json.dumps({"workflow_runs": [{
                    "id": 42, "run_number": 7, "run_attempt": 1,
                    "name": "Omega Sigmascope continuous worker", "path": ".github/workflows/sigmascope.yml",
                    "display_title": "scan batch", "event": "workflow_dispatch", "head_branch": "sigmascope", "head_sha": "a" * 40,
                    "status": "completed", "conclusion": "success", "created_at": "2026-08-27T18:50:00Z", "updated_at": "2026-08-27T18:55:00Z",
                    "html_url": "https://github.com/dalagab/omega/actions/runs/42",
                }]}).encode())
            if "/actions/runs/42/artifacts" in url:
                return _Response(json.dumps({"artifacts": [{"id": 5, "name": "scan-result", "size_in_bytes": 2048, "expired": False, "created_at": "x", "updated_at": "y"}]}).encode())
            if "/actions/runs/42/jobs" in url:
                return _Response(json.dumps({"jobs": [{"id": 99, "name": "scan", "status": "completed", "conclusion": "success", "started_at": "x", "completed_at": "y", "html_url": "https://github.com/dalagab/omega/actions/runs/42/job/99", "steps": [{"number": 1, "name": "Run scanner", "status": "completed", "conclusion": "success", "started_at": "x", "completed_at": "y"}]}]}).encode())
            if "/actions/jobs/99/logs" in url:
                return _Response(b"scanner output\n")
            raise AssertionError(url)

        client = deltascope_operations.GitHubOperationsClient("dalagab/omega", opener=opener, token="")
        client._workflow_cache[("workflows",)] = (1.0, {
            "schema": "omega.deltascope.github-workflows.v1", "available": True, "repository": "dalagab/omega", "fetchedAtUtc": "x",
            "workflows": [{"id": 10, "name": "Omega Sigmascope continuous worker", "path": ".github/workflows/sigmascope.yml", "state": "active", "url": "https://github.com/dalagab/omega/actions/workflows/10"}],
        })
        client._cache = {"schema": deltascope_operations.SCHEMA, "available": True, "events": [], "components": [], "fetchedAtUtc": "x"}

        before = deltascope_workflow_center.workflow_detail_snapshot(client, 10)
        self.assertFalse(before["history"]["available"])
        self.assertEqual([], requests)
        detail = deltascope_workflow_center.acquire_workflow_detail(client, 10, "sigmascope", history_limit=3, include_logs=True)
        self.assertTrue(detail["form"]["dispatchable"])
        self.assertEqual("internal_names", detail["form"]["inputs"][0]["name"])
        self.assertTrue(detail["history"]["available"])
        run = detail["history"]["runs"][0]
        self.assertEqual("scan-result", run["artifacts"][0]["name"])
        self.assertEqual("Run scanner", run["jobs"][0]["steps"][0]["name"])
        self.assertIn("scanner output", run["jobs"][0]["logPreview"])
        self.assertGreaterEqual(len(requests), 6)

    def test_run_controls_require_known_run_and_explicit_confirmation(self) -> None:
        requests = []

        def opener(request, timeout=0):
            requests.append((request.full_url, request.get_method()))
            return _Response(b"", status=202)

        client = deltascope_operations.GitHubOperationsClient("dalagab/omega", opener=opener, token="github_pat_" + "x" * 32)
        client._cache = deltascope_operations.project_runs("dalagab/omega", [{
            "id": 42, "run_number": 7, "run_attempt": 1, "name": "scan", "path": ".github/workflows/sigmascope.yml",
            "display_title": "scan", "event": "workflow_dispatch", "head_branch": "sigmascope", "head_sha": "a" * 40,
            "status": "in_progress", "conclusion": None, "created_at": "x", "updated_at": "y",
            "html_url": "https://github.com/dalagab/omega/actions/runs/42",
        }])
        with self.assertRaisesRegex(ValueError, "CANCEL"):
            deltascope_workflow_center.run_action(client, 42, "cancel", "")
        with self.assertRaisesRegex(ValueError, "not present"):
            deltascope_workflow_center.run_action(client, 99, "cancel", "CANCEL")
        result = deltascope_workflow_center.run_action(client, 42, "cancel", "CANCEL")
        self.assertTrue(result["accepted"])
        self.assertTrue(result["snapshotStale"])
        self.assertIn("/actions/runs/42/cancel", requests[-1][0])
        self.assertEqual("POST", requests[-1][1])

    def test_html_installs_dedicated_operations_workflow_workspace(self) -> None:
        deltascope_0015_compat.install()
        deltascope_workflow_center.install()
        html = developer_view.HTML
        self.assertIn('id="workbench-workflows"', html)
        self.assertIn("GitHub Workflows", html)
        self.assertIn("Acquire details", html)
        self.assertIn("workflow-center/run-action", html)
        self.assertIn("navigation never", html.lower())
        self.assertIn('data-workflow-id="${String(row.workflowId)}"', html)
        self.assertIn('data-wc-run="${String(run.runId)}"', html)
        self.assertNotIn('data-workflow-id="${fmt(row.workflowId)}"', html)
        self.assertNotIn('data-wc-run="${fmt(run.runId)}"', html)


if __name__ == "__main__":
    unittest.main()

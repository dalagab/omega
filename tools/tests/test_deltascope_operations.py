from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
CATALOG = ROOT / "tools" / "catalog"
for path in (SECURITY, CATALOG):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import deltascope_docs
import deltascope_operations
import developer_view


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


class DeltaScopeOperationsTests(unittest.TestCase):
    def test_actions_projection_groups_components_and_running_work(self) -> None:
        runs = [
            {
                "id": 3, "run_number": 88, "run_attempt": 1,
                "name": "Omega Sigmascope continuous worker",
                "path": ".github/workflows/sigmascope.yml",
                "display_title": "bounded scan batch", "event": "workflow_dispatch",
                "head_branch": "sigmascope", "head_sha": "a" * 40,
                "status": "in_progress", "conclusion": None,
                "created_at": "2026-08-22T15:00:00Z", "updated_at": "2026-08-22T15:02:00Z",
                "html_url": "https://github.com/dalagab/omega/actions/runs/3",
            },
            {
                "id": 2, "run_number": 7, "run_attempt": 1,
                "name": "Omega build", "path": ".github/workflows/build.yml",
                "display_title": "release build", "event": "push",
                "head_branch": "main", "head_sha": "b" * 40,
                "status": "completed", "conclusion": "success",
                "created_at": "2026-08-22T14:00:00Z", "updated_at": "2026-08-22T14:08:00Z",
                "html_url": "https://github.com/dalagab/omega/actions/runs/2",
            },
            {
                "id": 1, "run_number": 6, "run_attempt": 1,
                "name": "Omega security services regression tests", "path": ".github/workflows/regression-tests.yml",
                "display_title": "DeltaScope adjustments", "event": "push",
                "head_branch": "sigmascope", "head_sha": "c" * 40,
                "status": "completed", "conclusion": "failure",
                "created_at": "2026-08-22T13:00:00Z", "updated_at": "2026-08-22T13:08:00Z",
                "html_url": "https://github.com/dalagab/omega/actions/runs/1",
            },
        ]
        projected = deltascope_operations.project_runs("dalagab/omega", runs, fetched_at_utc="2026-08-22T15:03:00Z")
        self.assertTrue(projected["available"])
        self.assertEqual(1, projected["actionsRunning"])
        by_id = {row["componentId"]: row for row in projected["components"]}
        self.assertEqual("running", by_id["sigmascope"]["state"])
        self.assertEqual("healthy", by_id["omega-builds"]["state"])
        self.assertEqual("failed", by_id["security-regression"]["state"])
        self.assertEqual("unknown", by_id["stigma-1"]["state"])
        self.assertFalse(by_id["stigma-1"]["observed"])
        self.assertEqual("bounded scan batch", projected["events"][0]["title"])

    def test_actions_client_is_cached_and_read_only(self) -> None:
        calls = []
        payload = {"workflow_runs": [{
            "id": 1, "run_number": 1, "name": "DeltaScope developer audit", "path": ".github/workflows/deltascope.yml",
            "display_title": "docs", "event": "push", "head_branch": "sigmascope", "head_sha": "d" * 40,
            "status": "completed", "conclusion": "success", "created_at": "2026-08-22T12:00:00Z", "updated_at": "2026-08-22T12:01:00Z",
            "html_url": "https://github.com/dalagab/omega/actions/runs/1",
        }]}

        def opener(request, timeout=0):
            calls.append((request.full_url, timeout, request.get_method()))
            return _Response(json.dumps(payload).encode("utf-8"))

        client = deltascope_operations.GitHubOperationsClient("dalagab/omega", opener=opener, ttl_seconds=60)
        first = client.status()
        second = client.status()
        self.assertEqual(1, len(calls))
        self.assertTrue(first["readOnly"])
        self.assertEqual("none", first["mutationAuthority"])
        self.assertEqual(first["events"], second["events"])
        self.assertEqual("GET", calls[0][2])
        self.assertTrue(first["events"][0]["url"].startswith("https://github.com/"))
        unsafe = dict(payload["workflow_runs"][0], html_url="javascript:alert(1)")
        projected = deltascope_operations.project_runs("dalagab/omega", [unsafe])
        self.assertEqual("", projected["events"][0]["url"])

    def test_workflow_history_reads_bounded_recent_job_step_and_log_data(self) -> None:
        calls = []

        def opener(request, timeout=0):
            url = request.full_url
            calls.append((url, request.get_method()))
            if "/actions/workflows/catalog-builder.yml/runs" in url:
                payload = {"workflow_runs": [{
                    "id": 10, "run_number": 44, "run_attempt": 1, "name": "Omega catalog builder",
                    "path": ".github/workflows/catalog-builder.yml", "display_title": "catalog refresh", "event": "schedule",
                    "head_branch": "sigmascope", "head_sha": "e" * 40, "status": "completed", "conclusion": "success",
                    "created_at": "2026-08-23T18:00:00Z", "updated_at": "2026-08-23T18:05:00Z",
                    "html_url": "https://github.com/dalagab/omega/actions/runs/10",
                }]}
                return _Response(json.dumps(payload).encode("utf-8"))
            if "/actions/runs/10/artifacts" in url:
                payload = {"artifacts": [{"id": 30, "name": "raw-sources", "size_in_bytes": 1234, "expired": False, "created_at": "2026-08-23T18:01:00Z", "updated_at": "2026-08-23T18:01:00Z"}]}
                return _Response(json.dumps(payload).encode("utf-8"))
            if "/actions/runs/10/jobs" in url:
                payload = {"jobs": [{
                    "id": 20, "name": "Discover source feeds", "status": "completed", "conclusion": "success",
                    "started_at": "2026-08-23T18:00:30Z", "completed_at": "2026-08-23T18:01:00Z",
                    "html_url": "https://github.com/dalagab/omega/actions/runs/10/job/20",
                    "steps": [{"number": 1, "name": "Discover curated, Puni.sh and GitHub PluginMaster sources", "status": "completed", "conclusion": "success", "started_at": "", "completed_at": ""}],
                }]}
                return _Response(json.dumps(payload).encode("utf-8"))
            if "/actions/jobs/20/logs" in url:
                return _Response(b"Wrote build/raw-sources.json: 44 source(s) - 7 curated, 8 community, 12 puni.sh, 17 github-search\n")
            raise AssertionError(url)

        client = deltascope_operations.GitHubOperationsClient("dalagab/omega", opener=opener, ttl_seconds=60)
        first = client.workflow_history("catalog-builder.yml", limit=1, include_logs=True)
        second = client.workflow_history("catalog-builder.yml", limit=1, include_logs=True)
        self.assertTrue(first["available"])
        self.assertTrue(first["readOnly"])
        self.assertEqual("none", first["mutationAuthority"])
        self.assertEqual(1, len(first["runs"]))
        self.assertEqual("Discover source feeds", first["runs"][0]["jobs"][0]["name"])
        self.assertIn("44 source(s)", first["runs"][0]["jobs"][0]["logPreview"])
        self.assertEqual("raw-sources", first["runs"][0]["artifacts"][0]["name"])
        self.assertEqual(first, second)
        self.assertTrue(all(method == "GET" for _, method in calls))
        self.assertEqual(4, len(calls))

    def test_workflow_history_can_fetch_a_bounded_recent_log_window_for_trends(self) -> None:
        calls = []
        runs = [
            {
                "id": 11, "run_number": 45, "run_attempt": 1, "name": "Omega catalog builder",
                "path": ".github/workflows/catalog-builder.yml", "display_title": "newer", "event": "schedule",
                "head_branch": "sigmascope", "head_sha": "f" * 40, "status": "completed", "conclusion": "success",
                "created_at": "2026-08-24T18:00:00Z", "updated_at": "2026-08-24T18:05:00Z",
                "html_url": "https://github.com/dalagab/omega/actions/runs/11",
            },
            {
                "id": 10, "run_number": 44, "run_attempt": 1, "name": "Omega catalog builder",
                "path": ".github/workflows/catalog-builder.yml", "display_title": "older", "event": "schedule",
                "head_branch": "sigmascope", "head_sha": "e" * 40, "status": "completed", "conclusion": "success",
                "created_at": "2026-08-23T18:00:00Z", "updated_at": "2026-08-23T18:05:00Z",
                "html_url": "https://github.com/dalagab/omega/actions/runs/10",
            },
        ]

        def opener(request, timeout=0):
            url = request.full_url
            calls.append(url)
            if "/actions/workflows/catalog-builder.yml/runs" in url:
                return _Response(json.dumps({"workflow_runs": runs}).encode("utf-8"))
            if "/artifacts" in url:
                return _Response(b'{"artifacts": []}')
            if "/actions/runs/11/jobs" in url:
                job_id = 21
            elif "/actions/runs/10/jobs" in url:
                job_id = 20
            else:
                job_id = None
            if job_id is not None:
                payload = {"jobs": [{
                    "id": job_id, "name": "Discover source feeds", "status": "completed", "conclusion": "success",
                    "started_at": "2026-08-23T18:00:30Z", "completed_at": "2026-08-23T18:01:00Z",
                    "html_url": f"https://github.com/dalagab/omega/actions/runs/{10 if job_id == 20 else 11}/job/{job_id}",
                    "steps": [{"number": 1, "name": "Discover curated, Puni.sh and GitHub PluginMaster sources", "status": "completed", "conclusion": "success", "started_at": "", "completed_at": ""}],
                }]}
                return _Response(json.dumps(payload).encode("utf-8"))
            if "/actions/jobs/21/logs" in url:
                return _Response(b"newer collector log")
            if "/actions/jobs/20/logs" in url:
                return _Response(b"older collector log")
            raise AssertionError(url)

        client = deltascope_operations.GitHubOperationsClient("dalagab/omega", opener=opener, ttl_seconds=60)
        payload = client.workflow_history(
            "catalog-builder.yml", limit=2, include_logs=True,
            log_job_names={"Discover source feeds"}, log_run_limit=2,
        )
        self.assertEqual(2, len(payload["runs"]))
        self.assertEqual("newer collector log", payload["runs"][0]["jobs"][0]["logPreview"])
        self.assertEqual("older collector log", payload["runs"][1]["jobs"][0]["logPreview"])
        self.assertEqual(2, sum(1 for url in calls if "/logs" in url))

    def test_documentation_catalog_is_allowlisted_and_stigma_first(self) -> None:
        catalog = deltascope_docs.catalog()
        ids = [row["id"] for row in catalog["documents"]]
        self.assertIn("stigma1", ids)
        self.assertIn("rule-author-start", ids)
        document = deltascope_docs.read_document("stigma1")
        self.assertIn("Stigma-1", document["content"])
        self.assertIn("Fastest way to create a rule", document["content"])
        with self.assertRaises(ValueError):
            deltascope_docs.read_document("../../README")


    def test_ui_exposes_findings_operations_and_documentation_without_main_scroll(self) -> None:
        view = (ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        for token in (
            "Latest security findings", "Components & Actions", "Operations / Actions",
            'parsed.path == "/api/operations"', 'parsed.path == "/api/workbench/findings"',
            'data-perspective-route', "Developer Guide", "Platform manual", 'parsed.path == "/api/docs"',
            'parsed.path == "/api/doc"', 'parsed.path == "/api/workbench/collectors"', "Collectors", "collector-trend-grid", "Degrading", "Late / stale", "#workbench-docs>.docs-shell", "#docTree,#docContent",
        ):
            self.assertIn(token, view)
        self.assertIn("html,body{height:100%;min-height:0;overflow:hidden", view)
        self.assertIn("GitHubOperationsClient", view)


if __name__ == "__main__":
    unittest.main()

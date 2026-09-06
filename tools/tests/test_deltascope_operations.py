from __future__ import annotations

import base64
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
import deltascope_public_git_status
import developer_view


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


class DeltaScopeOperationsTests(unittest.TestCase):
    def test_public_git_monitor_uses_only_public_https_pages_without_credentials(self) -> None:
        requests = []

        def opener(request, timeout=0):
            requests.append((request.full_url, request.get_method(), dict(request.header_items())))
            return _Response(b"")

        monitor = deltascope_public_git_status.PublicGitUrlMonitor(
            "dalagab/omega", opener=opener, ttl_seconds=60
        )
        first_unloaded = monitor.status()
        self.assertFalse(first_unloaded["available"])
        self.assertEqual([], first_unloaded["components"])
        first = monitor.status(refresh=True)
        second = monitor.status()
        self.assertEqual(5, len(first["components"]))
        self.assertTrue(all(row["state"] == "healthy" for row in first["components"]))
        self.assertFalse(first["usesGitHubApi"])
        self.assertFalse(first["usesCredentials"])
        self.assertEqual(first["components"], second["components"])
        self.assertEqual(5, len(requests))
        self.assertTrue(all(url.startswith("https://github.com/") or url.startswith("https://www.githubstatus.com/") for url, _, _ in requests))
        self.assertTrue(all(method == "HEAD" for _, method, _ in requests))
        self.assertTrue(all("Authorization" not in headers for _, _, headers in requests))

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
        unloaded = client.status()
        self.assertFalse(unloaded["available"])
        self.assertEqual(0, len(calls))
        first = client.status(refresh=True)
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

    def test_session_token_dispatch_is_confirmed_and_never_returned(self) -> None:
        requests = []

        def opener(request, timeout=0):
            requests.append((request.full_url, request.get_method(), request.data, dict(request.header_items())))
            if request.get_method() == "POST":
                return _Response(b"")
            return _Response(json.dumps({"workflows": [{"id": 7, "name": "Security scan", "path": ".github/workflows/security.yml", "state": "active", "html_url": "https://github.com/dalagab/omega/actions/workflows/7"}]}).encode("utf-8"))

        client = deltascope_operations.GitHubOperationsClient("dalagab/omega", opener=opener, token="")
        with self.assertRaisesRegex(ValueError, "DISPATCH"):
            client.dispatch_workflow(7, "main", {}, "")
        status = client.configure_session_token("github_pat_" + "a" * 32)
        self.assertTrue(status["tokenConfigured"])
        self.assertEqual("session", status["tokenSource"])
        self.assertEqual("process-memory-only", status["tokenPersistence"])
        self.assertNotIn("github_pat_", json.dumps(status))
        workflows = client.workflows(refresh=True)
        self.assertEqual(7, workflows["workflows"][0]["id"])
        dispatched = client.dispatch_workflow(7, "main", {"depth": "standard"}, "DISPATCH")
        self.assertTrue(dispatched["accepted"])
        url, method, body, headers = requests[-1]
        self.assertIn("/actions/workflows/7/dispatches", url)
        self.assertEqual("POST", method)
        self.assertEqual({"ref": "main", "inputs": {"depth": "standard"}}, json.loads(body.decode("utf-8")))
        self.assertIn("Authorization", headers)
        self.assertNotIn("github_pat_", json.dumps(dispatched))


    def test_environment_token_is_described_without_being_returned(self) -> None:
        original = deltascope_operations.os.environ.get("OMEGA_GITHUB_TOKEN")
        try:
            deltascope_operations.os.environ["OMEGA_GITHUB_TOKEN"] = "github_pat_" + "b" * 32
            client = deltascope_operations.GitHubOperationsClient("dalagab/omega", opener=lambda *_args, **_kwargs: _Response(b'{}'))
            status = client.access_status()
            self.assertTrue(status["tokenConfigured"])
            self.assertEqual("environment", status["tokenSource"])
            self.assertEqual("process-environment", status["tokenPersistence"])
            self.assertNotIn("github_pat_", json.dumps(status))
        finally:
            if original is None:
                deltascope_operations.os.environ.pop("OMEGA_GITHUB_TOKEN", None)
            else:
                deltascope_operations.os.environ["OMEGA_GITHUB_TOKEN"] = original

    def test_remembered_token_reloads_from_local_credential_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "github"
            token = "github_pat_" + "r" * 32
            store = deltascope_operations.LocalGitHubCredentialStore("dalagab/omega", root)
            first = deltascope_operations.GitHubOperationsClient("dalagab/omega", token="", credential_store=store)
            status = first.configure_token(token, remember=True)
            self.assertEqual("remembered", status["tokenSource"])
            self.assertEqual("local-credential", status["tokenPersistence"])
            self.assertTrue(store.path.is_file())
            self.assertNotIn(token, json.dumps(status))

            reloaded = deltascope_operations.GitHubOperationsClient("dalagab/omega", credential_store=store)
            reloaded_status = reloaded.access_status()
            self.assertTrue(reloaded_status["tokenConfigured"])
            self.assertEqual("remembered", reloaded_status["tokenSource"])
            self.assertEqual(token, reloaded.token)
            self.assertNotIn(token, json.dumps(reloaded_status))

            cleared = reloaded.configure_token("", remember=True)
            self.assertFalse(cleared["tokenConfigured"])
            self.assertFalse(store.path.exists())

    def test_operations_ui_places_remembered_workflow_access_in_app_switcher(self) -> None:
        view = (ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        self.assertIn('data-app-action="github-access"', view)
        self.assertIn('id="githubAccessPanel"', view)
        self.assertIn("Save & connect", view)
        self.assertIn("Disconnect & forget", view)
        self.assertIn("remember:true", view)
        self.assertIn("workflowAccessReady", view)
        self.assertIn("Connection credentials are managed from the 9-dot menu", view)
        self.assertIn("GitHub workflow access failed", view)
        self.assertNotIn("Connect for this session", view)

    def test_shell_uses_global_read_only_state_and_route_aware_documentation(self) -> None:
        view = (ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        self.assertIn('id="headerReadOnly"', view)
        self.assertIn('id="contextDocsButton"', view)
        self.assertIn('id="contextDocsLabel"', view)
        self.assertIn('.workspace-view.active>.workspace-heading{display:none!important}', view)
        self.assertIn('function contextualDocumentationForCurrentPage()', view)
        self.assertIn("{doc:'scan-queue',label:'Queue docs'}", view)
        self.assertIn("{doc:'detection-coverage',label:'Coverage docs'}", view)
        self.assertIn("{doc:'threat-intelligence',label:'Threat intel docs'}", view)
        self.assertIn("{doc:'change-attribution',label:'Change docs'}", view)
        self.assertIn("{doc:'plugin-profile',label:'Profile docs'}", view)
        self.assertIn("{doc:'platform-operations',label:'Pipelines docs'}", view)
        self.assertIn("$('contextDocsButton').addEventListener('click',openContextDocumentation)", view)
        self.assertIn("button.dataset.docId=context.doc", view)


    def test_operations_queue_and_health_pages_have_distinct_operational_surfaces(self) -> None:
        view = (ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        self.assertIn('data-workbench-view="ops-evidence"', view)
        self.assertIn('data-workbench-view="ops-gates"', view)
        self.assertIn("{label:'Evidence',mark:'V',view:'ops-evidence'}", view)
        self.assertIn("{label:'Definitions & Gates',mark:'S',view:'ops-gates'}", view)
        self.assertIn('id="queueSelectedDetail"', view)
        self.assertIn('id="queueSearch"', view)
        self.assertIn('NEXT TO RUN', view)
        self.assertIn('A ruleset update is not an artifact rescan trigger by itself.', view)
        self.assertIn('Raw tables and relationship traversal remain under the Security Researcher → Data workspace', view)
        self.assertNotIn("{label:'Evidence',mark:'V',view:'system'},{label:'Definitions & Gates',mark:'S',view:'system'}", view)

    def test_workflow_dispatch_form_projects_declared_inputs_without_source_content(self) -> None:
        workflow_yaml = b"""name: Security scan
on:
  workflow_dispatch:
    inputs:
      work_id:
        description: Work item to scan
        required: true
        type: string
      depth:
        description: Analysis depth
        type: choice
        default: standard
        options: [standard, deep]
      include_source:
        type: boolean
        default: false
"""
        calls = []

        def opener(request, timeout=0):
            calls.append(request.full_url)
            if "/actions/workflows?" in request.full_url:
                return _Response(json.dumps({"workflows": [{
                    "id": 7, "name": "Security scan", "path": ".github/workflows/security.yml",
                    "state": "active", "html_url": "https://github.com/dalagab/omega/actions/workflows/7",
                }]}).encode("utf-8"))
            if "/contents/.github/workflows/security.yml?ref=sigmascope" in request.full_url:
                return _Response(json.dumps({
                    "encoding": "base64",
                    "content": base64.b64encode(workflow_yaml).decode("ascii"),
                }).encode("utf-8"))
            raise AssertionError(request.full_url)

        client = deltascope_operations.GitHubOperationsClient(
            "dalagab/omega", opener=opener, token="github_pat_" + "c" * 32, ttl_seconds=60
        )
        form = client.workflow_dispatch_form(7, "sigmascope", refresh=True)
        self.assertTrue(form["available"])
        self.assertTrue(form["dispatchable"])
        self.assertTrue(form["readOnly"])
        self.assertEqual("none", form["mutationAuthority"])
        self.assertEqual(["work_id", "depth", "include_source"], [row["name"] for row in form["inputs"]])
        self.assertTrue(form["inputs"][0]["required"])
        self.assertEqual(["standard", "deep"], form["inputs"][1]["options"])
        self.assertEqual("boolean", form["inputs"][2]["type"])
        self.assertNotIn("workflow_dispatch", json.dumps(form))
        self.assertEqual(2, len(calls))
        self.assertEqual(form, client.workflow_dispatch_form(7, "sigmascope"))
        self.assertEqual(2, len(calls))

    def test_workflow_dispatch_form_marks_non_dispatch_workflow(self) -> None:
        workflow_yaml = b"name: Build\non: [push]\n"

        def opener(request, timeout=0):
            if "/actions/workflows?" in request.full_url:
                return _Response(json.dumps({"workflows": [{
                    "id": 8, "name": "Build", "path": ".github/workflows/build.yml", "state": "active"
                }]}).encode("utf-8"))
            return _Response(json.dumps({
                "encoding": "base64", "content": base64.b64encode(workflow_yaml).decode("ascii")
            }).encode("utf-8"))

        client = deltascope_operations.GitHubOperationsClient("dalagab/omega", opener=opener, token="github_pat_" + "d" * 32)
        form = client.workflow_dispatch_form(8, "main", refresh=True)
        self.assertTrue(form["available"])
        self.assertFalse(form["dispatchable"])
        self.assertEqual([], form["inputs"])

    def test_operations_ui_builds_guided_fields_from_workflow_dispatch_schema(self) -> None:
        view = (ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        self.assertIn("/api/operations/workflow-form?workflow_id=", view)
        self.assertIn("Declared workflow inputs", view)
        self.assertIn("data-workflow-input", view)
        self.assertIn("Advanced inputs JSON (fallback)", view)
        self.assertIn("Not dispatchable from this ref", view)
        self.assertIn("required declared input", view)

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
        unloaded = client.workflow_history("catalog-builder.yml", limit=1, include_logs=True)
        self.assertFalse(unloaded["available"])
        self.assertEqual(0, len(calls))
        first = client.workflow_history("catalog-builder.yml", limit=1, include_logs=True, refresh=True)
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
            log_job_names={"Discover source feeds"}, log_run_limit=2, refresh=True,
        )
        self.assertEqual(2, len(payload["runs"]))
        self.assertEqual("newer collector log", payload["runs"][0]["jobs"][0]["logPreview"])
        self.assertEqual("older collector log", payload["runs"][1]["jobs"][0]["logPreview"])
        self.assertEqual(2, sum(1 for url in calls if "/logs" in url))

    def test_remote_acquisition_is_explicit_and_navigation_uses_snapshots(self) -> None:
        calls = []
        payload = {"workflow_runs": []}

        def opener(request, timeout=0):
            calls.append(request.full_url)
            if "/actions/runs?" in request.full_url:
                return _Response(json.dumps(payload).encode("utf-8"))
            if "/actions/workflows?" in request.full_url:
                return _Response(b'{"workflows": []}')
            raise AssertionError(request.full_url)

        client = deltascope_operations.GitHubOperationsClient("dalagab/omega", opener=opener, token="")
        self.assertFalse(client.status()["available"])
        self.assertEqual([], calls)
        refreshed = client.refresh_snapshot({})
        self.assertTrue(refreshed["refreshed"])
        calls_after_refresh = list(calls)
        self.assertEqual("explicit-refresh", client.snapshot_status()["cachePolicy"])
        client.status()
        client.workflows()
        self.assertEqual(calls_after_refresh, calls)

        view = (ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        self.assertIn('data-app-action="data-sources"', view)
        self.assertIn('id="dataSourcesPanel"', view)
        self.assertIn('/api/acquisition/refresh', view)
        self.assertIn('Navigation never refreshes data.', view)
        self.assertIn('Recompute from snapshot', view)
        self.assertNotIn('setInterval(checkEvidenceRevision,60000)', view)
        self.assertNotIn("loadPublicGitStatus(true)},20000", view)
        self.assertNotIn('id="refreshOperations"', view)
        self.assertNotIn('id="refreshCollectors"', view)

    def test_documentation_catalog_is_allowlisted_and_stigma_first(self) -> None:
        catalog = deltascope_docs.catalog()
        ids = [row["id"] for row in catalog["documents"]]
        self.assertIn("stigma1", ids)
        self.assertIn("rule-author-start", ids)
        self.assertIn("data-acquisition", ids)
        document = deltascope_docs.read_document("stigma1")
        self.assertIn("Stigma-1", document["content"])
        self.assertIn("Fastest way to create a rule", document["content"])
        with self.assertRaises(ValueError):
            deltascope_docs.read_document("../../README")


    def test_ui_exposes_findings_operations_and_documentation_without_main_scroll(self) -> None:
        view = (ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        for token in (
            "Case inbox", "Components & Actions", "Operations / Actions",
            'parsed.path == "/api/operations"', 'parsed.path == "/api/workbench/findings"',
            'data-perspective-route', "Developer Guide", "Platform manual", 'parsed.path == "/api/docs"',
            'parsed.path == "/api/doc"', 'parsed.path == "/api/workbench/collectors"', "Collectors", "collector-trend-grid", "Degrading", "Late / stale", "#workbench-docs>.docs-shell", "#docTree,#docContent",
        ):
            self.assertIn(token, view)
        self.assertIn("html,body{height:100%;min-height:0;overflow:hidden", view)
        self.assertIn("GitHubOperationsClient", view)

    def test_operator_pipeline_topology_keeps_inventory_opt_in_and_signals_loading(self) -> None:
        view = (ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        for token in (
            "Omega delivery path", "renderOperatorPipeline", "unobserved stages",
            "Operator action", "omegaLoading", "Refreshing Omega data",
            "loadOperationsWithIndicator", "loadCollectorsWithIndicator",
        ):
            self.assertIn(token, view)


if __name__ == "__main__":
    unittest.main()

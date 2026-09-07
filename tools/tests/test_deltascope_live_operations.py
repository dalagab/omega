from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_live_operations as live
import deltascope_operations


class _Headers(dict):
    def get(self, key, default=None):
        for candidate, value in self.items():
            if str(candidate).casefold() == str(key).casefold():
                return value
        return default


class _Response(io.BytesIO):
    def __init__(self, payload, *, status=200, headers=None):
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        super().__init__(raw)
        self.status = status
        self.headers = _Headers(headers or {})

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def getcode(self):
        return self.status


def _rate_headers(remaining=4900):
    return {
        "X-RateLimit-Limit": "5000",
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Used": str(5000 - remaining),
        "X-RateLimit-Resource": "core",
        "X-RateLimit-Reset": "1788811200",
    }


def _run_payload():
    return {
        "workflow_runs": [{
            "id": 101,
            "run_number": 88,
            "run_attempt": 1,
            "name": "Omega Sigmascope continuous worker",
            "path": ".github/workflows/sigmascope.yml",
            "display_title": "bounded scan batch",
            "event": "workflow_dispatch",
            "head_branch": "sigmascope",
            "head_sha": "a" * 40,
            "status": "in_progress",
            "conclusion": None,
            "created_at": "2026-09-07T20:00:00Z",
            "updated_at": "2026-09-07T20:01:00Z",
            "html_url": "https://github.com/dalagab/omega/actions/runs/101",
        }]
    }


def _jobs_payload():
    return {
        "jobs": [{
            "id": 201,
            "name": "Artifact worker",
            "status": "in_progress",
            "conclusion": None,
            "started_at": "2026-09-07T20:00:10Z",
            "completed_at": None,
            "runner_id": 7,
            "runner_name": "sigma-private-03",
            "runner_group_id": 2,
            "runner_group_name": "private-security",
            "labels": ["self-hosted", "Linux", "X64", "sigmascope"],
            "html_url": "https://github.com/dalagab/omega/actions/runs/101/job/201",
            "steps": [{
                "number": 1,
                "name": "Acquire queue",
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-09-07T20:00:10Z",
                "completed_at": "2026-09-07T20:00:20Z",
            }, {
                "number": 2,
                "name": "Artifact analysis",
                "status": "in_progress",
                "conclusion": None,
                "started_at": "2026-09-07T20:00:21Z",
                "completed_at": None,
            }],
        }]
    }


def _telemetry_log():
    return (
        "normal action output\n"
        '@@omega {"schema":"omega.actions.telemetry.v1","event":"queue.claimed","emittedAtUtc":"2026-09-07T20:00:22Z","component":"sigmascope","worker":{"roleId":"sigmascope","label":"SigmaScope worker","state":"claiming"},"subject":{"variantId":8291,"internalName":"Example.Plugin","version":"1.2.3","workType":"artifact"},"queue":{"reason":"first-plugin-coverage","remaining":1284}}\n'
        '@@omega {"schema":"omega.actions.telemetry.v1","event":"scan.progress","emittedAtUtc":"2026-09-07T20:01:00Z","component":"sigmascope","worker":{"roleId":"sigmascope","label":"SigmaScope worker","state":"scanning"},"stage":"managed assembly analysis","subject":{"variantId":8291,"internalName":"Example.Plugin","version":"1.2.3","workType":"artifact"},"progress":{"current":18,"total":31,"unit":"analysis stages"}}\n'
    )



class DeltaScopeLiveOperationsTests(unittest.TestCase):
    def client(self, opener, token="github_pat_" + "x" * 32):
        client = deltascope_operations.GitHubOperationsClient(
            "dalagab/omega", opener=opener, token=token
        )
        live._install_client_extensions(client.__class__)
        live._reset_state(client)
        return client

    def test_unauthenticated_live_status_does_not_touch_network(self):
        calls = []
        client = self.client(lambda request, timeout=0: calls.append(request.full_url), token="")
        result = client.live_status()
        self.assertFalse(result["available"])
        self.assertFalse(result["authenticated"])
        self.assertEqual([], calls)
        self.assertEqual("explicit-public-snapshot", result["cachePolicy"])

    def test_authenticated_live_snapshot_correlates_run_job_and_job_observed_runner(self):
        calls = []

        def opener(request, timeout=0):
            url = request.full_url
            calls.append(url)
            if "/actions/runs?" in url:
                return _Response(_run_payload(), headers=_rate_headers())
            if "/actions/runs/101/jobs" in url:
                return _Response(_jobs_payload(), headers=_rate_headers(4899))
            if "/actions/runners?" in url:
                raise urllib.error.HTTPError(url, 403, "forbidden", _Headers(_rate_headers(4898)), None)
            raise AssertionError(url)

        client = self.client(opener)
        result = client.live_status(foreground=True)
        self.assertTrue(result["live"])
        self.assertEqual(1, result["counts"]["activeRuns"])
        self.assertEqual(1, result["counts"]["jobs"])
        self.assertEqual(1, result["counts"]["runners"])
        self.assertEqual(1, result["counts"]["busyRunners"])
        runner = result["runners"][0]
        self.assertEqual("sigma-private-03", runner["runnerName"])
        self.assertEqual("job-observation", runner["source"])
        self.assertEqual("Artifact worker", runner["activeJobs"][0]["name"])
        self.assertTrue(result["capabilities"]["actionsRead"]["available"])
        self.assertTrue(result["capabilities"]["jobsRead"]["available"])
        self.assertFalse(result["capabilities"]["runnerInventoryRead"]["available"])
        self.assertIn("job-level runner observations", result["capabilities"]["runnerInventoryRead"]["detail"])
        self.assertNotIn("github_pat_", json.dumps(result))
        self.assertEqual(4898, result["rateLimit"]["remaining"])

    def test_authorized_runner_inventory_merges_online_busy_state(self):
        def opener(request, timeout=0):
            url = request.full_url
            if "/actions/runs?" in url:
                return _Response(_run_payload(), headers=_rate_headers())
            if "/actions/runs/101/jobs" in url:
                return _Response(_jobs_payload(), headers=_rate_headers())
            if "/actions/runners?" in url:
                return _Response({
                    "total_count": 1,
                    "runners": [{
                        "id": 7,
                        "name": "sigma-private-03",
                        "os": "Linux",
                        "status": "online",
                        "busy": True,
                        "labels": [{"name": "self-hosted"}, {"name": "sigmascope"}],
                    }],
                }, headers=_rate_headers())
            raise AssertionError(url)

        result = self.client(opener).live_status()
        runner = result["runners"][0]
        self.assertEqual("repository-runner-inventory", runner["source"])
        self.assertEqual("online", runner["status"])
        self.assertTrue(runner["busy"])
        self.assertEqual(["self-hosted", "sigmascope"], runner["labels"])
        self.assertTrue(result["capabilities"]["runnerInventoryRead"]["available"])

    def test_live_snapshot_is_cached_between_adaptive_poll_intervals(self):
        calls = []

        def opener(request, timeout=0):
            calls.append(request.full_url)
            if "/actions/runs?" in request.full_url:
                return _Response({"workflow_runs": []}, headers=_rate_headers())
            if "/actions/runners?" in request.full_url:
                return _Response({"total_count": 0, "runners": []}, headers=_rate_headers())
            raise AssertionError(request.full_url)

        client = self.client(opener)
        first = client.live_status(foreground=True)
        count = len(calls)
        second = client.live_status(foreground=True)
        self.assertEqual(count, len(calls))
        self.assertTrue(second["servedFromCache"])
        self.assertLessEqual(second["nextPollSeconds"], live.FOREGROUND_POLL_SECONDS)
        self.assertEqual(first["fetchedAtUtc"], second["fetchedAtUtc"])

    def test_low_rate_budget_increases_poll_interval(self):
        def opener(request, timeout=0):
            if "/actions/runs?" in request.full_url:
                return _Response({"workflow_runs": []}, headers=_rate_headers(400))
            if "/actions/runners?" in request.full_url:
                return _Response({"total_count": 0, "runners": []}, headers=_rate_headers(399))
            raise AssertionError(request.full_url)

        result = self.client(opener).live_status(foreground=True)
        self.assertGreaterEqual(result["nextPollSeconds"], 60)
        self.assertEqual(399, result["rateLimit"]["remaining"])
        self.assertEqual("core", result["rateLimit"]["resource"])

    def test_failed_refresh_keeps_last_known_good_live_snapshot_stale(self):
        state = {"fail": False}

        def opener(request, timeout=0):
            if state["fail"]:
                raise urllib.error.URLError("offline")
            if "/actions/runs?" in request.full_url:
                return _Response(_run_payload(), headers=_rate_headers())
            if "/actions/runs/101/jobs" in request.full_url:
                return _Response(_jobs_payload(), headers=_rate_headers())
            if "/actions/runners?" in request.full_url:
                return _Response({"total_count": 0, "runners": []}, headers=_rate_headers())
            raise AssertionError(request.full_url)

        client = self.client(opener)
        first = client.live_status()
        self.assertTrue(first["available"])
        state["fail"] = True
        client._live_cached_at = 0.0
        client._live_last_attempt_at = 0.0
        second = client.live_status(force=True)
        self.assertTrue(second["available"])
        self.assertTrue(second["stale"])
        self.assertIn("offline", second["error"])

    def test_token_change_resets_live_snapshot(self):
        def opener(request, timeout=0):
            if "/actions/runs?" in request.full_url:
                return _Response({"workflow_runs": []}, headers=_rate_headers())
            if "/actions/runners?" in request.full_url:
                return _Response({"total_count": 0, "runners": []}, headers=_rate_headers())
            raise AssertionError(request.full_url)

        client = self.client(opener)
        client.live_status()
        self.assertIsNotNone(client._live_cache)
        client.configure_token("github_pat_" + "y" * 32, remember=False)
        self.assertIsNone(client._live_cache)

    def test_ui_patch_adds_live_strip_and_adaptive_polling_without_token_material(self):
        html = live._patch_html("<html><script>const currentWorkbenchView='workflows';</script></html>")
        self.assertIn("__deltascopeLiveOperationsInstalled", html)
        self.assertIn("/api/operations/live?foreground=", html)
        self.assertIn("Rate remaining", html)
        self.assertIn("runnerInventoryRead", html)
        self.assertIn("document.visibilityState", html)
        self.assertNotIn("Authorization", html)
        self.assertNotIn("Bearer", html)


    def test_worker_role_is_separate_from_runner_infrastructure(self):
        job = {"componentId":"sigmascope","component":"SigmaScope","workflow":"Omega Sigmascope continuous worker","name":"Artifact worker","state":"running","labels":["self-hosted","sigmascope"],"steps":[{"number":1,"name":"Acquire queue","status":"completed","conclusion":"success"},{"number":2,"name":"Artifact analysis","status":"in_progress","conclusion":""}]}
        role=live._worker_role(job)
        self.assertEqual("sigmascope",role["roleId"]); self.assertEqual("SigmaScope worker",role["label"]); self.assertEqual("scanning",role["state"]); self.assertFalse(role["authoritative"]); self.assertTrue(role["inferred"])

    def test_runner_dashboard_keeps_inventory_state_and_worker_role_distinct(self):
        def opener(request, timeout=0):
            url=request.full_url
            if "/actions/runs?" in url:return _Response(_run_payload(),headers=_rate_headers())
            if "/actions/runs/101/jobs" in url:return _Response(_jobs_payload(),headers=_rate_headers())
            if "/actions/runners?" in url:return _Response({"total_count":2,"runners":[{"id":7,"name":"sigma-private-03","os":"Linux","status":"online","busy":True,"labels":[{"name":"self-hosted"},{"name":"sigmascope"}]},{"id":8,"name":"sigma-private-04","os":"Linux","status":"offline","busy":False,"labels":[{"name":"self-hosted"}]}]},headers=_rate_headers())
            raise AssertionError(url)
        dashboard=self.client(opener).runner_dashboard(); self.assertEqual(live.RUNNER_DASHBOARD_SCHEMA,dashboard["schema"]); self.assertEqual(2,dashboard["counts"]["runners"]); self.assertEqual(1,dashboard["counts"]["online"]); self.assertEqual(1,dashboard["counts"]["offline"]); self.assertEqual(1,dashboard["counts"]["busy"]); self.assertEqual(1,dashboard["counts"]["workers"])
        by_name={row["runnerName"]:row for row in dashboard["runners"]}; busy=by_name["sigma-private-03"]; self.assertTrue(busy["infrastructure"]["onlineObserved"]); self.assertEqual("github-actions-runner-state",busy["infrastructure"]["authority"]); self.assertEqual("SigmaScope worker",busy["workers"][0]["workerRole"]["label"]); self.assertTrue(dashboard["semanticBoundary"]["runnerIsInfrastructure"]); self.assertTrue(dashboard["semanticBoundary"]["workerIsExecutionRole"]); self.assertFalse(by_name["sigma-private-04"]["infrastructure"]["onlineObserved"]); self.assertEqual([],by_name["sigma-private-04"]["workers"])

    def test_job_observed_runner_never_claims_online_status(self):
        def opener(request, timeout=0):
            url=request.full_url
            if "/actions/runs?" in url:return _Response(_run_payload(),headers=_rate_headers())
            if "/actions/runs/101/jobs" in url:return _Response(_jobs_payload(),headers=_rate_headers())
            if "/actions/runners?" in url:raise urllib.error.HTTPError(url,403,"forbidden",_Headers(_rate_headers()),None)
            raise AssertionError(url)
        dashboard=self.client(opener).runner_dashboard(); self.assertEqual(1,dashboard["counts"]["observedOnly"]); runner=dashboard["runners"][0]; self.assertIsNone(runner["infrastructure"]["onlineObserved"]); self.assertEqual("job-observation",runner["infrastructure"]["source"]); self.assertIn("without claiming online/offline",dashboard["message"].lower())

    def test_runner_dashboard_reuses_live_backend_cache(self):
        calls=[]
        def opener(request, timeout=0):
            calls.append(request.full_url)
            if "/actions/runs?" in request.full_url:return _Response({"workflow_runs":[]},headers=_rate_headers())
            if "/actions/runners?" in request.full_url:return _Response({"total_count":0,"runners":[]},headers=_rate_headers())
            raise AssertionError(request.full_url)
        client=self.client(opener); client.live_status(); before=len(calls); dashboard=client.runner_dashboard(); self.assertEqual(before,len(calls)); self.assertTrue(dashboard["servedFromCache"])

    def test_runner_ui_adds_dedicated_view_filters_and_workflow_navigation(self):
        html=live._patch_html("<html><body><main></main><script>const currentWorkbenchView='runners';const currentPerspective='operations';</script></body></html>")
        self.assertIn('id="workbench-runners"',html); self.assertIn("Runner Dashboard",html); self.assertIn("Infrastructure state",html); self.assertIn("Omega worker activity",html); self.assertIn("data-runner-open-job",html); self.assertIn("workflowCenterList",html); self.assertIn("workflowCenterRunList",html); self.assertIn("runnerInventoryRead",html); self.assertNotIn("Authorization",html); self.assertNotIn("Bearer",html)


    def test_explicit_telemetry_overrides_inferred_worker_stage(self):
        def opener(request, timeout=0):
            url = request.full_url
            if "/actions/runs?" in url:
                return _Response(_run_payload(), headers=_rate_headers())
            if "/actions/runs/101/jobs" in url:
                return _Response(_jobs_payload(), headers=_rate_headers())
            if "/actions/jobs/201/logs" in url:
                return _Response(_telemetry_log().encode("utf-8"), headers=_rate_headers(4898))
            if "/actions/runners?" in url:
                return _Response({"total_count": 0, "runners": []}, headers=_rate_headers(4897))
            raise AssertionError(url)

        result = self.client(opener).live_status()
        job = result["jobs"][0]
        self.assertEqual(2, job["telemetry"]["eventCount"])
        self.assertEqual("scan.progress", job["latestTelemetry"]["event"])
        self.assertFalse(job["workerRole"]["inferred"])
        self.assertTrue(job["workerRole"]["workerPublished"])
        self.assertEqual("omega-actions-telemetry", job["workerRole"]["source"])
        self.assertEqual("scanning", job["workerRole"]["state"])
        self.assertFalse(job["workerRole"]["authoritative"])
        self.assertEqual("Example.Plugin", job["latestTelemetry"]["subject"]["internalName"])
        self.assertEqual(18, job["latestTelemetry"]["progress"]["current"])
        self.assertEqual(2, result["counts"]["telemetryEvents"])
        self.assertEqual(1, result["counts"]["telemetryJobs"])
        self.assertTrue(result["capabilities"]["jobLogsRead"]["observed"])
        self.assertTrue(result["capabilities"]["jobLogsRead"]["available"])

    def test_telemetry_log_acquisition_is_cached_independently(self):
        calls = []
        def opener(request, timeout=0):
            url = request.full_url
            calls.append(url)
            if "/actions/runs?" in url:
                return _Response(_run_payload(), headers=_rate_headers())
            if "/actions/runs/101/jobs" in url:
                return _Response(_jobs_payload(), headers=_rate_headers())
            if "/actions/jobs/201/logs" in url:
                return _Response(_telemetry_log().encode("utf-8"), headers=_rate_headers())
            if "/actions/runners?" in url:
                return _Response({"total_count": 0, "runners": []}, headers=_rate_headers())
            raise AssertionError(url)

        client = self.client(opener)
        first = client.live_status()
        self.assertEqual(1, sum("/actions/jobs/201/logs" in url for url in calls))
        client._live_cached_at = 0.0
        client._live_last_attempt_at = 0.0
        second = client.live_status(force=True)
        self.assertEqual(1, sum("/actions/jobs/201/logs" in url for url in calls))
        self.assertEqual(first["telemetry"]["eventCount"], second["telemetry"]["eventCount"])

    def test_telemetry_endpoint_projection_reuses_live_snapshot(self):
        calls = []
        def opener(request, timeout=0):
            url = request.full_url
            calls.append(url)
            if "/actions/runs?" in url:
                return _Response(_run_payload(), headers=_rate_headers())
            if "/actions/runs/101/jobs" in url:
                return _Response(_jobs_payload(), headers=_rate_headers())
            if "/actions/jobs/201/logs" in url:
                return _Response(_telemetry_log().encode("utf-8"), headers=_rate_headers())
            if "/actions/runners?" in url:
                return _Response({"total_count": 0, "runners": []}, headers=_rate_headers())
            raise AssertionError(url)

        client = self.client(opener)
        client.live_status()
        before = len(calls)
        view = client.actions_telemetry()
        self.assertEqual(before, len(calls))
        self.assertEqual(live.TELEMETRY_VIEW_SCHEMA, view["schema"])
        self.assertEqual("omega.actions.telemetry.v1", view["contract"])
        self.assertEqual(2, view["eventCount"])
        self.assertFalse(view["securityAuthority"])

    def test_runner_dashboard_carries_explicit_latest_telemetry(self):
        def opener(request, timeout=0):
            url = request.full_url
            if "/actions/runs?" in url:
                return _Response(_run_payload(), headers=_rate_headers())
            if "/actions/runs/101/jobs" in url:
                return _Response(_jobs_payload(), headers=_rate_headers())
            if "/actions/jobs/201/logs" in url:
                return _Response(_telemetry_log().encode("utf-8"), headers=_rate_headers())
            if "/actions/runners?" in url:
                return _Response({"total_count": 0, "runners": []}, headers=_rate_headers())
            raise AssertionError(url)

        dashboard = self.client(opener).runner_dashboard()
        worker = dashboard["runners"][0]["workers"][0]
        self.assertEqual("scan.progress", worker["latestTelemetry"]["event"])
        self.assertFalse(worker["workerRole"]["inferred"])
        self.assertTrue(dashboard["semanticBoundary"]["structuredTelemetryOverridesInference"])

    def test_runner_ui_distinguishes_telemetry_from_inferred_state(self):
        html = live._patch_html(
            "<html><body><main></main><script>"
            "const currentWorkbenchView='runners';const currentPerspective='operations';"
            "</script></body></html>"
        )
        self.assertIn("TELEMETRY", html)
        self.assertIn("INFERRED", html)
        self.assertIn("Subject:", html)
        self.assertIn("Progress:", html)
        self.assertIn("telemetryEvents", html)
        self.assertTrue(hasattr(live, "project_actions_telemetry"))

    def test_entrypoint_installs_live_operations_after_workflow_center(self):
        source = (SECURITY / "deltascope.py").read_text(encoding="utf-8")
        self.assertIn("import deltascope_live_operations", source)
        self.assertIn("deltascope_live_operations.install()", source)
        self.assertLess(
            source.index("deltascope_workflow_center.install()"),
            source.index("deltascope_live_operations.install()"),
        )


if __name__ == "__main__":
    unittest.main()

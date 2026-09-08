from __future__ import annotations

import io
import json
import sys
import threading
import unittest
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_live_operations as live
import deltascope_operations
import deltascope_operations_diagnostics as diagnostics


class _Response(io.BytesIO):
    def __init__(self, payload: object, headers: dict[str, str] | None = None):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        super().__init__(data)
        self.headers = headers or {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4988",
            "X-RateLimit-Used": "12",
            "X-RateLimit-Resource": "core",
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


class _SnapshotClient:
    repository = "dalagab/omega"
    token = "github_pat_test"

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.refreshes = 0
        self._live_cache = {
            "available": True,
            "live": True,
            "authenticated": True,
            "fetchedAtUtc": "2026-09-08T07:00:00Z",
            "capabilities": {
                "actionsRead": {"available": True, "observed": True, "source": "actions-runs"},
                "jobsRead": {"available": True, "observed": True, "source": "active-run-jobs"},
                "jobLogsRead": {"available": False, "observed": True, "source": "bounded-active-job-telemetry", "detail": "GitHub returned 403"},
                "runnerInventoryRead": {"available": False, "observed": True, "source": "repository-runner-inventory", "detail": "repository runner inventory unavailable (403)"},
                "workflowDispatch": {"available": True, "observed": False, "source": "connected-token"},
                "runControl": {"available": True, "observed": False, "source": "connected-token"},
            },
            "rateLimit": {},
        }
        self._live_cached_at = 1.0
        self._live_last_attempt_at = 1.0
        self._live_last_attempt_utc = "2026-09-08T07:00:00Z"
        self._live_last_success_utc = "2026-09-08T07:00:00Z"
        self._live_last_error = ""
        self._live_last_error_utc = ""
        self._live_backoff_reason = ""
        self._live_fetch_lock = threading.Lock()
        self._live_rate_limit = {
            "limit": 5000, "remaining": 4988, "used": 12, "resource": "core",
            "resetAtUtc": "2026-09-08T08:00:00Z", "retryAfterSeconds": 0,
        }
        self._live_backoff_until = 0.0
        self._live_runner_inventory = []
        self._live_runner_inventory_at = 0.0
        self._live_runner_inventory_error = ""
        self._live_runner_inventory_observed = False
        self._live_telemetry_cache = {}

    def access_status(self):
        return {
            "tokenConfigured": True, "statusMode": "authenticated", "tokenSource": "remembered",
            "tokenPersistence": "local-credential", "credentialProtection": "windows-dpapi-current-user",
            "credentialError": "",
        }

    def live_status(self, *, foreground=True, force=False):
        self.refreshes += 1
        return dict(self._live_cache)


class OperationsDiagnosticsTests(unittest.TestCase):
    def test_snapshot_projection_does_not_refresh(self) -> None:
        client = _SnapshotClient()
        result = diagnostics.project_operations_diagnostics(client, refresh=False)
        self.assertEqual(0, client.refreshes)
        self.assertTrue(result["snapshotOnly"])
        self.assertEqual("healthy", result["state"])
        self.assertEqual("2026-09-08T07:00:00Z", result["acquisition"]["lastSuccessfulAtUtc"])
        self.assertEqual(4988, result["rateLimit"]["remaining"])
        by_id = {row["id"]: row for row in result["capabilities"]}
        self.assertEqual("available", by_id["actionsRead"]["state"])
        self.assertEqual("unavailable", by_id["runnerInventoryRead"]["state"])
        self.assertEqual("configured-unverified", by_id["workflowDispatch"]["state"])
        self.assertIn("does not perform a mutating", by_id["workflowDispatch"]["explanation"])
        self.assertTrue(any("runner inventory unavailable" in row.lower() for row in result["guidance"]))

    def test_refresh_is_explicit(self) -> None:
        client = _SnapshotClient()
        result = diagnostics.project_operations_diagnostics(client, refresh=True)
        self.assertEqual(1, client.refreshes)
        self.assertTrue(result["refreshPerformed"])
        self.assertFalse(result["snapshotOnly"])

    def test_live_state_records_success_and_permission_failure(self) -> None:
        def opener(request, timeout=0):
            if "/actions/runs?" in request.full_url:
                return _Response({"workflow_runs": []})
            if "/actions/runners?" in request.full_url:
                return _Response({"total_count": 0, "runners": []})
            raise AssertionError(request.full_url)

        client = deltascope_operations.GitHubOperationsClient("dalagab/omega", token="github_pat_test", opener=opener)
        live._install_client_extensions(deltascope_operations.GitHubOperationsClient)
        first = client.live_status(force=True)
        self.assertTrue(first["live"])
        self.assertTrue(client._live_last_success_utc)
        self.assertEqual("", client._live_last_error)

        def denied(request, timeout=0):
            raise urllib.error.HTTPError(request.full_url, 403, "forbidden", {}, None)

        client._opener = denied
        client._live_last_attempt_at = 0.0
        client._live_backoff_until = 0.0
        stale = client.live_status(force=True)
        self.assertTrue(stale["stale"])
        self.assertIn("403", client._live_last_error)
        self.assertIn("denied", client._live_backoff_reason.lower())

    def test_html_contract_has_diagnostics_without_credentials(self) -> None:
        html = diagnostics._patch_html("<html><body><main></main><script>const perspectiveConfig={operations:{groups:[{label:'Operate',items:[]}]}};</script></body></html>")
        self.assertIn("Operations diagnostics", html)
        self.assertIn("/api/operations/diagnostics", html)
        self.assertIn("configured but intentionally not tested", html)
        self.assertIn("Loading the current diagnostics snapshot", html)
        self.assertIn("renderFailure", html)
        self.assertIn("Diagnostics unavailable", html)
        self.assertNotIn("Authorization", html)
        self.assertNotIn("Bearer ", html)


if __name__ == "__main__":
    unittest.main()

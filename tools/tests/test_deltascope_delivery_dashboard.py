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

import deltascope_delivery_dashboard
import deltascope_operations
import developer_view


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


class _Inspector:
    def __init__(self, evidence_revision: str = "ev-1") -> None:
        self.evidence_revision = evidence_revision
        self.summary_calls = 0

    def summary(self):
        self.summary_calls += 1
        return {
            "counts": {"variants": 12},
            "revisions": {
                "catalogDataRevision": "cat-1", "definitionsRevision": "defs-1",
                "evidenceRevision": self.evidence_revision, "securityRevision": "sec-1",
            },
        }

    def scan_queue_state(self):
        return {
            "selectionPolicy": "coverage-first-v1",
            "items": {
                "one": {"state": "pending", "variantId": 1, "primaryReason": "new_variant"},
                "two": {"state": "complete", "variantId": 2},
            },
        }


class _Client:
    def __init__(self, *, token: bool = True, publisher_state: str = "healthy") -> None:
        self.token = token
        self.publisher_state = publisher_state

    def access_status(self):
        return {"tokenConfigured": self.token, "statusMode": "authenticated" if self.token else "public"}

    def client_delivery(self, *, refresh=False):
        return {
            "available": True, "authenticated": True, "fetchedAtUtc": "2026-09-04T10:00:00Z",
            "release": {"publishedAtUtc": "2026-09-04T09:00:00Z", "assets": []},
            "publisherRun": {"runId": 9, "state": self.publisher_state},
            "manifest": {
                "schema": "omega.marketplace-build.v1", "generatedAtUtc": "2026-09-04T08:59:00Z",
                "inputs": {
                    "catalogRevision": "cat-1", "definitionsRevision": "defs-1",
                    "evidenceRevision": "ev-1", "securityRevision": "sec-1",
                    "evidenceCompatible": True,
                },
                "output": {"variantCount": 12, "logicalPluginCount": 8, "sourceCount": 3, "databaseSha256": "a" * 64},
                "materializedEvidence": {"currentVariantsAvailable": 12, "currentVariantsMaterialized": 12},
                "projectionIntegrity": {"status": "ok"},
            },
        }

    def status(self, *, refresh=False):
        return {
            "actionsRunning": 1 if self.publisher_state == "running" else 0,
            "recentFailureCount": 1 if self.publisher_state == "failed" else 0,
            "events": [],
        }


class DeltaScopeDeliveryDashboardTests(unittest.TestCase):
    def test_client_delivery_requires_authentication_without_network(self):
        calls = []
        client = deltascope_operations.GitHubOperationsClient(
            "dalagab/omega", token="", opener=lambda *args, **kwargs: calls.append(args),
        )
        result = client.client_delivery(refresh=True)
        self.assertFalse(result["authenticated"])
        self.assertFalse(result["available"])
        self.assertEqual([], calls)

    def test_client_delivery_acquires_release_manifest_and_publisher(self):
        requests = []
        release = {
            "name": "Latest catalog", "published_at": "2026-09-04T09:00:00Z",
            "updated_at": "2026-09-04T09:01:00Z",
            "html_url": "https://github.com/dalagab/omega/releases/tag/catalog-latest",
            "assets": [{
                "name": "database-build.json", "size": 800, "download_count": 4,
                "updated_at": "2026-09-04T09:01:00Z",
                "url": "https://api.github.com/repos/dalagab/omega/releases/assets/7",
                "browser_download_url": "https://github.com/dalagab/omega/releases/download/catalog-latest/database-build.json",
            }],
        }
        manifest = {"schema": "omega.marketplace-build.v1", "inputs": {}, "output": {}}

        def opener(request, timeout=0):
            requests.append((request.full_url, dict(request.header_items())))
            payload = manifest if request.full_url.endswith("/assets/7") else release
            return _Response(json.dumps(payload).encode("utf-8"))

        client = deltascope_operations.GitHubOperationsClient("dalagab/omega", token="github_pat_" + "x" * 32, opener=opener)
        client._cache = deltascope_operations.project_runs("dalagab/omega", [{
            "id": 99, "run_number": 5, "name": "Omega catalog publish",
            "path": ".github/workflows/catalog-client-publish.yml", "status": "completed",
            "conclusion": "success", "html_url": "https://github.com/dalagab/omega/actions/runs/99",
        }])
        result = client.client_delivery(refresh=True)
        self.assertTrue(result["available"])
        self.assertEqual("omega.marketplace-build.v1", result["manifest"]["schema"])
        self.assertEqual(99, result["publisherRun"]["runId"])
        self.assertEqual("application/octet-stream", requests[1][1]["Accept"])
        self.assertIn("Authorization", requests[1][1])
        self.assertEqual(2, len(requests))
        self.assertEqual(result, client.client_delivery())

    def test_projection_reports_ready_new_data_and_publishing(self):
        ready = deltascope_delivery_dashboard.project_delivery_dashboard(_Client(), _Inspector())
        self.assertEqual("ready", ready["state"])
        self.assertEqual(1, ready["queue"]["counts"]["pending"])
        self.assertEqual(12, ready["build"]["currentVariantsMaterialized"])

        changed = deltascope_delivery_dashboard.project_delivery_dashboard(_Client(), _Inspector("ev-2"))
        self.assertEqual("new-data", changed["state"])
        self.assertTrue(changed["newDataAvailable"])

        publishing = deltascope_delivery_dashboard.project_delivery_dashboard(
            _Client(publisher_state="running"), _Inspector("ev-2")
        )
        self.assertEqual("publishing", publishing["state"])

    def test_projection_is_gated_before_local_telemetry_is_read(self):
        inspector = _Inspector()
        result = deltascope_delivery_dashboard.project_delivery_dashboard(_Client(token=False), inspector)
        self.assertEqual("authentication-required", result["state"])
        self.assertEqual(0, inspector.summary_calls)

    def test_html_patch_registers_authenticated_delivery_surface(self):
        html = deltascope_delivery_dashboard._patch_html(developer_view.HTML)
        self.assertIn('id="workbench-delivery"', html)
        self.assertIn("/api/operations/delivery-dashboard", html)
        self.assertIn("Data Delivery", html)
        self.assertIn("navigation never refreshes data", html)
        self.assertIn("Security contract inventory", html)
        self.assertIn("/api/platform-contracts", html)
        self.assertIn("secondaryEngines", html)
        self.assertIn('id="workbench-contracts"', html)
        self.assertIn("Contract Explorer", html)
        self.assertIn("/api/platform-contracts/inventory", html)
        self.assertIn("/api/platform-contracts/resource", html)
        self.assertIn("Copy exact content", html)
        self.assertIn("data-contract-group", html)


if __name__ == "__main__":
    unittest.main()

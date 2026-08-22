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
import build_sqlite_catalog
import sigmascope


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

    def test_sqlite_latest_findings_are_current_and_newest_first(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "evidence.sqlite"
            with closing(__import__("sqlite3").connect(db_path)) as db:
                db.executescript(build_sqlite_catalog.SCHEMA_SQL)
                sigmascope.ensure_schema(db)
                for variant_id, scan_id, when, title in (
                    (1, 10, "2026-08-22T10:00:00Z", "older"),
                    (2, 20, "2026-08-22T12:00:00Z", "newer"),
                ):
                    db.execute("INSERT OR IGNORE INTO sources(source_id,url,name,provider,kind) VALUES(1,'https://example.invalid/repo.json','Example','Example','curated')")
                    db.execute("INSERT INTO plugins(plugin_id,internal_name,canonical_name,first_seen_utc,last_seen_utc,active) VALUES(?,?,?,?,?,1)", (variant_id, f"P{variant_id}", f"Plugin {variant_id}", when, when))
                    db.execute("INSERT INTO plugin_variants(variant_id,plugin_id,source_id,source_entry_key,author,name,assembly_version,dalamud_api_level,download_link_install,repo_url,first_seen_utc,last_seen_utc,active) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)", (variant_id, variant_id, 1, f"v{variant_id}", "Author", f"Plugin {variant_id}", "1.0", 15, "https://example.invalid/p.zip", "https://github.com/example/p", when, when))
                    db.execute("INSERT INTO plugin_security_scans(scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,scanned_at_utc,highest_severity,high_count,report_json) VALUES(?,?,?,?,?,?,?,?,?,'complete',?,'high',1,'{}')", (scan_id, variant_id, variant_id, 1, "1.0", "stable", "https://example.invalid/p.zip", str(variant_id)*64, sigmascope.SCANNER_VERSION, when))
                    db.execute("INSERT INTO plugin_security_current(variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,scanned_at_utc,highest_severity,high_count,findings_json,report_json) VALUES(?,?,?,?,?,?,?,'complete',?,'high',1,'[]','{}')", (variant_id, scan_id, "1.0", "stable", "https://example.invalid/p.zip", str(variant_id)*64, sigmascope.SCANNER_VERSION, when))
                    db.execute("INSERT INTO plugin_security_findings(scan_id,rule_id,severity,category,title,description,evidence_json) VALUES(?,?,'high','test',?,'','[]')", (scan_id, f"rule.{variant_id}", title))
                db.commit()
            inspector = developer_view.SecurityInspector(db_path)
            try:
                rows = inspector.latest_findings(10)
            finally:
                inspector.close()
            self.assertEqual(["newer", "older"], [row["title"] for row in rows])
            self.assertEqual([2, 1], [row["variantId"] for row in rows])

    def test_ui_exposes_findings_operations_and_documentation_without_main_scroll(self) -> None:
        view = (ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        for token in (
            "Latest security findings", "Components & Actions", "Operations / Actions",
            'parsed.path == "/api/operations"', 'parsed.path == "/api/workbench/findings"',
            'data-workbench-nav="docs"', "Documentation library", 'parsed.path == "/api/docs"',
            'parsed.path == "/api/doc"', "#workbench-docs>.docs-shell", "#docTree,#docContent",
        ):
            self.assertIn(token, view)
        self.assertIn("html,body{height:100%;min-height:0;overflow:hidden", view)
        self.assertIn("GitHubOperationsClient", view)


if __name__ == "__main__":
    unittest.main()

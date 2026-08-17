from __future__ import annotations

from contextlib import closing
import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from unittest import mock
from pathlib import Path

import common  # noqa: F401
import build_sqlite_catalog
import security_scan

ROOT = Path(__file__).resolve().parents[2]
SECURITY_TOOLS = ROOT / "tools" / "security"
if str(SECURITY_TOOLS) not in sys.path:
    sys.path.insert(0, str(SECURITY_TOOLS))
from evidence_v2_inspector import V2SecurityInspector

MODULE_PATH = ROOT / "tools" / "security" / "developer_view.py"
spec = importlib.util.spec_from_file_location("omega_security_developer_view", MODULE_PATH)
assert spec and spec.loader
view = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = view
spec.loader.exec_module(view)


def make_evidence(path: Path) -> None:
    with closing(sqlite3.connect(path)) as db:
        db.executescript(build_sqlite_catalog.SCHEMA_SQL)
        security_scan.ensure_schema(db)
        now = "2026-08-17T07:00:00Z"
        db.execute("INSERT INTO sources(source_id,url,name,provider,kind) VALUES(1,?,?,?,?)", ("https://example.invalid/repo.json", "Example repo", "Example", "curated"))
        db.execute("INSERT INTO plugins(plugin_id,internal_name,canonical_name,first_seen_utc,last_seen_utc,active) VALUES(1,'FixturePlugin','Fixture Plugin',?,?,1)", (now, now))
        db.execute("""
            INSERT INTO plugin_variants(variant_id,plugin_id,source_id,source_entry_key,author,name,assembly_version,dalamud_api_level,
                                        download_link_install,repo_url,first_seen_utc,last_seen_utc,active)
            VALUES(1,1,1,'fixture|1.0.0|15|stable','Fixture Author','Fixture Plugin','1.0.0',15,
                   'https://example.invalid/plugin.zip','https://github.com/example/fixture',?,?,1)
        """, (now, now))
        db.execute("""
            INSERT INTO plugin_security_scans(scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_channel,
                                              artifact_url,artifact_sha256,scanner_version,status,scanned_at_utc,highest_severity,
                                              high_count,source_available,source_repository,source_commit,report_json)
            VALUES(1,1,1,1,'1.0.0','stable','https://example.invalid/plugin.zip',?,?,'complete',?,'high',1,1,
                   'https://github.com/example/fixture','abc123',?)
        """, ("a" * 64, security_scan.SCANNER_VERSION, now, json.dumps({
            "source": {"scope": {"mode": "plugin-build-graph", "primaryProject": "FixturePlugin.csproj", "contextProjects": ["Server.csproj"]}},
            "package": {"files": ["FixturePlugin.dll"]},
        })))
        db.execute("""
            INSERT INTO plugin_security_current(variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,
                                                scanner_version,status,scanned_at_utc,highest_severity,high_count,findings_json,
                                                source_available,source_repository,source_commit,report_json)
            VALUES(1,1,'1.0.0','stable','https://example.invalid/plugin.zip',?,?,'complete',?,'high',1,'[]',1,
                   'https://github.com/example/fixture','abc123',?)
        """, ("a" * 64, security_scan.SCANNER_VERSION, now, json.dumps({
            "source": {"scope": {"mode": "plugin-build-graph", "primaryProject": "FixturePlugin.csproj", "contextProjects": ["Server.csproj"]}}
        })))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('public_advisory_source','OSV')")
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('public_advisory_ecosystem','NuGet')")
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('public_advisory_queried_packages','1')")
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('public_advisory_matched_packages','1')")
        db.execute("""
            INSERT INTO plugin_security_findings(scan_id,rule_id,severity,category,title,description,evidence_json)
            VALUES(1,'test.high','high','test','High test finding','Synthetic high finding','["evidence"]')
        """)
        db.execute("""
            INSERT INTO plugin_security_dependencies(dependency_id,scan_id,origin,kind,name,version,resolved_version,status,requirement,evidence_json)
            VALUES(1,1,'artifact','nuget','Newtonsoft.Json','12.0.1','12.0.1','resolved','required','[]')
        """)
        db.execute("""
            INSERT INTO plugin_security_dependency_resolutions(dependency_id,scan_id,source_plugin_id,source_variant_id,dependency_kind,
                                                               dependency_name,dependency_version,resolved_version,normalized_name,component_key,
                                                               requirement,resolution_status,version_status,confidence,match_basis,evidence_json)
            VALUES(1,1,1,1,'nuget','Newtonsoft.Json','12.0.1','12.0.1','newtonsoft.json','nuget:newtonsoft.json',
                   'required','resolved','exact','high','nuget','[]')
        """)
        db.execute("""
            INSERT INTO plugin_security_dependency_advisory_matches(advisory_id,component_key,component_kind,component_name,
                                                                    affected_version,severity,title,advisory_url,advisory_source,refreshed_at_utc)
            VALUES('OSV-TEST-1','nuget:newtonsoft.json','nuget','Newtonsoft.Json','12.0.1','high','Synthetic advisory',
                   'https://osv.dev/vulnerability/OSV-TEST-1','osv',?)
        """, (now,))
        db.execute("""
            INSERT INTO plugin_security_source_artifact_comparisons(scan_id,variant_id,source_available,source_dependency_count,
                                                                    artifact_dependency_count,matched_component_count,comparison_status,
                                                                    source_only_json,artifact_only_json,version_mismatches_json,requirement_mismatches_json)
            VALUES(1,1,1,1,1,1,'matched','[]','[]','[]','[]')
        """)
        db.commit()


def make_marketplace(path: Path, risk_score: int = 40) -> None:
    with closing(sqlite3.connect(path)) as db:
        db.execute("""
            CREATE TABLE marketplace_security_current(
                variant_id INTEGER PRIMARY KEY, highest_severity TEXT, known_advisory_count INTEGER,
                known_advisory_highest_severity TEXT, risk_score INTEGER
            )
        """)
        db.execute("INSERT INTO marketplace_security_current VALUES(1,'high',1,'high',?)", (risk_score,))
        db.commit()


class SecurityDeveloperViewTests(unittest.TestCase):
    def test_developer_view_reads_a_local_v2_snapshot_without_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "security-evidence-v2"
            (root / "indexes").mkdir(parents=True)
            (root / "variants" / "0000").mkdir(parents=True)
            (root / "artifacts" / "aa" / "analysis").mkdir(parents=True)
            (root / "indexes" / "plugins.json").write_text(json.dumps({"currentVariants": [{"variantId": 1, "scanId": 1, "variantPath": "variants/0000/1.json"}]}), encoding="utf-8")
            (root / "artifacts" / "aa" / "analysis" / "manifest.json").write_text(json.dumps({"datasets": {"findings": {"files": [{"path": "artifacts/aa/analysis/findings.json", "encoding": "json"}]}}}), encoding="utf-8")
            (root / "artifacts" / "aa" / "analysis" / "findings.json").write_text(json.dumps([{ "rule_id": "network.endpoint.public-ip-literal", "severity": "caution", "title": "Endpoint: 8.8.8.8"}]), encoding="utf-8")
            (root / "variants" / "0000" / "1.json").write_text(json.dumps({
                "variantId": 1, "plugin": {"plugin_id": 1, "internal_name": "Fixture", "canonical_name": "Fixture"},
                "variant": {"name": "Fixture", "author": "Test", "assembly_version": "1.0.0"},
                "source": {"name": "Fixture feed", "url": "https://example.invalid/repo.json"},
                "current": {"variant_id": 1, "scan_id": 1, "status": "complete", "highest_severity": "caution", "caution_count": 1},
                "analysis": {"path": "artifacts/aa/analysis"}, "derived": {},
            }), encoding="utf-8")
            (root / "index.json").write_text(json.dumps({"schema": "omega.security-evidence.v2", "formatVersion": 2, "counts": {}, "indexes": {"plugins": {"path": "indexes/plugins.json"}}}), encoding="utf-8")
            inspector = V2SecurityInspector(root)
            try:
                self.assertEqual("security-evidence-v2", inspector.summary()["format"])
                self.assertEqual("Fixture", inspector.list_plugins()[0]["canonical_name"])
                self.assertEqual("network.endpoint.public-ip-literal", inspector.plugin_detail(1)["findings"][0]["rule_id"])
                with self.assertRaises(ValueError):
                    inspector.read_sql("SELECT 1")
            finally:
                inspector.close()

    def test_reproduces_static_advisory_and_marketplace_conclusions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "evidence.sqlite"
            market = Path(td) / "market.sqlite"
            make_evidence(evidence)
            make_marketplace(market)
            inspector = view.SecurityInspector(evidence, market)
            try:
                detail = inspector.plugin_detail(1)
                self.assertEqual(1, detail["advisorySummary"]["count"])
                self.assertEqual("high", detail["advisorySummary"]["highestSeverity"])
                self.assertEqual(40, detail["riskScore"])
                failures = [x for x in detail["audit"] if x["status"] == "fail"]
                self.assertEqual([], failures)
                self.assertEqual("FixturePlugin.csproj", detail["sourceScope"]["primaryProject"])
            finally:
                inspector.close()

    def test_projection_drift_is_reported_as_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "evidence.sqlite"
            market = Path(td) / "market.sqlite"
            make_evidence(evidence)
            make_marketplace(market, risk_score=1)
            inspector = view.SecurityInspector(evidence, market)
            try:
                failures = [x for x in inspector.audit_variant(1) if x.status == "fail"]
                self.assertTrue(any(x.code == "projection.security_summary" for x in failures))
            finally:
                inspector.close()

    def test_sql_console_is_read_only_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "evidence.sqlite"
            make_evidence(evidence)
            inspector = view.SecurityInspector(evidence)
            try:
                rows = inspector.read_sql("SELECT internal_name FROM plugins")
                self.assertEqual([["FixturePlugin"]], rows["rows"])
                with self.assertRaises(ValueError):
                    inspector.read_sql("UPDATE plugins SET canonical_name='oops'")
                current = inspector.db.execute("SELECT canonical_name FROM plugins WHERE plugin_id=1").fetchone()[0]
                self.assertEqual("Fixture Plugin", current)
            finally:
                inspector.close()


    def test_default_sql_template_contains_real_line_breaks(self) -> None:
        marker = '<textarea id="sqlText">'
        start = view.HTML.index(marker) + len(marker)
        end = view.HTML.index('</textarea>', start)
        query = view.HTML[start:end]
        self.assertIn("\nFROM plugin_security_findings", query)
        self.assertNotIn("\\nFROM plugin_security_findings", query)

    def test_fetch_bundle_discards_wrong_size_cache_before_reusing_it(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "cache"
            release_dir = cache / "fixture-tag"
            release_dir.mkdir(parents=True)
            archive = release_dir / "fixture.sqlite.zip"
            archive.write_bytes(b"stale")

            source_zip = Path(td) / "fresh.zip"
            with zipfile.ZipFile(source_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("fixture.sqlite", b"SQLite format 3\x00fixture")
            fresh_bytes = source_zip.read_bytes()
            digest = view.hashlib.sha256(fresh_bytes).hexdigest()

            def asset(_tag: str, name: str) -> dict:
                if name.endswith(".sha256"):
                    return {"browser_download_url": "https://example.invalid/sidecar"}
                return {
                    "browser_download_url": "https://example.invalid/fresh",
                    "size": len(fresh_bytes),
                    "digest": f"sha256:{digest}",
                }

            def downloader(_url: str, destination: Path, expected_size: int = 0, label: str = "download") -> Path:
                self.assertEqual(len(fresh_bytes), expected_size)
                destination.write_bytes(fresh_bytes)
                return destination

            with mock.patch.object(view, "release_asset", side_effect=asset), \
                 mock.patch.object(view, "download_text", return_value=digest + "  fixture.sqlite.zip\n"), \
                 mock.patch.object(view, "download_file", side_effect=downloader) as download_mock:
                extracted = view.fetch_bundle("fixture-tag", "fixture.sqlite.zip", cache)

            self.assertEqual(1, download_mock.call_count)
            self.assertEqual(fresh_bytes, archive.read_bytes())
            self.assertTrue(extracted.is_file())


    def test_large_download_resumes_existing_partial_file(self) -> None:
        class FakeResponse:
            status = 206
            headers = {"Content-Range": "bytes 3-5/6", "Content-Length": "3"}
            def __init__(self) -> None:
                self.data = bytearray(b"def")
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def getcode(self) -> int:
                return self.status
            def read(self, size: int = -1) -> bytes:
                if not self.data:
                    return b""
                if size < 0:
                    size = len(self.data)
                out = bytes(self.data[:size])
                del self.data[:size]
                return out

        with tempfile.TemporaryDirectory() as td:
            destination = Path(td) / "evidence.zip"
            part = destination.with_suffix(destination.suffix + ".part")
            part.write_bytes(b"abc")
            with mock.patch.object(view.urllib.request, "urlopen", return_value=FakeResponse()):
                view.download_file("https://example.invalid/evidence.zip", destination, 6, "fixture")
            self.assertEqual(b"abcdef", destination.read_bytes())
            self.assertFalse(part.exists())

    def test_summary_exposes_scanner_generation_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "evidence.sqlite"
            make_evidence(evidence)
            inspector = view.SecurityInspector(evidence)
            try:
                summary = inspector.summary()
                self.assertEqual(1, summary["counts"]["currentAtScanner"])
                self.assertEqual(0, summary["counts"]["legacyCurrent"])
                self.assertEqual(1, summary["counts"]["observedNugetVersions"])
            finally:
                inspector.close()


    def test_global_audit_fails_when_osv_queries_zero_observed_packages(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "evidence.sqlite"
            make_evidence(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.execute("UPDATE catalog_meta SET value='0' WHERE key='public_advisory_queried_packages'")
                db.commit()
            inspector = view.SecurityInspector(evidence)
            try:
                audit = inspector.global_audit()
                failures = [item for item in audit["items"] if item["status"] == "fail"]
                self.assertTrue(any(item["code"] == "osv.coverage.queries" for item in failures))
            finally:
                inspector.close()

    def test_global_audit_checks_database_contract_and_current_conclusions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "evidence.sqlite"
            market = Path(td) / "market.sqlite"
            make_evidence(evidence)
            make_marketplace(market)
            inspector = view.SecurityInspector(evidence, market)
            try:
                audit = inspector.global_audit()
                self.assertEqual(0, audit["counts"]["fail"])
                codes = {x["code"] for x in audit["items"]}
                self.assertIn("database.integrity", codes)
                self.assertIn("artifact.canonical_conclusion", codes)
            finally:
                inspector.close()


    def test_click_through_table_browser_is_read_only_bounded_and_filterable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "evidence.sqlite"
            make_evidence(evidence)
            inspector = view.SecurityInspector(evidence)
            try:
                catalog = inspector.table_catalog()
                names = {item["name"] for item in catalog}
                self.assertIn("plugins", names)
                self.assertIn("plugin_security_findings", names)
                self.assertFalse(any(name.startswith("sqlite_") for name in names))

                page = inspector.browse_table("plugin_security_dependencies", limit=10)
                self.assertEqual("Observed dependencies", page["label"])
                self.assertEqual(1, len(page["rows"]))
                self.assertLessEqual(page["limit"], view.MAX_TABLE_ROWS)
                relationships = {(fk["from"], fk["table"], fk["to"]) for fk in page["foreignKeys"]}
                self.assertIn(("scan_id", "plugin_security_scans", "scan_id"), relationships)

                filtered = inspector.browse_table("plugin_variants", filter_column="variant_id", filter_value="1")
                self.assertEqual(1, len(filtered["rows"]))
                self.assertEqual(1, filtered["rows"][0]["variant_id"])
                self.assertEqual({"column": "variant_id", "value": "1"}, filtered["filter"])

                with self.assertRaises(ValueError):
                    inspector.browse_table("sqlite_master")
                with self.assertRaises(ValueError):
                    inspector.browse_table("plugins", filter_column="definitely_not_a_column", filter_value="1")
                self.assertEqual("Fixture Plugin", inspector.db.execute("SELECT canonical_name FROM plugins WHERE plugin_id=1").fetchone()[0])
            finally:
                inspector.close()

    def test_developer_view_uses_explicit_controls_and_click_through_evidence_browser(self) -> None:
        self.assertIn("Evidence browser", view.HTML)
        self.assertIn("No SQL required", view.HTML)
        self.assertIn("Advanced · read-only SQL console", view.HTML)
        self.assertIn("scanStatusFilter", view.HTML)
        self.assertIn("document.getElementById", view.HTML)
        self.assertNotIn("status.value", view.HTML)
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('parsed.path == "/api/tables"', source)
        self.assertIn('parsed.path == "/api/table"', source)

if __name__ == "__main__":
    unittest.main()

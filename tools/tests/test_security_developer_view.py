from __future__ import annotations

from contextlib import closing
import gzip
import hashlib
import io
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
import sigmascope

ROOT = Path(__file__).resolve().parents[2]
SECURITY_TOOLS = ROOT / "tools" / "security"
if str(SECURITY_TOOLS) not in sys.path:
    sys.path.insert(0, str(SECURITY_TOOLS))
from evidence_v2_inspector import V2SigmascopeInspector

MODULE_PATH = ROOT / "tools" / "security" / "developer_view.py"
spec = importlib.util.spec_from_file_location("omega_security_developer_view", MODULE_PATH)
assert spec and spec.loader
view = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = view
spec.loader.exec_module(view)


def make_evidence(path: Path) -> None:
    with closing(sqlite3.connect(path)) as db:
        db.executescript(build_sqlite_catalog.SCHEMA_SQL)
        sigmascope.ensure_schema(db)
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
        """, ("a" * 64, sigmascope.SCANNER_VERSION, now, json.dumps({
            "source": {"scope": {"mode": "plugin-build-graph", "primaryProject": "FixturePlugin.csproj", "contextProjects": ["Server.csproj"]}},
            "package": {"files": ["FixturePlugin.dll"]},
        })))
        db.execute("""
            INSERT INTO plugin_security_current(variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,
                                                scanner_version,status,scanned_at_utc,highest_severity,high_count,findings_json,
                                                source_available,source_repository,source_commit,report_json)
            VALUES(1,1,'1.0.0','stable','https://example.invalid/plugin.zip',?,?,'complete',?,'high',1,'[]',1,
                   'https://github.com/example/fixture','abc123',?)
        """, ("a" * 64, sigmascope.SCANNER_VERSION, now, json.dumps({
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
        db.execute(
            "UPDATE plugin_security_current SET findings_json=? WHERE variant_id=1",
            (json.dumps([{
                "ruleId": "test.high", "severity": "high", "category": "test",
                "title": "High test finding", "description": "Synthetic high finding", "evidence": ["evidence"],
            }], separators=(",", ":")),),
        )
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
            inspector = V2SigmascopeInspector(root)
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

    def test_current_projection_can_include_derived_findings_without_mutating_scan_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "evidence.sqlite"
            make_evidence(evidence)
            derived = {
                "ruleId": "artifact.cross-source-hash-mismatch",
                "severity": "caution",
                "category": "provenance",
                "title": "Cross-source artifact hash mismatch",
                "description": "Derived current projection finding.",
                "evidence": ["fixture"],
            }
            with closing(sqlite3.connect(evidence)) as db:
                existing = json.loads(db.execute("SELECT findings_json FROM plugin_security_current WHERE variant_id=1").fetchone()[0])
                existing.append(derived)
                db.execute(
                    "UPDATE plugin_security_current SET caution_count=1,findings_json=? WHERE variant_id=1",
                    (json.dumps(existing, separators=(",", ":")),),
                )
                db.commit()
            inspector = view.SecurityInspector(evidence)
            try:
                failures = [x for x in inspector.audit_variant(1) if x.status == "fail"]
                self.assertEqual([], failures)
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
                self.assertEqual(1, summary["counts"]["currentAtSigmascope"])
                self.assertEqual(summary["counts"]["currentAtSigmascope"], summary["counts"]["currentAtScanner"])
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

    def test_global_audit_allows_new_nuget_after_frozen_definitions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            advisories = root / "osv-advisories.json"
            make_evidence(evidence)
            with closing(sqlite3.connect(evidence)) as db:
                db.execute("UPDATE catalog_meta SET value='0' WHERE key='public_advisory_queried_packages'")
                db.execute("UPDATE catalog_meta SET value='0' WHERE key='public_advisory_matched_packages'")
                db.commit()
            advisories.write_text(json.dumps({
                "schema": "omega.public-advisories.v1",
                "generatedAtUtc": "2026-08-20T07:20:53Z",
                "source": "OSV",
                "ecosystem": "NuGet",
                "queriedPackages": 0,
                "matchedPackages": 0,
                "queriedPackageVersionPairs": [],
                "advisories": [],
            }), encoding="utf-8")
            inspector = view.SecurityInspector(evidence, None, advisories)
            try:
                audit = inspector.global_audit()
                failures = [item for item in audit["items"] if item["status"] == "fail"]
                warnings = [item for item in audit["items"] if item["status"] == "warn"]
                passes = [item for item in audit["items"] if item["status"] == "pass"]
                self.assertFalse(any(item["code"].startswith("osv.coverage") for item in failures))
                self.assertTrue(any(item["code"] == "osv.coverage.queries" for item in passes))
                self.assertTrue(any(item["code"] == "osv.coverage.frozen_gap" for item in warnings))
            finally:
                inspector.close()

    def test_global_audit_rejects_inconsistent_frozen_osv_query_universe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "evidence.sqlite"
            advisories = root / "osv-advisories.json"
            make_evidence(evidence)
            advisories.write_text(json.dumps({
                "schema": "omega.public-advisories.v1",
                "generatedAtUtc": "2026-08-20T07:20:53Z",
                "source": "OSV",
                "ecosystem": "NuGet",
                "queriedPackages": 0,
                "matchedPackages": 0,
                "queriedPackageVersionPairs": [{"name": "Newtonsoft.Json", "version": "12.0.1"}],
                "advisories": [],
            }), encoding="utf-8")
            inspector = view.SecurityInspector(evidence, None, advisories)
            try:
                audit = inspector.global_audit()
                failures = [item for item in audit["items"] if item["status"] == "fail"]
                self.assertTrue(any(item["code"] == "osv.coverage.metadata" for item in failures))
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


    def test_online_v2_developer_view_fetches_indexes_then_evidence_lazily(self) -> None:
        class Response:
            def __init__(self, data: bytes):
                self.data = io.BytesIO(data)
                self.headers = {"Content-Length": str(len(data))}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n: int = -1) -> bytes: return self.data.read(n)

        def packed(value) -> bytes:
            return (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")

        finding_bytes = gzip.compress((json.dumps({"rule_id": "network.endpoint", "severity": "caution", "title": "Network endpoint"}) + "\n").encode("utf-8"))
        manifest = {"datasets": {"findings": {"records": 1, "files": [{"path": "artifacts/aa/analysis/findings.jsonl.gz", "encoding": "jsonl+gzip", "sha256": hashlib.sha256(finding_bytes).hexdigest()}]}}}
        variant = {
            "schema": "omega.security-evidence.variant.v2", "formatVersion": 2, "variantId": 1,
            "pluginId": 1, "sourceId": 1,
            "plugin": {"plugin_id": 1, "internal_name": "Fixture", "canonical_name": "Fixture"},
            "variant": {"variant_id": 1, "name": "Fixture", "author": "Test", "assembly_version": "1.0.0"},
            "source": {"source_id": 1, "name": "Fixture feed", "url": "https://example.invalid/repo.json"},
            "current": {"variant_id": 1, "scan_id": 7, "status": "complete", "highest_severity": "caution", "caution_count": 1, "scanner_version": "2.5.0", "scanned_at_utc": "2026-08-18T08:00:00Z"},
            "analysis": {"analysisId": "a" * 64, "path": "artifacts/aa/analysis", "artifactSha256": "b" * 64}, "derived": {},
        }
        variant_bytes = packed(variant)
        plugins = {"schema": "omega.security-evidence.plugins-index.v2", "currentVariants": [{
            "variantId": 1, "scanId": 7, "artifactSha256": "b" * 64, "analysisId": "a" * 64,
            "variantPath": "variants/0000/1.json", "variantSha256": hashlib.sha256(variant_bytes).hexdigest(),
            "summary": {"plugin_id": 1, "internal_name": "Fixture", "canonical_name": "Fixture", "name": "Fixture", "author": "Test", "assembly_version": "1.0.0", "source_name": "Fixture feed", "source_url": "https://example.invalid/repo.json", "scan_id": 7, "scan_status": "complete", "highest_severity": "caution", "caution_count": 1, "scanned_at_utc": "2026-08-18T08:00:00Z", "scanner_version": "2.5.0"},
        }]}
        plugin_bytes = packed(plugins)
        root = {"schema": "omega.security-evidence.v2", "formatVersion": 2, "generatedAtUtc": "2026-08-18T08:01:00Z", "engine": {"name": "Sigmascope", "version": "2.5.0"}, "counts": {"currentVariants": 1}, "revisions": {"evidenceRevision": "ev-v2-1111111111111111"}, "indexes": {"plugins": {"path": "indexes/plugins.json", "sha256": hashlib.sha256(plugin_bytes).hexdigest()}}}
        base = "https://raw.githubusercontent.com/dalagab/omega/security-evidence-v2/"
        files = {
            base + "index.json": packed(root),
            base + "indexes/plugins.json": plugin_bytes,
            base + "variants/0000/1.json": variant_bytes,
            base + "artifacts/aa/analysis/manifest.json": packed(manifest),
            base + "artifacts/aa/analysis/findings.jsonl.gz": finding_bytes,
        }
        requests: list[str] = []
        def fake_urlopen(request, timeout=0):
            del timeout
            url = request.full_url
            requests.append(url)
            if url not in files:
                raise AssertionError(f"unexpected remote fetch: {url}")
            return Response(files[url])

        with tempfile.TemporaryDirectory() as td:
            inspector = V2SigmascopeInspector.online(base_url=base, cache_dir=Path(td) / "cache", cache_limit_bytes=8 * 1024 * 1024, urlopen=fake_urlopen)
            try:
                self.assertEqual([base + "index.json", base + "indexes/plugins.json"], requests)
                self.assertEqual("Fixture", inspector.list_plugins()[0]["canonical_name"])
                self.assertEqual(2, len(requests), "plugin list must not fetch per-variant evidence")
                summary = inspector.summary()
                self.assertTrue(summary["indexSummaryAvailable"])
                self.assertEqual(1, summary["counts"]["findings"])
                detail = inspector.plugin_detail(1)
                self.assertTrue(detail["lazyDatasets"])
                self.assertEqual(1, detail["datasetCounts"]["findings"])
                self.assertIn(base + "variants/0000/1.json", requests)
                self.assertIn(base + "artifacts/aa/analysis/manifest.json", requests)
                self.assertNotIn(base + "artifacts/aa/analysis/findings.jsonl.gz", requests)
                rows = inspector.plugin_dataset(1, "findings")
                self.assertEqual("network.endpoint", rows[0]["rule_id"])
                self.assertIn(base + "artifacts/aa/analysis/findings.jsonl.gz", requests)
                before = len(requests)
                self.assertEqual("network.endpoint", inspector.plugin_dataset(1, "findings")[0]["rule_id"])
                self.assertEqual(before, len(requests), "viewed shards should reuse bounded local cache")
            finally:
                inspector.close()

    def test_online_v2_revision_check_and_refresh_switches_snapshot_namespace(self) -> None:
        class Response:
            def __init__(self, data: bytes): self.data = io.BytesIO(data); self.headers = {"Content-Length": str(len(data))}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n: int = -1) -> bytes: return self.data.read(n)
        def packed(value) -> bytes: return (json.dumps(value, sort_keys=True) + "\n").encode()
        base = "https://raw.githubusercontent.com/dalagab/omega/security-evidence-v2/"
        plugins = {"schema": "omega.security-evidence.plugins-index.v2", "currentVariants": []}
        plugin_bytes = packed(plugins)
        state = {"revision": "ev-v2-1111111111111111"}
        def root_bytes(): return packed({"schema": "omega.security-evidence.v2", "formatVersion": 2, "revisions": {"evidenceRevision": state["revision"]}, "indexes": {"plugins": {"path": "indexes/plugins.json", "sha256": hashlib.sha256(plugin_bytes).hexdigest()}}})
        def fake_urlopen(request, timeout=0):
            del timeout
            if request.full_url == base + "index.json": return Response(root_bytes())
            if request.full_url == base + "indexes/plugins.json": return Response(plugin_bytes)
            raise AssertionError(request.full_url)
        with tempfile.TemporaryDirectory() as td:
            inspector = V2SigmascopeInspector.online(base_url=base, cache_dir=Path(td), urlopen=fake_urlopen)
            try:
                state["revision"] = "ev-v2-2222222222222222"
                status = inspector.source_status(check_remote=True)
                self.assertTrue(status["updateAvailable"])
                self.assertEqual("ev-v2-1111111111111111", status["currentRevision"])
                refreshed = inspector.refresh_online()
                self.assertFalse(refreshed["updateAvailable"])
                self.assertEqual("ev-v2-2222222222222222", refreshed["currentRevision"])
            finally:
                inspector.close()



    def test_online_v2_remains_compatible_with_pre_summary_published_index(self) -> None:
        class Response:
            def __init__(self, data: bytes): self.data = io.BytesIO(data); self.headers = {"Content-Length": str(len(data))}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n: int = -1) -> bytes: return self.data.read(n)
        def packed(value) -> bytes: return (json.dumps(value, sort_keys=True) + "\n").encode()
        base = "https://raw.githubusercontent.com/dalagab/omega/security-evidence-v2/"
        plugins = {"schema": "omega.security-evidence.plugins-index.v2", "currentVariants": [{"variantId": 1, "scanId": 5, "artifactSha256": "a" * 64, "analysisId": "b" * 64, "variantPath": "variants/0000/1.json"}]}
        identities = {"schema": "omega.security-evidence.identities.v2", "plugins": [{"plugin_id": 1, "internal_name": "LegacyFixture", "canonical_name": "Legacy Fixture"}], "plugin_variants": [{"variant_id": 1, "plugin_id": 1, "source_id": 1, "name": "Legacy Fixture", "author": "Test", "assembly_version": "1.0"}], "sources": [{"source_id": 1, "name": "Legacy feed", "url": "https://example.invalid/feed"}]}
        pb, ib = packed(plugins), packed(identities)
        root = {"schema": "omega.security-evidence.v2", "formatVersion": 2, "revisions": {"evidenceRevision": "ev-v2-legacy0000000000"}, "indexes": {"plugins": {"path": "indexes/plugins.json", "sha256": hashlib.sha256(pb).hexdigest()}, "identities": {"path": "indexes/identities.json", "sha256": hashlib.sha256(ib).hexdigest()}}}
        files = {base + "index.json": packed(root), base + "indexes/plugins.json": pb, base + "indexes/identities.json": ib}
        requests=[]
        def fake_urlopen(request, timeout=0):
            del timeout
            requests.append(request.full_url)
            if request.full_url not in files: raise AssertionError(f"legacy online view unexpectedly fetched {request.full_url}")
            return Response(files[request.full_url])
        with tempfile.TemporaryDirectory() as td:
            inspector = V2SigmascopeInspector.online(base_url=base, cache_dir=Path(td), urlopen=fake_urlopen)
            try:
                row = inspector.list_plugins()[0]
                self.assertEqual("Legacy Fixture", row["canonical_name"])
                self.assertEqual("published", row["scan_status"])
                self.assertEqual("unknown", row["highest_severity"])
                self.assertEqual(3, len(requests))
                self.assertFalse(inspector.summary()["indexSummaryAvailable"])
            finally:
                inspector.close()

    def test_default_developer_view_mode_is_online_v2_without_full_release_download(self) -> None:
        fake = mock.Mock()
        fake.evidence_path = "https://raw.githubusercontent.com/dalagab/omega/security-evidence-v2/"
        with mock.patch.object(view.V2SigmascopeInspector, "online", return_value=fake) as online, mock.patch.object(view, "serve", return_value=0) as serve_mock, mock.patch.object(view, "fetch_latest") as fetch_mock:
            self.assertEqual(0, view.main(["--no-browser"]))
        online.assert_called_once()
        serve_mock.assert_called_once()
        fetch_mock.assert_not_called()

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
        self.assertIn('parsed.path == "/api/source"', source)
        self.assertIn('parsed.path == "/api/dataset"', source)
        self.assertIn('path == "/api/refresh"', source)
        self.assertIn('serve-online', source)
        self.assertIn('setInterval(checkEvidenceRevision,60000)', source)

if __name__ == "__main__":
    unittest.main()

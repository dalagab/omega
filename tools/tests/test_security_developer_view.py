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
from evidence_v2_inspector import RemoteEvidenceSource, V2SigmascopeInspector

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
                "current": {"variant_id": 1, "scan_id": 1, "status": "complete", "scanned_at_utc": "2026-08-17T07:00:00Z", "highest_severity": "caution", "caution_count": 1, "findings_json": [{"ruleId": "network.endpoint.public-ip-literal", "severity": "caution", "title": "Endpoint: 8.8.8.8"}]},
                "analysis": {"path": "artifacts/aa/analysis"}, "derived": {},
            }), encoding="utf-8")
            (root / "index.json").write_text(json.dumps({"schema": "omega.security-evidence.v2", "formatVersion": 2, "counts": {}, "indexes": {"plugins": {"path": "indexes/plugins.json"}}}), encoding="utf-8")
            inspector = V2SigmascopeInspector(root)
            try:
                self.assertEqual("security-evidence-v2", inspector.summary()["format"])
                self.assertEqual("Fixture", inspector.list_plugins()[0]["canonical_name"])
                self.assertEqual("network.endpoint.public-ip-literal", inspector.plugin_detail(1)["findings"][0]["rule_id"])
                latest = inspector.latest_findings(5)
                self.assertEqual(1, len(latest))
                self.assertEqual("Endpoint: 8.8.8.8", latest[0]["title"])
                self.assertEqual(1, latest[0]["variantId"])
                with self.assertRaises(ValueError):
                    inspector.read_sql("SELECT 1")
            finally:
                inspector.close()

    def test_v2_workbench_case_inputs_are_loaded_lazily_from_retained_observations_and_rule_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "security-evidence-v2"
            (root / "indexes").mkdir(parents=True)
            (root / "variants" / "0000").mkdir(parents=True)
            (root / "artifacts" / "aa" / "analysis").mkdir(parents=True)
            (root / "rule-projections" / "variants").mkdir(parents=True)
            (root / "indexes" / "plugins.json").write_text(json.dumps({"currentVariants": [{"variantId": 1, "scanId": 1, "variantPath": "variants/0000/1.json"}]}), encoding="utf-8")
            (root / "artifacts" / "aa" / "analysis" / "manifest.json").write_text(json.dumps({
                "datasets": {
                    "staticPatternMatches": {"files": [{"path": "artifacts/aa/analysis/static.json", "encoding": "json"}]},
                    "networkEndpoints": {"files": [{"path": "artifacts/aa/analysis/endpoints.json", "encoding": "json"}]},
                }
            }), encoding="utf-8")
            (root / "artifacts" / "aa" / "analysis" / "static.json").write_text(json.dumps([
                {"origin": "artifact", "pattern": "HttpWebRequest", "evidenceLabel": "metadata:Fixture.dll"},
                {"origin": "artifact", "pattern": "Process.Start", "evidenceLabel": "metadata:Fixture.dll"},
            ]), encoding="utf-8")
            (root / "artifacts" / "aa" / "analysis" / "endpoints.json").write_text(json.dumps([
                {"host": "api.example.test", "url": "https://api.example.test"},
            ]), encoding="utf-8")
            (root / "variants" / "0000" / "1.json").write_text(json.dumps({
                "variantId": 1,
                "plugin": {"plugin_id": 1, "internal_name": "Fixture", "canonical_name": "Fixture"},
                "variant": {"name": "Fixture", "author": "Test", "assembly_version": "1.0.0"},
                "source": {"name": "Fixture feed", "url": "https://example.invalid/repo.json"},
                "current": {"variant_id": 1, "scan_id": 1, "status": "complete", "scanned_at_utc": "2026-08-21T10:00:00Z", "highest_severity": "high", "high_count": 1, "findings_json": [{"ruleId": "compound.network-execute", "severity": "high", "title": "Network + execution"}]},
                "analysis": {"path": "artifacts/aa/analysis"}, "derived": {},
                "observations": {"collections": {
                    "staticPatternMatches": {"backingDataset": "staticPatternMatches", "completeness": "retained"},
                    "networkEndpoints": {"backingDataset": "networkEndpoints", "completeness": "retained"},
                }},
            }), encoding="utf-8")
            (root / "rule-projections" / "variants" / "1.json").write_text(json.dumps({
                "schema": "omega.sigmascope.srl-rule-projection.v1", "variantId": 1,
                "projectionRevision": "projection-1", "ruleSetRevision": "rules-1",
                "facts": ["network.http", "process.launch"], "matchedRuleIds": ["compound.network-execute"],
                "findings": [{"ruleId": "compound.network-execute", "findingId": "compound.network-execute", "severity": "high"}],
                "productionWriteBack": False,
            }), encoding="utf-8")
            (root / "rule-projections" / "reanalysis-requests.json").write_text(json.dumps({
                "schema": "omega.sigmascope.srl-reanalysis-requests.v1", "requests": [], "queueMutationAuthorized": False,
            }), encoding="utf-8")
            (root / "rule-projections" / "analysis-requests.json").write_text(json.dumps({
                "schema": "omega.stigma-1.analysis-requests.v1",
                "requests": [{
                    "variantId": 1, "profile": "artifact-differential-v1", "depth": "extended",
                    "compareWith": "stable-artifact-baseline", "ruleId": "provenance.deep",
                    "reason": "fixture divergence",
                }],
                "queueMutationScope": "deep-scan-evidence-acquisition-only",
                "productionFindingsWriteBack": False,
            }), encoding="utf-8")
            (root / "rule-projections" / "index.json").write_text(json.dumps({
                "schema": "omega.sigmascope.srl-rule-projection-set.v1", "projectionSetRevision": "set-1", "ruleSetRevision": "rules-1",
                "productionRuleEvaluationEnabled": False, "productionWriteBack": False, "queueMutationAuthorized": False,
                "variants": [{"variantId": 1, "path": "variants/1.json"}],
                "reanalysisRequests": {"path": "reanalysis-requests.json"},
                "analysisRequests": {"path": "analysis-requests.json"},
            }), encoding="utf-8")
            (root / "index.json").write_text(json.dumps({
                "schema": "omega.security-evidence.v2", "formatVersion": 2, "counts": {},
                "indexes": {"plugins": {"path": "indexes/plugins.json"}},
                "srlRuleProjections": {"path": "rule-projections/index.json", "projectionSetRevision": "set-1", "ruleSetRevision": "rules-1", "productionWriteBack": False, "queueMutationAuthorized": False},
            }), encoding="utf-8")
            inspector = V2SigmascopeInspector(root)
            try:
                rows = inspector.workbench_observation_rows(1, per_collection_limit=1)
                self.assertEqual(1, len(rows["staticPatternMatches"]))
                self.assertEqual("HttpWebRequest", rows["staticPatternMatches"][0]["pattern"])
                self.assertEqual("api.example.test", rows["networkEndpoints"][0]["host"])
                state = inspector.srl_projection_state(1)
                self.assertTrue(state["available"])
                self.assertEqual("projection-1", state["projection"]["projectionRevision"])
                self.assertFalse(state["productionWriteBack"])
                self.assertFalse(state["queueMutationAuthorized"])
                self.assertEqual("artifact-differential-v1", state["analysisRequest"]["profile"])
                self.assertEqual("extended", state["analysisRequest"]["depth"])
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


    def test_metric_card_wiring_helper_is_defined_for_both_metric_groups(self) -> None:
        self.assertIn("function wireMetricCards(root)", view.HTML)
        self.assertIn("wireMetricCards($('summaryCards'))", view.HTML)
        self.assertIn("wireMetricCards($('allMetricCards'))", view.HTML)
        self.assertLess(view.HTML.index("function wireMetricCards(root)"), view.HTML.index("async function init()"))

    def test_behavior_consistency_panel_is_present_and_keeps_developer_claims_non_authoritative(self) -> None:
        self.assertIn("function renderBehaviorConsistency(d)", view.HTML)
        self.assertIn("Behavior consistency · observed ↔ developer-declared", view.HTML)
        self.assertIn("Developer explanation:", view.HTML)
        self.assertIn("Developer claims do not suppress, downgrade, or prove SigmaScope observations.", view.HTML)
        self.assertLess(view.HTML.index("function renderBehaviorConsistency(d)"), view.HTML.index("function researchCaseHtml(d,id)"))

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


    def test_deltascope_browses_modern_v2_lifecycle_queue_secondary_and_forensics(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "security-evidence-v2"
            (root / "indexes").mkdir(parents=True)
            (root / "variants" / "0000").mkdir(parents=True)
            (root / "variants" / "history").mkdir(parents=True)
            analysis = root / "artifacts" / "aa" / "analysis"
            analysis.mkdir(parents=True)

            report = {
                "artifactIdentityContractVersion": 1,
                "manifestObservationContractVersion": 1,
                "sourceAttributionContractVersion": 1,
                "secondarySecurityContractVersion": 3,
                "scanProvenance": {"workType": "source", "artifactAnalysisRevision": "artifact-v3", "sourceAnalysisRevision": "source-v1"},
                "artifactIdentity": {"schema": "omega.sigmascope.artifact-identity.v1", "artifactSha256": "a" * 64, "artifactBytes": 1234},
                "manifestObservation": {"schema": "omega.manifest-observation.v1", "observationKey": "fixture"},
                "source": {
                    "available": True, "repository": "https://github.com/example/fixture", "commit": "b" * 40,
                    "attribution": {"schema": "omega.artifact-source-attribution.v1", "confidence": 70, "coverageLabel": "Version-correlated source", "basis": ["version_match"]},
                    "provenance": {"identityMatched": True, "versionMatched": True},
                },
                "secondarySecurity": {
                    "schema": "omega.sigmascope.secondary-security.v1", "artifactSha256": "a" * 64,
                    "semantics": "supplemental-evidence-only", "matchCount": 1,
                    "engines": [{
                        "engine": "yara", "status": "complete", "available": True, "enabled": True, "version": "4.5.0",
                        "scanScope": {"schema": "omega.sigmascope.yara-scan-scope.v1", "artifactContainerScanned": True, "archiveMembersScanned": 2, "targetCount": 3},
                        "matches": [{"rule": "Omega_Test", "ruleClass": "compound-abuse", "confidence": "high", "license": "LicenseRef-Omega-First-Party", "target": {"kind": "archive-member", "path": "Fixture.dll", "sha256": "c" * 64, "bytes": 42}}],
                    }, {"engine": "clamav", "status": "complete", "available": True, "enabled": True, "version": "ClamAV fixture", "matches": []}],
                },
                "package": {"archive": "Fixture.zip", "fileCount": 4, "bundledManagedAssemblyCount": 1},
                "intelligence": {
                    "endpointSummary": {"schema": "omega.sigmascope.endpoint-summary.v1", "literalCount": 1, "concreteDestinationCount": 1, "hosts": ["api.example.test"]},
                    "networkEndpoints": [{"host": "api.example.test", "classification": "unrecognised-host", "originType": "source-code", "confidence": "High", "concreteDestinationEvidence": True}],
                    "componentSummary": {"schema": "omega.sigmascope.component-summary.v1", "dependencyCount": 2, "nativeRelationships": [{"library": "kernel32.dll", "disposition": "platform-library", "directManagedCallObserved": True}]},
                    "coverage": {"managedMetadata": True}, "limits": {"calls": 20000},
                },
            }
            current_payload = {
                "variantId": 1,
                "plugin": {"plugin_id": 1, "internal_name": "ModernFixture", "canonical_name": "Modern Fixture"},
                "variant": {"variant_id": 1, "name": "Modern Fixture", "author": "Test", "assembly_version": "2.14.0"},
                "source": {"source_id": 1, "name": "Fixture feed", "url": "https://example.test/repo.json"},
                "current": {"variant_id": 1, "scan_id": 9, "status": "complete", "highest_severity": "caution", "caution_count": 1, "source_attribution_confidence": 70, "report_json": report},
                "analysis": {"path": "artifacts/aa/analysis", "artifactSha256": "a" * 64, "analysisId": "d" * 64},
                "derived": {"sourceArtifactComparison": {"comparisonStatus": "matched"}, "scanLineage": {"representativeScanId": 8}, "dependencyDrift": []},
            }
            historical_payload = {**current_payload, "current": {**current_payload["current"], "scan_id": 8}, "lifecycle": {"state": "superseded", "terminal": True, "reason": "artifact_identity_changed"}}
            (root / "variants" / "0000" / "1.json").write_text(json.dumps(current_payload), encoding="utf-8")
            (root / "variants" / "history" / "1-old.json").write_text(json.dumps(historical_payload), encoding="utf-8")

            datasets = {
                "findings": [{"rule_id": "fixture", "severity": "caution", "title": "Fixture"}],
                "assemblies": [{"path": "Fixture.dll", "assembly_name": "Fixture"}],
                "imports": [{"assembly_path": "Fixture.dll", "native_library": "kernel32.dll", "entry_point": "CreateFileW"}],
                "reachability": [{"method": "Fixture.Run", "reachable": True}],
                "symbols": [{"assembly_path": "Fixture.dll", "symbol": "Fixture.Run"}],
                "calls": [{"caller": "Fixture.Run", "target": "CreateFileW"}],
            }
            manifest = {"datasets": {}}
            for name, rows in datasets.items():
                path = analysis / f"{name}.json"
                path.write_text(json.dumps(rows), encoding="utf-8")
                manifest["datasets"][name] = {"records": len(rows), "recordDigest": name + "-digest", "files": [{"path": f"artifacts/aa/analysis/{name}.json", "encoding": "json"}]}
            manifest_path = analysis / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

            plugins_index = {
                "schema": "omega.security-evidence.plugins-index.v2", "lifecycleContractVersion": 1,
                "currentVariants": [{"variantId": 1, "scanId": 9, "variantPath": "variants/0000/1.json", "summary": {"plugin_id": 1, "internal_name": "ModernFixture", "canonical_name": "Modern Fixture", "scan_status": "complete", "highest_severity": "caution", "caution_count": 1, "source_available": 1, "source_repository": "https://github.com/example/fixture", "source_attribution_confidence": 70, "source_coverage_label": "Version-correlated source"}}],
                "terminalVariants": [],
                "historicalSnapshots": [{"variantId": 1, "scanId": 8, "variantPath": "variants/history/1-old.json", "lifecycle": {"state": "superseded", "terminal": True}, "summary": {"plugin_id": 1, "canonical_name": "Modern Fixture", "lifecycle_state": "superseded"}}],
            }
            (root / "indexes" / "plugins.json").write_text(json.dumps(plugins_index), encoding="utf-8")
            global_indexes = {
                "artifacts": {"artifacts": [{"artifactSha256": "a" * 64, "currentVariants": [1], "variants": [1], "historicalSnapshots": [], "terminalSnapshots": [], "analyses": [{"analysisId": "d" * 64, "path": "artifacts/aa/analysis", "manifest": {"path": "artifacts/aa/analysis/manifest.json", "sha256": "__MANIFEST_SHA__", "bytes": 0}}]}]},
                "dependency-components": {"records": [{"component": "kernel32.dll", "family": "native"}]},
                "advisories": {"records": [{"id": "GHSA-fixture"}]},
                "nuget": {"packages": [{"package": "Fixture.Package", "version": "1.0.0"}]},
                "ipc": {"providers": [{"channel": "Fixture.Channel", "variantId": 1}]},
                "identities": {"plugins": [{"plugin_id": 1, "internal_name": "ModernFixture"}], "plugin_variants": [{"variant_id": 1, "plugin_id": 1}], "sources": [{"source_id": 1, "name": "Fixture feed"}]},
            }
            index_desc = {"plugins": {"path": "indexes/plugins.json"}}
            for key, payload in global_indexes.items():
                if key == "artifacts":
                    payload["artifacts"][0]["analyses"][0]["manifest"]["sha256"] = manifest_sha
                    payload["artifacts"][0]["analyses"][0]["manifest"]["bytes"] = manifest_path.stat().st_size
                filename = key + ".json"
                (root / "indexes" / filename).write_text(json.dumps(payload), encoding="utf-8")
                root_key = {"dependency-components": "dependencyComponents"}.get(key, key)
                index_desc[root_key] = {"path": "indexes/" + filename}
            queue = {"schema": "omega.sigmascope.queue-state.v2", "items": {"variant:2:artifact": {"queueKey": "variant:2:artifact", "variantId": 2, "workType": "artifact", "state": "pending", "reasons": ["new_variant"]}}, "recentCompleted": [{"queueKey": "variant:1:source", "variantId": 1, "workType": "source", "state": "complete"}]}
            (root / "scanner-queue.json").write_text(json.dumps(queue), encoding="utf-8")
            root_index = {
                "schema": "omega.security-evidence.v2", "formatVersion": 2, "engine": {"name": "Sigmascope", "version": "2.14.0"},
                "counts": {"currentVariants": 1, "historicalSnapshots": 1, "analyses": 1, "artifactGroups": 1, "dependencyComponents": 1, "advisories": 1, "nugetPackageVersionPairs": 1},
                "indexes": index_desc,
                "scannerQueue": {"path": "scanner-queue.json", "summary": {"total": 2, "states": {"pending": 1, "complete": 1, "retry": 0}}},
                "revisions": {"evidenceRevision": "ev-v2-modern", "artifactAnalysisRevision": "artifact-v3", "sourceAnalysisRevision": "source-v1"},
                "source": {"scan": {"queueBatch": {"selectedCount": 20, "scanElapsedSeconds": 123.4}}},
            }
            (root / "index.json").write_text(json.dumps(root_index), encoding="utf-8")

            inspector = V2SigmascopeInspector(root)
            try:
                summary = inspector.summary()
                self.assertEqual(1, summary["counts"]["historicalSnapshots"])
                self.assertEqual(1, summary["counts"]["queuePending"])
                self.assertEqual(20, summary["lastBatch"]["selectedCount"])
                detail = inspector.plugin_detail(1)
                self.assertEqual(3, detail["contracts"]["secondarySecurityContractVersion"])
                self.assertEqual(70, detail["sourceAttribution"]["confidence"])
                self.assertTrue(detail["sourceCoverage"]["sourceCodeAvailable"])
                self.assertEqual("artifact+source", detail["sourceCoverage"]["mode"])
                self.assertEqual("source+artifact", inspector.list_plugins()[0]["source_code_status"])
                self.assertEqual(1, detail["secondarySecurity"]["matchCount"])
                self.assertEqual(1, detail["researcher"]["secondaryMatchCount"])
                self.assertEqual("urgent", detail["researcher"]["priority"])
                self.assertTrue(detail["researcher"]["signals"])
                self.assertEqual("api.example.test", detail["endpointSummary"]["hosts"][0])
                self.assertTrue(detail["componentSummary"]["nativeRelationships"][0]["directManagedCallObserved"])
                self.assertIn("assemblies", {row["name"] for row in detail["datasetCatalog"]})
                self.assertEqual("Fixture.dll", inspector.plugin_dataset(1, "assemblies")[0]["path"])
                self.assertEqual("superseded", inspector.variant_snapshots(1)[1]["snapshotKind"])
                snapshot = inspector.snapshot_detail("variants/history/1-old.json")
                self.assertEqual("superseded", snapshot["snapshotKind"])
                self.assertEqual("superseded", snapshot["lifecycle"]["state"])
                self.assertEqual("artifact", inspector.browse_table("v2_queue_items")["rows"][0]["workType"])
                analyses = inspector.browse_table("v2_analyses")["rows"]
                self.assertEqual(1, len(analyses))
                self.assertEqual("d" * 64, analyses[0]["analysisId"])
                self.assertEqual("artifacts/aa/analysis/manifest.json", analyses[0]["manifestPath"])
                self.assertIn("datasets", inspector.analysis_manifest(analyses[0]["manifestPath"]))
                breakdown = inspector.browse_table("v2_finding_breakdown")["rows"]
                self.assertEqual(1, breakdown[0]["finding_count"])
                self.assertEqual(1, len(inspector.browse_table("v2_finding_breakdown", filter_column="caution_count", filter_value="__positive__")["rows"]))
                self.assertEqual("native", inspector.browse_table("v2_dependency_components")["rows"][0]["family"])
                self.assertEqual("CreateFileW", inspector.browse_table("plugin_security_managed_imports", filter_column="variant_id", filter_value="1")["rows"][0]["entry_point"])
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

    def test_online_cache_uses_short_hashed_paths_for_deep_evidence_members(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # Simulate the long Windows Store Python cache prefix that previously pushed
            # immutable analysis paths over MAX_PATH.
            base = Path(td) / ("w" * 120)
            source = RemoteEvidenceSource(
                "https://raw.githubusercontent.com/dalagab/omega/security-evidence-v2/",
                base,
                urlopen=lambda *args, **kwargs: None,
            )
            source.set_revision("ev-v2-9f3c6bf213892b8c")
            relative = "artifacts/e7/" + "e7" * 32 + "/analyses/" + "a1" * 32 + "/forensics/reachability-0001.jsonl.gz"
            path = source._cache_path(relative)
            self.assertLess(len(str(path)), 240)
            self.assertNotIn("artifacts", str(path))
            self.assertNotIn("analyses", str(path))
            self.assertEqual(".bin", path.suffix)
            self.assertEqual(path, source._cache_path(relative), "cache key must be deterministic")

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



    def test_online_plugin_open_recovers_when_branch_publishes_between_index_and_variant_fetch(self) -> None:
        class Response:
            def __init__(self, data: bytes):
                self.data = io.BytesIO(data)
                self.headers = {"Content-Length": str(len(data))}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n: int = -1) -> bytes: return self.data.read(n)

        def packed(value) -> bytes:
            return (json.dumps(value, sort_keys=True) + "\n").encode()

        base = "https://raw.githubusercontent.com/dalagab/omega/security-evidence-v2/"
        manifest = {"datasets": {}}
        variant1 = {
            "schema": "omega.security-evidence.variant.v2", "formatVersion": 2, "variantId": 1,
            "plugin": {"plugin_id": 1, "internal_name": "RaceFixture", "canonical_name": "Race Fixture"},
            "variant": {"variant_id": 1, "name": "Race Fixture", "assembly_version": "1.0"},
            "source": {},
            "current": {"variant_id": 1, "scan_id": 1, "status": "complete", "highest_severity": "none", "report_json": {}},
            "analysis": {"analysisId": "a" * 64, "path": "artifacts/aa/analysis", "artifactSha256": "b" * 64},
            "derived": {},
        }
        variant2 = {**variant1, "current": {**variant1["current"], "scan_id": 2, "scanned_at_utc": "2026-08-20T21:00:00Z"}}
        vb1, vb2 = packed(variant1), packed(variant2)
        plugins1 = {"schema": "omega.security-evidence.plugins-index.v2", "currentVariants": [{
            "variantId": 1, "scanId": 1, "variantPath": "variants/0000/1.json", "variantSha256": hashlib.sha256(vb1).hexdigest(),
            "summary": {"plugin_id": 1, "internal_name": "RaceFixture", "canonical_name": "Race Fixture", "scan_id": 1, "scan_status": "complete", "highest_severity": "none"},
        }]}
        plugins2 = {"schema": "omega.security-evidence.plugins-index.v2", "currentVariants": [{
            "variantId": 1, "scanId": 2, "variantPath": "variants/0000/1.json", "variantSha256": hashlib.sha256(vb2).hexdigest(),
            "summary": {"plugin_id": 1, "internal_name": "RaceFixture", "canonical_name": "Race Fixture", "scan_id": 2, "scan_status": "complete", "highest_severity": "none"},
        }]}
        pb1, pb2 = packed(plugins1), packed(plugins2)
        root1 = {"schema": "omega.security-evidence.v2", "formatVersion": 2, "revisions": {"evidenceRevision": "ev-v2-race-old"}, "indexes": {"plugins": {"path": "indexes/plugins.json", "sha256": hashlib.sha256(pb1).hexdigest()}}}
        root2 = {"schema": "omega.security-evidence.v2", "formatVersion": 2, "revisions": {"evidenceRevision": "ev-v2-race-new"}, "indexes": {"plugins": {"path": "indexes/plugins.json", "sha256": hashlib.sha256(pb2).hexdigest()}}}
        state = {"new": False}

        def fake_urlopen(request, timeout=0):
            del timeout
            url = request.full_url
            if url == base + "index.json":
                return Response(packed(root2 if state["new"] else root1))
            if url == base + "indexes/plugins.json":
                return Response(pb2 if state["new"] else pb1)
            if url == base + "variants/0000/1.json":
                state["new"] = True
                return Response(vb2)
            if url == base + "artifacts/aa/analysis/manifest.json":
                return Response(packed(manifest))
            raise AssertionError(url)

        with tempfile.TemporaryDirectory() as td:
            inspector = V2SigmascopeInspector.online(base_url=base, cache_dir=Path(td), urlopen=fake_urlopen)
            try:
                detail = inspector.plugin_detail(1)
                self.assertTrue(detail["onlineSnapshotRefreshed"])
                self.assertEqual(2, detail["identity"]["scan_id"])
                self.assertEqual("ev-v2-race-new", inspector.source_status()["currentRevision"])
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

    def test_developer_view_uses_research_workbench_with_advanced_raw_evidence(self) -> None:
        self.assertIn("SECURITY RESEARCH WORKBENCH", view.HTML)
        self.assertIn("Research queue", view.HTML)
        self.assertIn("Journey", view.HTML)
        self.assertIn("Plugin journey", view.HTML)
        self.assertIn("/api/workbench/journey", view.HTML)
        self.assertIn("Triage", view.HTML)
        self.assertIn("Malware", view.HTML)
        self.assertIn("Code & native", view.HTML)
        self.assertIn("Supply chain", view.HTML)
        self.assertIn("Advanced · raw Evidence-v2 / database browser", view.HTML)
        self.assertIn("Metrics & coverage · exact drill-down counts", view.HTML)
        self.assertIn("Never scanned", view.HTML)
        self.assertIn("SOURCE CODE", view.HTML)
        self.assertIn("ARTIFACT ONLY", view.HTML)
        self.assertIn("sourceCoverage", MODULE_PATH.read_text(encoding="utf-8"))
        self.assertIn("Advanced · read-only SQL console", view.HTML)
        self.assertIn("scanStatusFilter", view.HTML)
        self.assertIn("document.getElementById", view.HTML)
        self.assertNotIn("status.value", view.HTML)
        self.assertIn("rule-smart-editor", view.HTML)
        self.assertIn("Context intelligence", view.HTML)
        self.assertIn("Rule flow", view.HTML)
        self.assertIn("Ctrl/Cmd+Space", view.HTML)
        self.assertIn("Prose spellcheck", view.HTML)
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('parsed.path == "/api/tables"', source)
        self.assertIn('parsed.path == "/api/table"', source)
        self.assertIn('parsed.path == "/api/source"', source)
        self.assertIn('parsed.path == "/api/dataset"', source)
        self.assertIn('path == "/api/refresh"', source)
        self.assertIn('path == "/api/rule-lab/intelligence"', source)
        self.assertIn('path == "/api/rule-lab/format"', source)
        self.assertIn('serve-online', source)
        self.assertIn('setInterval(checkEvidenceRevision,60000)', source)

if __name__ == "__main__":
    unittest.main()

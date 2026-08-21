from __future__ import annotations

from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import common
import artifact_source_model as model
import build_sqlite_catalog
import sigmascope
import test_sqlite_catalog


class ArtifactSourceModelTests(unittest.TestCase):
    def test_machine_confidence_ladder_is_numeric_and_100_is_reserved_for_proof(self) -> None:
        current = model.attribution_from_source_result({
            "available": True,
            "repository": "https://github.com/example/plugin",
            "commit": "a" * 40,
            "provenance": {"identityMatched": True, "selectedRefKind": "default-branch", "selectedRef": "main"},
        })
        self.assertEqual(40, current["confidence"])
        self.assertIn("default_branch", current["basis"])

        correlated = model.attribution_from_source_result({
            "available": True,
            "repository": "https://github.com/example/plugin",
            "commit": "b" * 40,
            "provenance": {"identityMatched": True, "versionMatched": True, "selectedRefKind": "version-tag", "selectedRef": "v1.2.3"},
        })
        self.assertEqual(70, correlated["confidence"])
        self.assertIn("version_match", correlated["basis"])

        pinned = model.attribution_from_source_result({
            "available": True,
            "repository": "https://github.com/example/plugin",
            "commit": "c" * 40,
            "provenance": {"identityMatched": True, "artifactPinnedCommit": "c" * 40},
        })
        self.assertEqual(95, pinned["confidence"])

        proof = model.attribution_from_source_result({
            "available": True,
            "repository": "https://github.com/example/plugin",
            "commit": "d" * 40,
            "provenance": {"identityMatched": True, "artifactPinnedCommit": "d" * 40, "reproducibleSourceToArtifact": True},
        })
        self.assertEqual(100, proof["confidence"])
        self.assertIn("reproducible_build", proof["basis"])

    def test_manifest_observation_identity_is_stable_and_attribution_is_derived(self) -> None:
        observation = model.manifest_observation_contract(
            17, "stable", "ExamplePlugin", "1.2.3",
            "https://example.invalid/plugin.zip", "https://github.com/example/plugin", observation_id=99,
        )
        self.assertEqual(model.MANIFEST_OBSERVATION_SCHEMA, observation["schema"])
        self.assertEqual(17, observation["variantId"])
        self.assertEqual(
            model.manifest_observation_key(17, "stable", "ExamplePlugin", "1.2.3",
                                           "https://example.invalid/plugin.zip", "https://github.com/example/plugin"),
            observation["observationKey"],
        )

        source = {
            "available": True,
            "repository": "https://github.com/example/plugin",
            "commit": "a" * 40,
            "provenance": {"identityMatched": True, "versionMatched": True, "selectedRefKind": "version-tag", "selectedRef": "v1.2.3"},
        }
        canonical = model.attribution_from_source_result(source)
        self.assertEqual([], model.attribution_invariant_errors(source, canonical))
        hand_authored = dict(canonical)
        hand_authored["confidence"] = 95
        errors = model.attribution_invariant_errors(source, hand_authored)
        self.assertTrue(any("not derivable" in item for item in errors))

    def test_alias_collision_becomes_ambiguous_never_automatic(self) -> None:
        rows = [
            {"plugin_id": 1, "normalized_value": "same"},
            {"plugin_id": 2, "normalized_value": "same"},
            {"plugin_id": 3, "normalized_value": "different"},
        ]
        result = model.resolve_identity_candidates(rows, "SAME")
        self.assertEqual("ambiguous", result["status"])
        self.assertEqual([1, 2], result["pluginIds"])
        self.assertEqual("resolved", model.resolve_identity_candidates(rows, "different")["status"])
        self.assertEqual("unresolved", model.resolve_identity_candidates(rows, "missing")["status"])

    def test_catalog_preserves_manifest_observation_separately_from_source_candidate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-artifact-source-catalog-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            doc = json.loads(enriched.read_text(encoding="utf-8"))
            for source in doc["sources"]:
                for plugin in source.get("plugins") or []:
                    plugin["repoUrl"] = "https://github.com/ExampleOrg/ExamplePlugin"
                    plugin["downloadLinkInstall"] = "https://github.com/ExampleOrg/ExamplePlugin/releases/download/v1.0.0/plugin.zip"
            enriched.write_text(json.dumps(doc), encoding="utf-8")
            out = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, out, curated, raw, enriched, websites)
            with closing(sqlite3.connect(out / "omega-catalog.sqlite")) as db:
                db.row_factory = sqlite3.Row
                observations = db.execute("SELECT * FROM manifest_observations WHERE active=1 ORDER BY observation_id").fetchall()
                self.assertEqual(2, len(observations))
                self.assertTrue(all(row["channel"] == "stable" for row in observations))
                repos = db.execute("SELECT * FROM source_repositories ORDER BY repository_key").fetchall()
                self.assertEqual(1, len(repos))
                self.assertEqual("https://github.com/ExampleOrg/ExamplePlugin", repos[0]["canonical_url"])
                candidates = db.execute("SELECT COUNT(*) FROM manifest_source_candidates").fetchone()[0]
                self.assertEqual(2, candidates)
                self.assertGreaterEqual(db.execute("SELECT COUNT(*) FROM source_repository_aliases").fetchone()[0], 2)

    def test_sigmascope_persists_artifact_and_source_attribution_as_separate_contracts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-artifact-source-security-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            out = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, out, curated, raw, enriched, websites)
            with closing(sqlite3.connect(out / "omega-catalog.sqlite")) as db:
                db.row_factory = sqlite3.Row
                sigmascope.ensure_schema(db)
                row = db.execute("SELECT variant_id,plugin_id,source_id FROM plugin_variants ORDER BY variant_id LIMIT 1").fetchone()
                cur = db.execute(
                    "INSERT INTO plugin_security_scans(plugin_id,variant_id,source_id,status,artifact_sha256,scanner_version) VALUES(?,?,?,?,?,?)",
                    (row["plugin_id"], row["variant_id"], row["source_id"], "complete", "a" * 64, sigmascope.SCANNER_VERSION),
                )
                scan_id = int(cur.lastrowid)
                result = {
                    "artifactSha256": "a" * 64,
                    "artifactBytes": 12345,
                    "scannedAtUtc": "2026-08-19T12:00:00Z",
                    "status": "complete",
                    "source": {
                        "available": True,
                        "repository": "https://github.com/ExampleOrg/ExamplePlugin",
                        "commit": "b" * 40,
                        "branch": "v1.0.0",
                        "scope": {"primaryProject": "src/ExamplePlugin/ExamplePlugin.csproj"},
                        "provenance": {
                            "identityMatched": True,
                            "versionMatched": True,
                            "selectedRefKind": "version-tag",
                            "selectedRef": "v1.0.0",
                            "manifestRepositoryMatched": True,
                        },
                    },
                }
                sigmascope.persist_artifact_source_identity(db, int(row["variant_id"]), result, scan_id)
                self.assertEqual(1, db.execute("SELECT COUNT(*) FROM artifact_blobs").fetchone()[0])
                self.assertEqual(12345, db.execute("SELECT package_bytes FROM artifact_blobs").fetchone()[0])
                self.assertEqual(1, db.execute("SELECT COUNT(*) FROM source_revisions").fetchone()[0])
                attr = db.execute("SELECT confidence,coverage_label,source_root_path,basis_json FROM artifact_source_attributions WHERE active=1").fetchone()
                self.assertEqual(70, attr["confidence"])
                self.assertEqual("Version-correlated source", attr["coverage_label"])
                self.assertEqual("src/ExamplePlugin", attr["source_root_path"])
                self.assertIn("version_match", json.loads(attr["basis_json"]))
                self.assertEqual(70, result["source"]["attribution"]["confidence"])

    def test_source_work_attaches_to_completed_artifact_without_redownloading_plugin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-source-worker-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            out = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, out, curated, raw, enriched, websites)
            with closing(sqlite3.connect(out / "omega-catalog.sqlite")) as db:
                db.row_factory = sqlite3.Row
                sigmascope.ensure_schema(db)
                row = db.execute("""
                    SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,v.author,v.assembly_version,
                           v.testing_assembly_version,v.download_link_install,v.download_link_update,v.download_link_testing,v.repo_url,
                           s.name AS source_name,s.url AS source_url,s.source_repo_url
                      FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id JOIN sources s ON s.source_id=v.source_id
                     ORDER BY v.variant_id LIMIT 1
                """).fetchone()
                artifact_sha = "a" * 64
                artifact_payload = {
                    "schema": sigmascope.ARTIFACT_ANALYSIS_SCHEMA, "artifactSha256": artifact_sha, "artifactBytes": 123,
                    "resolvedArtifactUrl": str(row["download_link_install"] or ""), "artifactAssemblyVersion": str(row["assembly_version"] or ""),
                    "manifestPath": "", "package": {}, "ruleFindings": [], "ruleCapabilities": [],
                    "dependencyIntelligence": sigmascope.empty_dependency_intelligence("artifact"), "findings": [], "capabilities": [],
                    "automation": {"level": "none", "capabilities": [], "findings": []},
                    "counts": {"informational": 0, "caution": 0, "high": 0, "critical": 0}, "highestSeverity": "none",
                }
                rep = db.execute(
                    """INSERT INTO plugin_security_scans(plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,
                           scanner_version,status,scanned_at_utc,highest_severity,capabilities_json,report_json)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (row["plugin_id"], row["variant_id"], row["source_id"], row["assembly_version"], "stable", row["download_link_install"],
                     artifact_sha, sigmascope.SCANNER_VERSION, "complete", "2026-08-19T12:00:00Z", "none", "[]",
                     json.dumps({"schema": "omega.plugin-security.scan.v1", "workType": "artifact", "artifactSha256": artifact_sha,
                                 "artifactAnalysisRevision": "artifact-fixture", "resolvedArtifactUrl": row["download_link_install"],
                                 "source": {"available": False, "attribution": {"confidence": 0}}, "findings": [], "capabilities": [],
                                 "dependencyIntelligence": sigmascope.empty_dependency_intelligence("artifact")})),
                )
                rep_scan = int(rep.lastrowid)
                db.execute("INSERT INTO artifact_blobs(artifact_sha256,package_bytes) VALUES(?,?)", (artifact_sha, 123))
                db.execute(
                    """INSERT INTO artifact_analyses(artifact_sha256,scanner_version,definitions_revision,representative_scan_id,status,analysis_payload_json)
                       VALUES(?,?,?,?,?,?)""",
                    (artifact_sha, sigmascope.SCANNER_VERSION, "artifact-fixture", rep_scan, "complete", json.dumps(artifact_payload)),
                )
                db.execute(
                    """INSERT INTO plugin_security_current(variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,
                           scanned_at_utc,highest_severity,capabilities_json,findings_json,source_available,source_repository,source_commit,report_json)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (row["variant_id"], rep_scan, row["assembly_version"], "stable", row["download_link_install"], artifact_sha,
                     sigmascope.SCANNER_VERSION, "complete", "2026-08-19T12:00:00Z", "none", "[]", "[]", 0, row["repo_url"], "",
                     json.dumps({"schema": "omega.plugin-security.scan.v1", "workType": "artifact", "artifactSha256": artifact_sha,
                                 "artifactAnalysisRevision": "artifact-fixture", "resolvedArtifactUrl": row["download_link_install"],
                                 "source": {"available": False, "attribution": {"confidence": 0}}, "findings": [], "capabilities": [],
                                 "dependencyIntelligence": sigmascope.empty_dependency_intelligence("artifact")})),
                )
                db.commit()
                source_result = {
                    "available": True, "repository": "https://github.com/example/plugin", "commit": "b" * 40, "branch": "v1.0.0",
                    "treeSha256": "c" * 40, "filesScanned": 3, "dependencyIntelligence": sigmascope.empty_dependency_intelligence("source"),
                    "scope": {"primaryProject": "src/Plugin/Plugin.csproj"},
                    "provenance": {"identityMatched": True, "versionMatched": True, "selectedRefKind": "version-tag", "selectedRef": "v1.0.0"},
                    "error": "",
                }
                with mock.patch.object(sigmascope, "request_bytes", side_effect=AssertionError("source work must not download plugin artifact")), \
                     mock.patch.object(sigmascope, "fetch_source", side_effect=[dict(source_result), dict(source_result)]) as fetch:
                    result = sigmascope.scan_source_row(row, token="", db=db, source_analysis_revision="source-fixture")
                self.assertEqual("complete", result["status"])
                self.assertEqual("source", result["workType"])
                self.assertEqual(artifact_sha, result["artifactSha256"])
                self.assertTrue(result["source"]["available"])
                self.assertEqual(70, result["source"]["attribution"]["confidence"])
                self.assertEqual(2, fetch.call_count)
                self.assertFalse(fetch.call_args_list[0].kwargs["analyze"])
                self.assertTrue(fetch.call_args_list[1].kwargs["analyze"])

                # Combined source+artifact finalization can derive findings (for example
                # endpoint findings) that do not live in source["findings"].  The immutable
                # source-projection rows must persist the final finding list exactly.
                result["findings"].append({
                    "ruleId": "network.endpoint.fixture", "severity": "caution", "category": "network-endpoint",
                    "title": "Endpoint: fixture.example", "description": "Derived combined endpoint evidence",
                    "evidence": ["source:fixture"],
                })
                result["counts"]["caution"] += 1
                result["highestSeverity"] = "caution"
                new_scan = sigmascope.save_scan(db, row, result)
                db.commit()
                current = db.execute("SELECT scan_id,source_available,artifact_sha256 FROM plugin_security_current WHERE variant_id=?", (row["variant_id"],)).fetchone()
                self.assertEqual(new_scan, current["scan_id"])
                self.assertEqual(1, current["source_available"])
                self.assertEqual(artifact_sha, current["artifact_sha256"])
                persisted_findings = db.execute(
                    "SELECT rule_id,severity FROM plugin_security_findings WHERE scan_id=? ORDER BY finding_id", (new_scan,)
                ).fetchall()
                self.assertEqual([("network.endpoint.fixture", "caution")], [(r["rule_id"], r["severity"]) for r in persisted_findings])
                persisted_scan = db.execute(
                    "SELECT caution_count,informational_count,high_count,critical_count FROM plugin_security_scans WHERE scan_id=?", (new_scan,)
                ).fetchone()
                self.assertEqual(1, persisted_scan["caution_count"])
                self.assertEqual(1, len(persisted_findings))

    def test_source_analysis_reuses_same_immutable_revision_within_worker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-source-cache-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            out = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, out, curated, raw, enriched, websites)
            with closing(sqlite3.connect(out / "omega-catalog.sqlite")) as db:
                db.row_factory = sqlite3.Row
                sigmascope.ensure_schema(db)
                row = db.execute("""
                    SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,v.author,v.assembly_version,
                           v.testing_assembly_version,v.download_link_install,v.download_link_update,v.download_link_testing,v.repo_url,
                           s.name AS source_name,s.url AS source_url,s.source_repo_url
                      FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id JOIN sources s ON s.source_id=v.source_id
                     ORDER BY v.variant_id LIMIT 1
                """).fetchone()
                artifact_sha = "d" * 64
                artifact_payload = {
                    "schema": sigmascope.ARTIFACT_ANALYSIS_SCHEMA, "artifactSha256": artifact_sha, "artifactBytes": 50,
                    "artifactAssemblyVersion": str(row["assembly_version"] or ""), "manifestPath": "", "package": {}, "ruleFindings": [],
                    "ruleCapabilities": [], "dependencyIntelligence": sigmascope.empty_dependency_intelligence("artifact"), "findings": [], "capabilities": [],
                    "automation": {"level": "none", "capabilities": [], "findings": []},
                    "counts": {"informational": 0, "caution": 0, "high": 0, "critical": 0}, "highestSeverity": "none",
                }
                rep = db.execute("INSERT INTO plugin_security_scans(plugin_id,variant_id,source_id,status,artifact_sha256,scanner_version,report_json) VALUES(?,?,?,?,?,?,?)",
                                 (row["plugin_id"], row["variant_id"], row["source_id"], "complete", artifact_sha, sigmascope.SCANNER_VERSION, "{}"))
                rep_scan = int(rep.lastrowid)
                db.execute("INSERT INTO artifact_blobs(artifact_sha256,package_bytes) VALUES(?,?)", (artifact_sha, 50))
                db.execute("INSERT INTO artifact_analyses(artifact_sha256,scanner_version,definitions_revision,representative_scan_id,status,analysis_payload_json) VALUES(?,?,?,?,?,?)",
                           (artifact_sha, sigmascope.SCANNER_VERSION, "artifact-cache", rep_scan, "complete", json.dumps(artifact_payload)))
                current_report = {"workType": "artifact", "artifactSha256": artifact_sha, "artifactAnalysisRevision": "artifact-cache",
                                  "resolvedArtifactUrl": row["download_link_install"], "source": {"available": False, "attribution": {"confidence": 0}}}
                db.execute("""INSERT INTO plugin_security_current(variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,
                           scanned_at_utc,highest_severity,capabilities_json,findings_json,source_available,report_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                           (row["variant_id"], rep_scan, row["assembly_version"], "stable", row["download_link_install"], artifact_sha, sigmascope.SCANNER_VERSION,
                            "complete", "2026-08-19T12:00:00Z", "none", "[]", "[]", 0, json.dumps(current_report)))
                repository = "https://github.com/example/plugin"
                commit = "e" * 40
                rkey = model.repository_key(repository)
                revkey = model.source_revision_key(repository, commit)
                db.execute("INSERT INTO source_repositories(repository_key,canonical_url) VALUES(?,?)", (rkey, repository))
                db.execute("INSERT INTO source_revisions(source_revision_key,repository_key,commit_sha) VALUES(?,?,?)", (revkey, rkey, commit))
                source = {"available": True, "repository": repository, "commit": commit, "branch": "main", "treeSha256": "f" * 40,
                          "filesScanned": 2, "dependencyIntelligence": sigmascope.empty_dependency_intelligence("source"),
                          "scope": {"primaryProject": "src/Plugin/Plugin.csproj"}, "findings": [], "capabilities": [],
                          "provenance": {"identityMatched": True, "selectedRefKind": "default-branch", "selectedRef": "main"}, "error": ""}
                payload = sigmascope._source_payload(source, {}, analysis_complete=True)
                db.execute("""INSERT INTO source_analyses(source_revision_key,source_root_path,scanner_version,definitions_revision,representative_scan_id,status,analysis_payload_json)
                           VALUES(?,?,?,?,?,?,?)""", (revkey, "src/Plugin", sigmascope.SCANNER_VERSION, "source-cache", rep_scan, "complete", json.dumps(payload)))
                db.commit()
                resolution = dict(source)
                with mock.patch.object(sigmascope, "fetch_source", return_value=resolution) as fetch:
                    result = sigmascope.scan_source_row(row, token="", db=db, source_analysis_revision="source-cache")
                self.assertEqual(1, fetch.call_count)
                self.assertFalse(fetch.call_args.kwargs["analyze"])
                self.assertTrue(result["sourceAnalysisReused"])
                self.assertEqual(rep_scan, result["sourceAnalysisRepresentativeScanId"])

    def test_artifact_analysis_is_reused_only_after_sha256_identity_is_proven(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-artifact-cache-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            out = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, out, curated, raw, enriched, websites)
            artifact = b"same distributed bytes"
            artifact_sha = sigmascope.sha256_bytes(artifact)
            with closing(sqlite3.connect(out / "omega-catalog.sqlite")) as db:
                db.row_factory = sqlite3.Row
                sigmascope.ensure_schema(db)
                row = db.execute("""
                    SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,v.author,v.assembly_version,
                           v.testing_assembly_version,v.download_link_install,v.download_link_update,v.download_link_testing,v.repo_url,
                           s.name AS source_name,s.url AS source_url,s.source_repo_url
                      FROM plugin_variants v
                      JOIN plugins p ON p.plugin_id=v.plugin_id
                      JOIN sources s ON s.source_id=v.source_id
                     ORDER BY v.variant_id LIMIT 1
                """).fetchone()
                payload = {
                    "schema": sigmascope.ARTIFACT_ANALYSIS_SCHEMA,
                    "artifactSha256": artifact_sha,
                    "artifactBytes": len(artifact),
                    "resolvedArtifactUrl": str(row["download_link_install"] or ""),
                    "artifactAssemblyVersion": str(row["assembly_version"] or ""),
                    "manifestPath": "",
                    "package": {},
                    "ruleFindings": [],
                    "ruleCapabilities": [],
                    "dependencyIntelligence": sigmascope.empty_dependency_intelligence("artifact"),
                    "findings": [],
                    "capabilities": [],
                    "automation": {"level": "none", "capabilities": [], "findings": []},
                    "counts": {"informational": 0, "caution": 0, "high": 0, "critical": 0},
                    "highestSeverity": "none",
                }
                db.execute(
                    "INSERT INTO artifact_blobs(artifact_sha256,package_bytes) VALUES(?,?)",
                    (artifact_sha, len(artifact)),
                )
                db.execute(
                    """INSERT INTO artifact_analyses(
                           artifact_sha256,scanner_version,definitions_revision,status,analysis_payload_json,representative_scan_id)
                       VALUES(?,?,?,?,?,?)""",
                    (artifact_sha, sigmascope.SCANNER_VERSION, "rules-v1-cache", "complete", json.dumps(payload), 77),
                )
                db.commit()
                with mock.patch.object(sigmascope, "request_bytes", return_value=(artifact, str(row["download_link_install"] or ""))), \
                     mock.patch.object(sigmascope, "_build_artifact_analysis", side_effect=AssertionError("artifact parser should not run")):
                    result = sigmascope.scan_row(
                        row,
                        token="",
                        scan_source=False,
                        db=db,
                        artifact_analysis_revision="rules-v1-cache",
                    )
                self.assertEqual("complete", result["status"])
                self.assertTrue(result["artifactAnalysisReused"])
                self.assertEqual(77, result["artifactAnalysisRepresentativeScanId"])
                self.assertEqual(artifact_sha, result["artifactSha256"])
                self.assertEqual("unresolved", result["source"]["status"])

    def test_artifact_reuse_clones_normalized_evidence_after_transport_payload_is_compacted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-artifact-transport-reuse-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            out = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, out, curated, raw, enriched, websites)
            artifact = b"transport-stable-artifact"
            artifact_sha = sigmascope.sha256_bytes(artifact)
            with closing(sqlite3.connect(out / "omega-catalog.sqlite")) as db:
                db.row_factory = sqlite3.Row
                sigmascope.ensure_schema(db)
                rows = db.execute("""
                    SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,v.author,v.assembly_version,
                           v.testing_assembly_version,v.download_link_install,v.download_link_update,v.download_link_testing,v.repo_url,
                           s.name AS source_name,s.url AS source_url,s.source_repo_url
                      FROM plugin_variants v
                      JOIN plugins p ON p.plugin_id=v.plugin_id
                      JOIN sources s ON s.source_id=v.source_id
                     ORDER BY v.variant_id LIMIT 2
                """).fetchall()
                self.assertEqual(2, len(rows))
                representative, target = rows
                rep = db.execute(
                    """INSERT INTO plugin_security_scans(
                           plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,
                           scanner_version,status,scanned_at_utc,highest_severity,informational_count,capabilities_json,report_json)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        representative["plugin_id"], representative["variant_id"], representative["source_id"],
                        representative["assembly_version"], "stable", representative["download_link_install"], artifact_sha,
                        sigmascope.SCANNER_VERSION, "complete", "2026-08-19T12:00:00Z", "informational", 1, "[]",
                        json.dumps({
                            "schema": "omega.plugin-security.scan.v1",
                            "workType": "artifact",
                            "artifactBytes": len(artifact),
                            "artifactSha256": artifact_sha,
                            "package": {"fileCount": 1},
                            "automation": {"level": "none", "capabilities": [], "findings": []},
                            "scanProvenance": {"ruleSetRevision": "rules-v1-transport"},
                        }),
                    ),
                )
                rep_scan_id = int(rep.lastrowid)
                db.execute(
                    """INSERT INTO plugin_security_findings(scan_id,rule_id,severity,category,title,description,evidence_json)
                       VALUES(?,?,?,?,?,?,?)""",
                    (rep_scan_id, "network.http", "informational", "network", "Network access", "fixture", "[]"),
                )
                db.execute("INSERT INTO artifact_blobs(artifact_sha256,package_bytes) VALUES(?,?)", (artifact_sha, len(artifact)))
                db.execute(
                    """INSERT INTO artifact_analyses(
                           artifact_sha256,scanner_version,definitions_revision,representative_scan_id,status,analysis_payload_json)
                       VALUES(?,?,?,?,?,?)""",
                    (artifact_sha, sigmascope.SCANNER_VERSION, "rules-v1-transport", rep_scan_id, "complete", "{}"),
                )
                db.commit()
                with mock.patch.object(sigmascope, "request_bytes", return_value=(artifact, str(target["download_link_install"] or ""))), \
                     mock.patch.object(sigmascope, "_build_artifact_analysis", side_effect=AssertionError("transport reuse must clone normalized evidence")):
                    result = sigmascope.scan_row(
                        target,
                        token="",
                        scan_source=False,
                        db=db,
                        artifact_analysis_revision="rules-v1-transport",
                    )
                self.assertTrue(result["artifactAnalysisReused"])
                self.assertEqual(rep_scan_id, result["artifactAnalysisCloneFromScanId"])
                new_scan_id = sigmascope.save_scan(db, target, result)
                db.commit()
                self.assertNotEqual(rep_scan_id, new_scan_id)
                cloned = db.execute(
                    "SELECT rule_id,severity FROM plugin_security_findings WHERE scan_id=?",
                    (new_scan_id,),
                ).fetchall()
                self.assertEqual([("network.http", "informational")], [(row["rule_id"], row["severity"]) for row in cloned])
                analysis = db.execute(
                    """SELECT representative_scan_id,reuse_count
                         FROM artifact_analyses
                        WHERE artifact_sha256=? AND scanner_version=? AND definitions_revision=?""",
                    (artifact_sha, sigmascope.SCANNER_VERSION, "rules-v1-transport"),
                ).fetchone()
                self.assertEqual(rep_scan_id, analysis["representative_scan_id"])
                self.assertEqual(1, analysis["reuse_count"])
                current = db.execute("SELECT source_available,artifact_sha256 FROM plugin_security_current WHERE variant_id=?", (target["variant_id"],)).fetchone()
                self.assertEqual(0, current["source_available"])
                self.assertEqual(artifact_sha, current["artifact_sha256"])



    def test_source_replay_preserves_artifact_bound_secondary_security_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-secondary-replay-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            out = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, out, curated, raw, enriched, websites)
            with closing(sqlite3.connect(out / "omega-catalog.sqlite")) as db:
                db.row_factory = sqlite3.Row
                sigmascope.ensure_schema(db)
                row = db.execute("""
                    SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,v.author,v.assembly_version,
                           v.download_link_install,s.name AS source_name,s.url AS source_url,s.source_repo_url
                      FROM plugin_variants v
                      JOIN plugins p ON p.plugin_id=v.plugin_id
                      JOIN sources s ON s.source_id=v.source_id
                     ORDER BY v.variant_id LIMIT 1
                """).fetchone()
                artifact_sha = "9" * 64
                secondary = {
                    "schema": "omega.sigmascope.secondary-security.v1",
                    "artifactSha256": artifact_sha,
                    "semantics": "supplemental-evidence-only",
                    "matchCount": 0,
                    "engines": [],
                }
                report = {
                    "schema": "omega.security-evidence.scan-summary.v2",
                    "artifactBytes": 42,
                    "artifactIdentity": {"manifestPath": "Plugin.json"},
                    "package": {},
                    "automation": {"level": "none", "capabilities": [], "findings": []},
                    "secondarySecurity": secondary,
                    "secondarySecurityContractVersion": 2,
                }
                db.execute("INSERT INTO artifact_blobs(artifact_sha256,package_bytes) VALUES(?,?)", (artifact_sha, 42))
                scan = db.execute(
                    """INSERT INTO plugin_security_scans(plugin_id,variant_id,source_id,assembly_version,artifact_sha256,scanner_version,status,
                               highest_severity,capabilities_json,report_json)
                           VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (row["plugin_id"], row["variant_id"], row["source_id"], row["assembly_version"], artifact_sha,
                     sigmascope.SCANNER_VERSION, "complete", "none", "[]", json.dumps(report)),
                )
                scan_id = int(scan.lastrowid)
                # Evidence-v2 materialization intentionally restores the normalized
                # representative and may not retain the large artifact payload cache.
                db.execute(
                    """INSERT INTO artifact_analyses(artifact_sha256,scanner_version,definitions_revision,representative_scan_id,status,analysis_payload_json)
                           VALUES(?,?,?,?,?,?)""",
                    (artifact_sha, sigmascope.SCANNER_VERSION, "artifact-replay", scan_id, "complete", "{}"),
                )
                db.commit()

                replay, representative = sigmascope._load_cached_artifact_analysis(db, artifact_sha, "artifact-replay")
                self.assertEqual(scan_id, representative)
                self.assertIsNotNone(replay)
                self.assertEqual(2, replay["secondarySecurityContractVersion"])
                self.assertEqual(secondary, replay["secondarySecurity"])

                base = {"artifactSha256": artifact_sha, "secondarySecurityContractVersion": 2, "secondarySecurity": {"stale": True}}
                sigmascope._apply_artifact_analysis(base, replay, str(row["assembly_version"] or ""), reused=True, representative_scan_id=scan_id)
                self.assertEqual(2, base["secondarySecurityContractVersion"])
                self.assertEqual(artifact_sha, base["secondarySecurity"]["artifactSha256"])
                self.assertEqual("supplemental-evidence-only", base["secondarySecurity"]["semantics"])

                # A malformed/missing replay payload must never leave a stale marker.
                base = {"artifactSha256": artifact_sha, "secondarySecurityContractVersion": 2, "secondarySecurity": {"stale": True}}
                sigmascope._apply_artifact_analysis(
                    base,
                    {"artifactSha256": artifact_sha, "artifactAssemblyVersion": str(row["assembly_version"] or ""), "findings": [], "capabilities": [], "counts": {}, "highestSeverity": "none"},
                    str(row["assembly_version"] or ""), reused=True, representative_scan_id=scan_id,
                )
                self.assertNotIn("secondarySecurityContractVersion", base)
                self.assertIsNone(base["secondarySecurity"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations
from contextlib import closing
import io
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import common
import scan_queue
import sigmascope
import sigmascope_request_adapter
import test_sqlite_catalog
from migrate_security_evidence_v2 import migrate
from production_sigmascope_v2_pipeline import run_pipeline


class SigmaScopeRequestPipelineTests(unittest.TestCase):
    def test_generic_request_selects_exact_canonical_queue_item_and_verifies_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-sigma-request-pipeline-") as td:
            root = Path(td)
            curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
            built = root / "built"
            test_sqlite_catalog.run_builder(common.ROOT, built, curated, raw, enriched, websites)
            database = built / "omega-catalog.sqlite"
            with closing(sqlite3.connect(database)) as db:
                db.row_factory = sqlite3.Row
                sigmascope.ensure_schema(db)
                selected = db.execute(
                    """SELECT v.variant_id,v.plugin_id,v.source_id,v.assembly_version
                         FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id
                        WHERE v.active=1 AND p.active=1 ORDER BY v.variant_id LIMIT 1"""
                ).fetchone()
                self.assertIsNotNone(selected)
                variant_id = int(selected["variant_id"])
                plugin_id = int(selected["plugin_id"])
                source_id = int(selected["source_id"])
                artifact_sha = "a" * 64
                db.execute(
                    """INSERT INTO plugin_security_scans(
                         scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,
                         artifact_sha256,scanner_version,status,scanned_at_utc,highest_severity,
                         informational_count,caution_count,high_count,critical_count,capabilities_json,
                         source_available,source_repository,source_commit,source_to_binary_verified,report_json,error)
                         VALUES(?,?,?,?,?,'stable','https://example.invalid/plugin.zip',?,?,'complete',
                         '2026-08-17T00:00:00Z','caution',0,1,0,0,'[]',1,'https://example.invalid/repo',
                         'abc',1,'{}','')""",
                    (9001, plugin_id, variant_id, source_id, str(selected["assembly_version"] or "1.0.0"), artifact_sha, sigmascope.SCANNER_VERSION),
                )
                db.execute(
                    """INSERT INTO plugin_security_current(
                         variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,
                         scanner_version,status,scanned_at_utc,highest_severity,informational_count,caution_count,
                         high_count,critical_count,capabilities_json,automation_level,automation_capabilities_json,
                         findings_json,source_available,source_repository,source_commit,source_to_binary_verified,
                         report_json,error)
                         VALUES(?,9001,?,'stable','https://example.invalid/plugin.zip',?,?,'complete',
                         '2026-08-17T00:00:00Z','caution',0,1,0,0,'[]','none','[]','[]',1,
                         'https://example.invalid/repo','abc',1,'{}','')""",
                    (variant_id, str(selected["assembly_version"] or "1.0.0"), artifact_sha, sigmascope.SCANNER_VERSION),
                )
                db.execute(
                    """INSERT INTO plugin_security_findings(scan_id,rule_id,severity,category,title,description,evidence_json)
                       VALUES(9001,'fixture.rule','caution','fixture','Fixture','Fixture finding','["fixture"]')"""
                )
                db.execute(
                    """INSERT INTO plugin_security_dependencies(
                       scan_id,origin,kind,name,version,version_requirement,resolved_version,path,status,requirement,
                       evidence_json,relationship,relationship_confidence,relationship_evidence_json)
                       VALUES(9001,'artifact','nuget-resolved','Example.Package','1.2.3','1.2.3','1.2.3',
                       'Fixture.deps.json','known','required','[]','','','[]')"""
                )
                db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_scanner_version',?)", (sigmascope.SCANNER_VERSION,))
                db.commit()
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)

            base = root / "base.sqlite"
            shutil.copy2(database, base)
            with closing(sqlite3.connect(base)) as db:
                sigmascope.ensure_schema(db)
                db.execute("PRAGMA foreign_keys=OFF")
                for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchall():
                    db.execute(f'DELETE FROM "{row[0]}"')
                db.execute("PRAGMA foreign_keys=ON")
                variant = db.execute(
                    "SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,s.name,v.assembly_version,v.download_link_install "
                    "FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id JOIN sources s ON s.source_id=v.source_id "
                    "WHERE v.variant_id=?", (variant_id,)
                ).fetchone()
                db.commit()

            queue_seed = root / "scan-queue.json"
            queue_seed.write_text(json.dumps({
                "schema": scan_queue.SEED_SCHEMA,
                "queueSeedRevision": "queue-seed-v2-request-fixture",
                "catalogRevision": "cat-json-v1-fixture",
                "catalogIdentityEpoch": "",
                "definitionsRevision": "defs-v1-fixture",
                "scannerRevision": "scanner-v1-fixture",
                "scannerBundleSha256": "b" * 64,
                "ruleSetRevision": "rules-v1-fixture",
                "artifactAnalysisRevision": "artifact-analysis-v1-fixture",
                "sourceAnalysisRevision": "source-analysis-v1-fixture",
                "sourceObservationRevision": "source-observations-v1-fixture",
                "advisoryRevision": "",
                "counts": {"queued": 1},
                "items": [{
                    "queueKey": f"variant-{variant_id}", "workType": "artifact",
                    "targetFingerprint": "stale-fixture-target",
                    "variantId": variant_id, "pluginId": int(variant[1]), "sourceId": int(variant[2]),
                    "internalName": str(variant[3]), "name": str(variant[4]), "sourceName": str(variant[5]),
                    "assemblyVersion": str(variant[6]), "artifactChannel": "stable", "artifactUrl": str(variant[7]),
                    "repositoryUrl": "https://github.com/example/plugin", "sourceRepositoryUrl": "",
                    "catalogRevision": "cat-json-v1-fixture", "definitionsRevision": "defs-v1-fixture",
                    "artifactAnalysisRevision": "artifact-analysis-v1-fixture", "sourceAnalysisRevision": "source-analysis-v1-fixture",
                    "ruleSetRevision": "rules-v1-fixture", "reasons": ["artifact_analysis_changed"],
                    "primaryReason": "artifact_analysis_changed", "priority": 750,
                    "currentScanId": 9001, "currentScannedAtUtc": "2026-08-17T00:00:00Z",
                    "currentArtifactSha256": "a" * 64, "enqueuedAtUtc": "2026-08-24T00:00:00Z",
                }],
            }), encoding="utf-8")
            request_path = root / "request.json"
            request_path.write_text(json.dumps({
                "schema": "omega.analysis-request.v1",
                "requestId": "analysis-managed-calls-fixture",
                "observation": "managedCallSites",
                "subject": {"type": "variant", "variantId": variant_id},
                "reason": "SRL requires managed call-site evidence",
                "priority": 900,
                "requestedBy": {"componentId": "omega.stigma-1", "ruleId": "fixture.needs-calls"},
                "requestedAtUtc": "2026-08-24T20:00:00Z",
            }), encoding="utf-8")

            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("fixture.txt", "brokered SigmaScope fixture")
            artifact = buffer.getvalue()
            args = SimpleNamespace(
                base_database=base, descriptor=None, current_evidence=evidence,
                candidate_evidence=root / "candidate", work_dir=root / "work", publication_output=None,
                previous_marketplace_descriptor=None, marketplace_download_url="",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
                source_overrides=common.ROOT / "sources" / "source-overrides.json", max_scans=20,
                rescan_after_hours=168, max_batch_seconds=0, internal_names="", variant_ids="", skip_source=True,
                osv_timeout=1.0, max_osv_packages=2000, github_output=None, skip_marketplace=True,
                frozen_advisories=None, frozen_definitions=None,
                catalog_revision="cat-json-v1-fixture", definitions_revision="defs-v1-fixture",
                scanner_revision="scanner-v1-fixture", scanner_bundle_sha256="b" * 64,
                artifact_analysis_revision="artifact-analysis-v1-fixture", source_analysis_revision="source-analysis-v1-fixture",
                rule_set_revision="rules-v1-fixture", advisory_revision="", queue_seed=queue_seed,
                analysis_request=request_path, analysis_work_item_id="work-managed-calls-fixture",
                deep_scan_state=None, deep_scan_output=None,
            )

            def fake_collect(index_path, output, timeout=20.0, max_packages=2000):
                document = {"schema": "omega.public-advisories.v1", "generatedAtUtc": "2026-08-24T00:00:00Z", "source": "OSV", "ecosystem": "NuGet", "queriedPackages": 0, "matchedPackages": 0, "advisories": []}
                Path(output).write_text(json.dumps(document), encoding="utf-8")
                return document

            with patch("sigmascope.request_bytes", return_value=(artifact, str(variant[7]))), \
                 patch("production_sigmascope_v2_pipeline.collect_public_advisories.collect_from_nuget_index", side_effect=fake_collect):
                result = run_pipeline(args)

            self.assertEqual("managedCallSites", result["analysisRequest"]["observation"])
            self.assertEqual(variant_id, int(result["analysisRequest"]["variantId"]))
            self.assertEqual(1, result["queue"]["selectedCount"])
            self.assertEqual(f"variant-{variant_id}", result["queue"]["selected"]["queueKey"])
            queue_state = json.loads((root / "candidate" / "scanner-queue.json").read_text(encoding="utf-8"))
            item = queue_state["items"][f"variant-{variant_id}"]
            self.assertEqual("complete", item["state"])
            self.assertEqual("work-managed-calls-fixture", item["analysisRequests"][0]["workItemId"])
            target = json.loads((root / "work" / "analysis-request-target.json").read_text(encoding="utf-8"))
            verified = sigmascope_request_adapter.verify_target(root / "candidate", target)
            self.assertTrue(verified["ok"])
            self.assertEqual("managedCallSites", verified["observation"])


if __name__ == "__main__":
    unittest.main()

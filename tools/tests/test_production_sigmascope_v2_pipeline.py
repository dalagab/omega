from __future__ import annotations

from contextlib import closing
from pathlib import Path
import io
import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

import common
import test_sqlite_catalog

SECURITY = common.ROOT / "tools" / "security"
CATALOG = common.ROOT / "tools" / "catalog"
for item in (SECURITY, CATALOG):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

import sigmascope
import scan_queue
import variant_lifecycle
import catalog_json_store
import compile_marketplace_snapshot
import definitions_snapshot
import definition_packs
import validate_marketplace_catalog
import developer_view as developer_view
from migrate_security_evidence_v2 import migrate
from production_sigmascope_v2_pipeline import (
    _current_rows,
    _restore_last_known_good,
    _semantic_security_revision,
    materialize_current_state,
    run_pipeline,
    synchronize_candidate,
    _write_variant_derived_datasets,
    _merge_successful_subset,
    _build_plugins_artifacts_indexes,
    _merge_scan_reports,
    rebuild_candidate_indexes,
    materialize_srl_reprojection_sidecar,
)
from security_evidence_v2 import canonical_json_bytes, read_record_dataset, sha256_bytes, validate_snapshot, write_record_dataset


class ProductionSecurityV2PipelineTests(unittest.TestCase):
    def test_bounded_batch_report_aggregates_multiple_queue_invocations(self) -> None:
        reports = [
            {
                "schema": "omega.plugin-security.batch.v1", "engineName": "Sigmascope",
                "engineVersion": sigmascope.SIGMASCOPE_VERSION, "scannerVersion": sigmascope.SCANNER_VERSION,
                "startedAtUtc": "2026-08-20T00:00:00Z", "selected": 1, "completed": 1, "failed": 0,
                "artifactAnalysesReused": 0, "sourceAnalysesReused": 0,
                "plugins": [{"variantId": 1, "status": "complete", "elapsedSeconds": 2.5}],
            },
            {
                "schema": "omega.plugin-security.batch.v1", "engineName": "Sigmascope",
                "engineVersion": sigmascope.SIGMASCOPE_VERSION, "scannerVersion": sigmascope.SCANNER_VERSION,
                "startedAtUtc": "2026-08-20T00:00:03Z", "selected": 1, "completed": 0, "failed": 1,
                "artifactAnalysesReused": 1, "sourceAnalysesReused": 0,
                "plugins": [{"variantId": 2, "status": "failed", "elapsedSeconds": 0.5}],
            },
        ]
        merged = _merge_scan_reports(reports, batch_budget_seconds=3300, stopped_by_budget=False, batch_elapsed_seconds=4.0)
        self.assertEqual(2, merged["selected"])
        self.assertEqual(1, merged["completed"])
        self.assertEqual(1, merged["failed"])
        self.assertEqual(2, merged["invocations"])
        self.assertEqual(3.0, merged["pluginElapsedSecondsTotal"])
        self.assertEqual(1.5, merged["pluginElapsedSecondsAverage"])
        self.assertEqual(2.5, merged["pluginElapsedSecondsMax"])
        self.assertEqual([1, 2], [item["variantId"] for item in merged["plugins"]])

    def test_inactive_variant_becomes_terminal_snapshot_and_keeps_analysis(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-terminal-variant-") as td:
            root = Path(td)
            database, variant_id, _ = self.make_catalog_with_security(root)
            candidate = root / "candidate"
            migrate(database, candidate, reset=True)
            current_path = next((candidate / "variants").rglob(f"{variant_id}.json"))
            current_payload = json.loads(current_path.read_text(encoding="utf-8"))
            analysis_path = candidate / current_payload["analysis"]["path"] / "manifest.json"
            self.assertTrue(analysis_path.is_file())
            with closing(sqlite3.connect(database)) as db:
                db.execute("UPDATE plugin_variants SET active=0 WHERE variant_id=?", (variant_id,))
                db.commit()

            report = synchronize_candidate(candidate, database, set())
            self.assertEqual(1, report["variantsRetired"])
            self.assertFalse(current_path.exists())
            terminal = variant_lifecycle.terminal_path(candidate, variant_id)
            self.assertTrue(terminal.is_file())
            payload = json.loads(terminal.read_text(encoding="utf-8"))
            self.assertEqual("retired", payload["lifecycle"]["state"])
            self.assertFalse(payload["lifecycle"]["rescanEligible"])
            self.assertNotIn("derivedEvidence", payload)
            self.assertTrue(analysis_path.is_file(), "terminal evidence must retain its immutable artifact analysis")

            _plugins, _artifacts, current_count, terminal_count, history_count, analysis_count, _groups = _build_plugins_artifacts_indexes(candidate)
            self.assertEqual((0, 1, 0, 1), (current_count, terminal_count, history_count, analysis_count))
            index = json.loads((candidate / "indexes" / "plugins.json").read_text(encoding="utf-8"))
            self.assertEqual([], index["currentVariants"])
            self.assertEqual(variant_id, index["terminalVariants"][0]["variantId"])

    def test_replaced_terminal_snapshot_is_archived_as_superseded_history(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-terminal-history-") as td:
            root = Path(td)
            database, variant_id, _ = self.make_catalog_with_security(root)
            candidate = root / "candidate"
            migrate(database, candidate, reset=True)
            current_path = next((candidate / "variants").rglob(f"{variant_id}.json"))
            current_rel = current_path.relative_to(candidate)
            current_payload = json.loads(current_path.read_text(encoding="utf-8"))
            with closing(sqlite3.connect(database)) as db:
                db.execute("UPDATE plugin_variants SET active=0 WHERE variant_id=?", (variant_id,))
                db.commit()

            synchronize_candidate(candidate, database, set())
            terminal = variant_lifecycle.terminal_path(candidate, variant_id)
            first_terminal = json.loads(terminal.read_text(encoding="utf-8"))
            self.assertEqual("retired", first_terminal["lifecycle"]["state"])

            replacement = json.loads(json.dumps(current_payload))
            replacement["current"]["scan_id"] = int(replacement["current"].get("scan_id") or 0) + 1
            replacement["current"]["artifact_sha256"] = "b" * 64
            replacement["analysis"]["artifactSha256"] = "b" * 64
            replacement["current"]["artifact_url"] = "https://example.invalid/replacement.zip"
            replacement_path = candidate / current_rel
            replacement_path.parent.mkdir(parents=True, exist_ok=True)
            replacement_path.write_text(json.dumps(replacement), encoding="utf-8")

            synchronize_candidate(candidate, database, set())

            history = list((candidate / "history" / "variants").rglob("*.json"))
            self.assertEqual(1, len(history))
            archived = json.loads(history[0].read_text(encoding="utf-8"))
            self.assertEqual("superseded", archived["lifecycle"]["state"])
            self.assertTrue(archived["lifecycle"]["terminal"])
            self.assertFalse(archived["lifecycle"]["rescanEligible"])
            self.assertEqual("terminal_snapshot_replaced", archived["lifecycle"]["reason"])
            self.assertEqual(first_terminal["current"]["artifact_sha256"], archived["current"]["artifact_sha256"])

            current_terminal = json.loads(terminal.read_text(encoding="utf-8"))
            self.assertEqual("retired", current_terminal["lifecycle"]["state"])
            self.assertEqual("b" * 64, current_terminal["current"]["artifact_sha256"])

    def test_terminal_snapshot_is_validated_and_counted_in_rebuilt_evidence_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-terminal-validation-") as td:
            root = Path(td)
            database, variant_id, _ = self.make_catalog_with_security(root)
            candidate = root / "candidate"
            migrate(database, candidate, reset=True)
            previous_index = json.loads((candidate / "index.json").read_text(encoding="utf-8"))
            with closing(sqlite3.connect(database)) as db:
                db.execute("UPDATE plugin_variants SET active=0 WHERE variant_id=?", (variant_id,))
                db.commit()
            synchronize_candidate(candidate, database, set())
            rebuilt = rebuild_candidate_indexes(
                candidate, database, previous_index,
                {
                    "catalogDataRevision": "cat-fixture", "catalogIdentityEpoch": catalog_json_store.IDENTITY_EPOCH,
                    "definitionsRevision": "defs-fixture", "artifactAnalysisRevision": "artifact-fixture",
                    "sourceAnalysisRevision": "source-fixture", "advisoryRevision": "osv-fixture",
                    "previousIndexSha256": "",
                },
                {
                    "inputPackageVersionPairs": 0, "expectedQueryPackageVersionPairs": 0,
                    "queriedPackageVersionPairs": 0, "matchedPackageVersionPairs": 0, "advisoryRecords": 0,
                },
            )
            validation = validate_snapshot(candidate)
            self.assertTrue(validation["ok"], validation["errors"])
            self.assertEqual(0, rebuilt["counts"]["currentVariants"])
            self.assertEqual(1, rebuilt["counts"]["terminalVariants"])
            self.assertEqual(0, rebuilt["counts"]["historicalSnapshots"])
            self.assertEqual(1, rebuilt["counts"]["analyses"])

    def test_new_artifact_archives_superseded_snapshot_but_source_only_projection_does_not(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-superseded-") as td:
            root = Path(td)
            database, variant_id, _ = self.make_catalog_with_security(root)
            candidate = root / "candidate"
            migrate(database, candidate, reset=True)
            current_path = next((candidate / "variants").rglob(f"{variant_id}.json"))
            previous = json.loads(current_path.read_text(encoding="utf-8"))

            source_only_subset = root / "source-only"
            source_variant = source_only_subset / current_path.relative_to(candidate)
            source_variant.parent.mkdir(parents=True, exist_ok=True)
            source_only = json.loads(json.dumps(previous))
            source_only["current"]["scan_id"] = int(source_only["current"].get("scan_id") or 0) + 1
            source_variant.write_text(json.dumps(source_only), encoding="utf-8")
            result = _merge_successful_subset(candidate, source_only_subset)
            self.assertEqual(0, result["historicalSnapshotsArchived"], "source-only projection must not manufacture artifact history")

            artifact_subset = root / "artifact-change"
            artifact_variant = artifact_subset / current_path.relative_to(candidate)
            artifact_variant.parent.mkdir(parents=True, exist_ok=True)
            changed = json.loads(json.dumps(source_only))
            changed["current"]["scan_id"] += 1
            changed["current"]["artifact_sha256"] = "b" * 64
            changed["analysis"]["artifactSha256"] = "b" * 64
            changed["current"]["artifact_url"] = "https://example.invalid/plugin-v2.zip"
            artifact_variant.write_text(json.dumps(changed), encoding="utf-8")
            result = _merge_successful_subset(candidate, artifact_subset)
            self.assertEqual(1, result["historicalSnapshotsArchived"])
            history = list((candidate / "history" / "variants").rglob("*.json"))
            self.assertEqual(1, len(history))
            archived = json.loads(history[0].read_text(encoding="utf-8"))
            self.assertEqual("superseded", archived["lifecycle"]["state"])
            self.assertEqual(previous["current"]["artifact_sha256"], archived["current"]["artifact_sha256"])

    def test_synchronize_preserves_unmaterialized_published_source_analysis_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-source-cache-preserve-") as td:
            root = Path(td)
            database, variant_id, _ = self.make_catalog_with_security(root)
            candidate = root / "candidate"
            migrate(database, candidate, reset=True)

            variant_file = next((candidate / "variants").rglob(f"{variant_id}.json"))
            payload = json.loads(variant_file.read_text(encoding="utf-8"))
            source_payload = {
                "schema": sigmascope.SOURCE_ANALYSIS_SCHEMA,
                "analysisComplete": True,
                "sourceRevisionKey": "fixture-source-revision",
                "sourceRootPath": "src/Plugin",
            }
            cache_record = {
                "schema": "omega.security-evidence.source-analysis-cache.v1",
                "sourceRevisionKey": source_payload["sourceRevisionKey"],
                "sourceRootPath": source_payload["sourceRootPath"],
                "scannerVersion": sigmascope.SCANNER_VERSION,
                "sourceAnalysisRevision": "source-analysis-v1-fixture",
                "analysisPayloadSha256": sha256_bytes(canonical_json_bytes(source_payload)),
                "analysisPayload": source_payload,
            }
            directory = candidate / "derived" / "variants" / f"{variant_id // 1000:04d}" / str(variant_id)
            descriptor = write_record_dataset(
                candidate, directory, "source-analysis-cache", [cache_record]
            )
            payload.setdefault("derivedEvidence", {})["sourceAnalysisCache"] = descriptor
            variant_file.write_text(json.dumps(payload), encoding="utf-8")
            cache_path = candidate / descriptor["files"][0]["path"]
            before = cache_path.read_bytes()

            # Deliberately leave source_analyses empty: this reproduces the real
            # unchanged-variant path that previously overwrote the cache with [].
            with closing(sqlite3.connect(database)) as db:
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM source_analyses").fetchone()[0])

            synchronize_candidate(candidate, database, set())

            after_payload = json.loads(variant_file.read_text(encoding="utf-8"))
            after_descriptor = after_payload["derivedEvidence"]["sourceAnalysisCache"]
            self.assertEqual(descriptor, after_descriptor)
            self.assertEqual(before, cache_path.read_bytes())


    def make_catalog_with_security(self, root: Path) -> tuple[Path, int, int]:
        curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
        built = root / "built"
        test_sqlite_catalog.run_builder(common.ROOT, built, curated, raw, enriched, websites)
        database = built / "omega-catalog.sqlite"
        with closing(sqlite3.connect(database)) as db:
            db.row_factory = sqlite3.Row
            sigmascope.ensure_schema(db)
            variant = db.execute(
                """SELECT v.variant_id,v.plugin_id,v.source_id,v.assembly_version
                     FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id
                    WHERE v.active=1 AND p.active=1 ORDER BY v.variant_id LIMIT 1"""
            ).fetchone()
            self.assertIsNotNone(variant)
            variant_id = int(variant["variant_id"])
            plugin_id = int(variant["plugin_id"])
            source_id = int(variant["source_id"])
            artifact = "a" * 64
            db.execute(
                """INSERT INTO plugin_security_scans(
                     scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,
                     artifact_sha256,scanner_version,status,scanned_at_utc,highest_severity,
                     informational_count,caution_count,high_count,critical_count,capabilities_json,
                     source_available,source_repository,source_commit,source_to_binary_verified,report_json,error)
                     VALUES(?,?,?,?,?,'stable','https://example.invalid/plugin.zip',?,?,'complete',
                     '2026-08-17T00:00:00Z','caution',0,1,0,0,'[]',1,'https://example.invalid/repo',
                     'abc',1,'{}','')""",
                (9001, plugin_id, variant_id, source_id, str(variant["assembly_version"] or "1.0.0"), artifact, sigmascope.SCANNER_VERSION),
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
                (variant_id, str(variant["assembly_version"] or "1.0.0"), artifact, sigmascope.SCANNER_VERSION),
            )
            db.execute(
                """INSERT INTO plugin_security_findings(scan_id,rule_id,severity,category,title,description,evidence_json)
                   VALUES(9001,'fixture.rule','caution','fixture','Fixture','Fixture finding','[\"fixture\"]')"""
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
        return database, variant_id, plugin_id

    def _make_reprojection_compatible(self, database: Path) -> None:
        report = {
            "schema": "omega.plugin-security.scan.v1",
            "artifactAnalysisRevision": "artifact-analysis-fixture",
            "sourceAnalysisRevision": "source-analysis-fixture",
            "dependencyIntelligence": {
                "staticPatternMatchContractVersion": 1,
                "staticPatternMatches": [
                    {
                        "origin": "artifact",
                        "pattern": "System.Net.Http.HttpClient",
                        "evidenceLabel": "metadata:Fixture.dll",
                        "evidence": ["metadata:Fixture.dll: System.Net.Http.HttpClient"],
                    },
                    {
                        "origin": "artifact",
                        "pattern": "Process.Start",
                        "evidenceLabel": "metadata:Fixture.dll",
                        "evidence": ["metadata:Fixture.dll: Process.Start"],
                    },
                ],
            },
        }
        encoded = json.dumps(report, separators=(",", ":"))
        with closing(sqlite3.connect(database)) as db:
            db.execute("UPDATE plugin_security_scans SET report_json=? WHERE scan_id=9001", (encoded,))
            db.execute("UPDATE plugin_security_current SET report_json=? WHERE scan_id=9001", (encoded,))
            db.commit()

    def _frozen_srl_definitions(self, root: Path) -> Path:
        definitions = root / "definitions-srl"
        definitions.mkdir(parents=True, exist_ok=True)
        descriptor = definition_packs.freeze_pack_root(
            common.ROOT / "security-definitions" / "packs", definitions, include_local=False
        )
        (definitions / "index.json").write_text(
            json.dumps({
                "schema": "omega.definitions.v1",
                "definitionsRevision": "defs-v1-phase10-fixture",
                "srlDefinitionPacks": descriptor,
            }, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return definitions

    def test_phase10_srl_sidecar_is_hash_pinned_nonproduction_and_snapshot_valid(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-srl-sidecar-") as td:
            root = Path(td)
            database, variant_id, _ = self.make_catalog_with_security(root)
            self._make_reprojection_compatible(database)
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            definitions = self._frozen_srl_definitions(root)

            descriptor = materialize_srl_reprojection_sidecar(evidence, definitions)
            self.assertTrue(descriptor["enabled"], descriptor)
            self.assertFalse(descriptor["productionRuleEvaluationEnabled"])
            self.assertFalse(descriptor["productionWriteBack"])
            root_index = json.loads((evidence / "index.json").read_text(encoding="utf-8"))
            root_index["srlRuleProjections"] = {key: value for key, value in descriptor.items() if key != "validation"}
            (evidence / "index.json").write_text(json.dumps(root_index, sort_keys=True, indent=2) + "\n", encoding="utf-8")

            validation = validate_snapshot(evidence, require_no_orphans=True)
            self.assertTrue(validation["ok"], validation["errors"])
            projection_index = json.loads((evidence / "rule-projections" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(1, projection_index["counts"]["reprojectedVariants"])
            self.assertEqual("analysis-requests.json", projection_index["analysisRequests"]["path"])
            deep_request_path = evidence / "rule-projections" / projection_index["analysisRequests"]["path"]
            deep_request_payload = json.loads(deep_request_path.read_text(encoding="utf-8"))
            self.assertEqual("omega.stigma-1.analysis-requests.v1", deep_request_payload["schema"])
            self.assertEqual("deep-scan-evidence-acquisition-only", deep_request_payload["queueMutationScope"])
            self.assertFalse(deep_request_payload["productionFindingsWriteBack"])
            projection_path = evidence / "rule-projections" / projection_index["variants"][0]["path"]
            projection = json.loads(projection_path.read_text(encoding="utf-8"))
            self.assertEqual(variant_id, projection["variantId"])
            self.assertIn("compound.network-execute", [item["ruleId"] for item in projection["findings"]])
            self.assertFalse(projection["productionWriteBack"])

    def test_phase10_snapshot_validation_rejects_projection_tampering_and_orphans(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-srl-sidecar-tamper-") as td:
            root = Path(td)
            database, _variant_id, _ = self.make_catalog_with_security(root)
            self._make_reprojection_compatible(database)
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            definitions = self._frozen_srl_definitions(root)
            descriptor = materialize_srl_reprojection_sidecar(evidence, definitions)
            root_index = json.loads((evidence / "index.json").read_text(encoding="utf-8"))
            root_index["srlRuleProjections"] = {key: value for key, value in descriptor.items() if key != "validation"}
            (evidence / "index.json").write_text(json.dumps(root_index, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            projection_index = json.loads((evidence / "rule-projections" / "index.json").read_text(encoding="utf-8"))
            projection_path = evidence / "rule-projections" / projection_index["variants"][0]["path"]
            projection_path.write_text(projection_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
            validation = validate_snapshot(evidence, require_no_orphans=True)
            self.assertFalse(validation["ok"])
            self.assertTrue(any("srlRuleProjections" in item and "sha256 mismatch" in item for item in validation["errors"]), validation["errors"])

            # Re-materializing repairs the set; an undeclared leftover must still fail closed.
            descriptor = materialize_srl_reprojection_sidecar(evidence, definitions)
            root_index = json.loads((evidence / "index.json").read_text(encoding="utf-8"))
            root_index["srlRuleProjections"] = {key: value for key, value in descriptor.items() if key != "validation"}
            (evidence / "index.json").write_text(json.dumps(root_index, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            orphan = evidence / "rule-projections" / "variants" / "999999.json"
            orphan.write_text("{}\n", encoding="utf-8")
            validation = validate_snapshot(evidence, require_no_orphans=True)
            self.assertFalse(validation["ok"])
            self.assertTrue(any("orphan SRL rule projection file" in item for item in validation["errors"]), validation["errors"])

    def test_phase10_missing_frozen_definitions_removes_stale_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-srl-sidecar-disabled-") as td:
            root = Path(td)
            candidate = root / "candidate"
            (candidate / "rule-projections").mkdir(parents=True)
            (candidate / "rule-projections" / "stale.json").write_text("{}\n", encoding="utf-8")
            result = materialize_srl_reprojection_sidecar(candidate, None)
            self.assertFalse(result["enabled"])
            self.assertFalse((candidate / "rule-projections").exists())

    def test_daily_marketplace_compiler_reapplies_frozen_definitions_without_artifact_rescan(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-daily-definitions-projection-") as td:
            root = Path(td)
            database, variant_id, _ = self.make_catalog_with_security(root)
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            source_index = json.loads((evidence / "index.json").read_text(encoding="utf-8"))
            source_security_revision = str((source_index.get("revisions") or {}).get("securityRevision") or "")

            catalog_root = root / "catalog"
            catalog_json_store.export_snapshot(database, catalog_root, source_commit="fixture")
            evidence_index = json.loads((evidence / "index.json").read_text(encoding="utf-8"))
            evidence_index.setdefault("revisions", {})["catalogIdentityEpoch"] = catalog_json_store.IDENTITY_EPOCH
            (evidence / "index.json").write_text(json.dumps(evidence_index), encoding="utf-8")
            advisory_file = root / "today-osv.json"
            advisory_file.write_text(json.dumps({
                "schema": "omega.public-advisories.v1",
                "generatedAtUtc": "2026-08-19T00:00:00Z",
                "source": "OSV",
                "ecosystem": "NuGet",
                "queriedPackages": 1,
                "matchedPackages": 1,
                "advisories": [{
                    "id": "OSV-TODAY",
                    "componentKind": "nuget",
                    "name": "Example.Package",
                    "affectedVersions": ["1.2.3"],
                    "fixedVersion": "1.2.4",
                    "severity": "high",
                    "title": "Today's frozen advisory",
                    "url": "https://osv.dev/vulnerability/OSV-TODAY",
                    "source": "OSV",
                }],
            }), encoding="utf-8")
            definitions_root = root / "definitions"
            definitions = definitions_snapshot.build_snapshot(
                repo_root=common.ROOT, evidence_root=evidence, output=definitions_root,
                source_commit="fixture", advisories_input=advisory_file,
            )
            output = root / "compiled"
            result = compile_marketplace_snapshot.build(
                catalog_root=catalog_root, definitions_root=definitions_root, evidence_root=evidence,
                output=output, download_url="https://example.invalid/omega-marketplace.sqlite.zip",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
            )
            validation = validate_marketplace_catalog.validate_bytes(
                (output / "catalog.json").read_bytes(),
                (output / "omega-marketplace.sqlite.zip").read_bytes(),
                require_v2=True,
            )
            self.assertEqual("ok", validation["integrity"])
            descriptor = json.loads((output / "catalog.json").read_text(encoding="utf-8"))
            self.assertEqual(2, descriptor["schemaVersion"])
            self.assertEqual("omega.catalog.marketplace.v2", descriptor["schema"])
            self.assertTrue(descriptor["catalogRevision"].startswith("cat-v2-"))
            self.assertTrue(descriptor["catalogJsonRevision"].startswith("cat-json-v1-"))
            self.assertEqual(descriptor["catalogRevision"].removeprefix("cat-v2-"),
                             descriptor["catalogJsonRevision"].removeprefix("cat-json-v1-"))

            with closing(sqlite3.connect(output / "omega-marketplace.sqlite")) as db:
                row = db.execute(
                    "SELECT security_known_advisory_count,security_known_advisory_highest_severity FROM runtime_plugin_variants WHERE variant_id=?",
                    (variant_id,),
                ).fetchone()
                self.assertEqual((1, "high"), tuple(row))
                meta = {str(k): str(v) for k, v in db.execute("SELECT key,value FROM catalog_meta")}
            self.assertEqual(definitions["definitionsRevision"], meta["definitions_revision"])
            self.assertEqual(source_security_revision, meta["source_security_revision"])
            self.assertEqual(result["inputs"]["securityRevision"], meta["security_revision"])
            self.assertNotEqual(source_security_revision, meta["security_revision"], "today's Definitions-derived advisory projection must have its own truthful security revision")
            self.assertEqual(0, result["definitionsProjectionRefresh"]["dependencyGraph"]["dependencies"] - 1)
            # The compiler refreshed derived state only; immutable artifact scan history stayed one row.
            self.assertEqual(1, result["materializedEvidence"]["currentVariantsMaterialized"])


    def test_daily_marketplace_compiler_ignores_incompatible_legacy_security_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-daily-clean-security-baseline-") as td:
            root = Path(td)
            database, _variant_id, _ = self.make_catalog_with_security(root)
            evidence = root / "legacy-evidence"
            migrate(database, evidence, reset=True)
            legacy_index = json.loads((evidence / "index.json").read_text(encoding="utf-8"))
            self.assertFalse((legacy_index.get("revisions") or {}).get("catalogIdentityEpoch"))

            catalog_root = root / "catalog"
            catalog_json_store.export_snapshot(database, catalog_root, source_commit="fixture")
            advisory_file = root / "empty-osv.json"
            advisory_file.write_text(json.dumps({
                "schema": "omega.public-advisories.v1", "generatedAtUtc": "2026-08-19T00:00:00Z",
                "source": "OSV", "ecosystem": "NuGet", "queriedPackages": 1, "matchedPackages": 0,
                "queriedPackageVersionPairs": [{"name": "Example.Package", "version": "1.2.3"}],
                "advisories": [],
            }), encoding="utf-8")
            definitions_root = root / "definitions"
            definitions_snapshot.build_snapshot(
                repo_root=common.ROOT, evidence_root=evidence, output=definitions_root,
                source_commit="fixture", advisories_input=advisory_file,
            )
            output = root / "compiled"
            result = compile_marketplace_snapshot.build(
                catalog_root=catalog_root, definitions_root=definitions_root, evidence_root=evidence,
                output=output, download_url="https://example.invalid/omega-marketplace.sqlite.zip",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
            )
            descriptor = json.loads((output / "catalog.json").read_text(encoding="utf-8"))
            self.assertFalse(descriptor["evidenceCompatible"])
            self.assertEqual("", descriptor["evidenceRevision"])
            self.assertEqual(0, result["materializedEvidence"]["currentVariantsMaterialized"])
            self.assertFalse(result["materializedEvidence"]["evidenceInherited"])
            with closing(sqlite3.connect(output / "omega-marketplace.sqlite")) as db:
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM marketplace_security_current").fetchone()[0])
                meta = {str(k): str(v) for k, v in db.execute("SELECT key,value FROM catalog_meta")}
            self.assertEqual(catalog_json_store.IDENTITY_EPOCH, meta["catalog_identity_epoch"])
            self.assertEqual("0", meta["evidence_compatible"])
            self.assertEqual("", meta["evidence_revision"])

    def test_v2_sqlite_test_connections_are_windows_cleanup_safe(self) -> None:
        # sqlite3.Connection.__exit__ commits/rolls back but does not close the handle.
        # A leaked handle is tolerated by POSIX unlink semantics and rejected by Windows,
        # so v2 temporary-database tests must always wrap connections in closing().
        for path in (
            Path(__file__),
            Path(__file__).with_name("test_security_evidence_v2.py"),
        ):
            self.assertNotIn("with sqlite3." + "connect(", path.read_text(encoding="utf-8"))

    def test_materializes_published_v2_into_disposable_working_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-production-") as td:
            root = Path(td)
            database, variant_id, _ = self.make_catalog_with_security(root)
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            self.assertTrue(validate_snapshot(evidence)["ok"])

            # Simulate the catalog builder delivering identities/presentation without detailed state.
            base = root / "base.sqlite"
            shutil.copy2(database, base)
            with closing(sqlite3.connect(base)) as db:
                sigmascope.ensure_schema(db)
                db.execute("PRAGMA foreign_keys=OFF")
                for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchall():
                    db.execute(f'DELETE FROM "{row[0]}"')
                db.execute("PRAGMA foreign_keys=ON")
                db.commit()

            work = root / "work.sqlite"
            report = materialize_current_state(base, evidence, work)
            self.assertEqual(report["currentVariantsMaterialized"], 1)
            with closing(sqlite3.connect(work)) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM plugin_security_current").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM plugin_security_findings").fetchone()[0], 1)
                dep = db.execute("SELECT kind,name,resolved_version FROM plugin_security_dependencies").fetchone()
                self.assertEqual(dep, ("nuget-resolved", "Example.Package", "1.2.3"))
                self.assertEqual(db.execute("SELECT scan_id FROM plugin_security_current WHERE variant_id=?", (variant_id,)).fetchone()[0], 9001)

    def test_materialization_repairs_stale_v2_summary_from_normalized_findings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-stale-summary-repair-") as td:
            root = Path(td)
            database, variant_id, _ = self.make_catalog_with_security(root)
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            variant_path = next((evidence / "variants").rglob("*.json"))
            payload = json.loads(variant_path.read_text(encoding="utf-8"))
            legacy_report = {
                "scannerVersion": "2.0.0",
                "status": "complete",
                "highestSeverity": "caution",
                "counts": {"informational": 0, "caution": 1, "high": 0, "critical": 0},
                "capabilities": ["Fixture capability"],
                "source": {"repository": "https://example.invalid/repo"},
            }
            for field in ("scan", "current"):
                payload[field]["highest_severity"] = "none"
                payload[field]["informational_count"] = 0
                payload[field]["caution_count"] = 0
                payload[field]["high_count"] = 0
                payload[field]["critical_count"] = 0
                payload[field]["report_json"] = legacy_report
            payload["current"]["findings_json"] = []
            variant_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            base = root / "base.sqlite"
            shutil.copy2(database, base)
            with closing(sqlite3.connect(base)) as db:
                sigmascope.ensure_schema(db)
                db.execute("PRAGMA foreign_keys=OFF")
                for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchall():
                    db.execute(f'DELETE FROM "{row[0]}"')
                db.execute("PRAGMA foreign_keys=ON")
                db.commit()

            work = root / "work.sqlite"
            materialize_current_state(base, evidence, work)
            with closing(sqlite3.connect(work)) as db:
                db.row_factory = sqlite3.Row
                scan = db.execute("SELECT highest_severity,informational_count,caution_count,high_count,critical_count,report_json FROM plugin_security_scans WHERE scan_id=9001").fetchone()
                current = db.execute("SELECT highest_severity,informational_count,caution_count,high_count,critical_count,findings_json,report_json FROM plugin_security_current WHERE variant_id=?", (variant_id,)).fetchone()
                self.assertEqual(tuple(scan[:5]), ("caution", 0, 1, 0, 0))
                self.assertEqual(tuple(current[:5]), ("caution", 0, 1, 0, 0))
                self.assertEqual(json.loads(current["findings_json"])[0]["ruleId"], "fixture.rule")
                self.assertEqual(json.loads(scan["report_json"])["highestSeverity"], "caution")
                self.assertEqual(json.loads(current["report_json"])["counts"]["caution"], 1)

            # Reproduce the live workflow's next gate: the independent developer audit
            # must accept the self-healed historical row after materialization.
            inspector = developer_view.SecurityInspector(work)
            try:
                failures = [item for item in inspector.audit_variant(variant_id) if item.status == "fail"]
                self.assertEqual([], failures)
            finally:
                inspector.close()

    def test_candidate_synchronization_repairs_legacy_oversized_variant_reports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-legacy-report-repair-") as td:
            root = Path(td)
            database, variant_id, _plugin_id = self.make_catalog_with_security(root)
            candidate = root / "candidate"
            migrate(database, candidate, reset=True)
            variant_path = next((candidate / "variants").rglob("*.json"))
            payload = json.loads(variant_path.read_text(encoding="utf-8"))
            legacy = {
                "opaqueLegacyEvidence": "x" * (18 * 1024 * 1024),
                "source": {"dependencyIntelligence": {"fingerprints": {"relevantSourceSha256": "c" * 64}}},
            }
            payload["scan"]["report_json"] = legacy
            payload["current"]["report_json"] = legacy
            variant_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            self.assertGreater(variant_path.stat().st_size, 32 * 1024 * 1024)

            # Loading an old published branch must not recreate the oversized report
            # in the disposable SQLite working database either.
            work_database = root / "materialized.sqlite"
            materialize_current_state(database, candidate, work_database)
            with closing(sqlite3.connect(work_database)) as db:
                report_json = db.execute(
                    "SELECT report_json FROM plugin_security_current WHERE variant_id=?", (variant_id,)
                ).fetchone()[0]
            compact = json.loads(report_json)
            self.assertEqual(compact["schema"], "omega.security-evidence.scan-summary.v2")
            self.assertLess(len(report_json.encode("utf-8")), 256 * 1024)

            synchronize_candidate(candidate, database, {variant_id})
            self.assertLess(variant_path.stat().st_size, 1024 * 1024)
            repaired = json.loads(variant_path.read_text(encoding="utf-8"))
            self.assertEqual(repaired["scan"]["report_json"]["schema"], "omega.security-evidence.scan-summary.v2")
            self.assertEqual(
                repaired["scan"]["report_json"]["source"]["dependencyIntelligence"]["fingerprints"]["relevantSourceSha256"],
                "c" * 64,
            )
            self.assertNotIn("opaqueLegacyEvidence", variant_path.read_text(encoding="utf-8"))

    def test_candidate_synchronization_adapts_legacy_analysis_without_rescan(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-observation-legacy-adapter-") as td:
            root = Path(td)
            database, variant_id, _plugin_id = self.make_catalog_with_security(root)
            candidate = root / "candidate"
            migrate(database, candidate, reset=True)
            variant_path = next((candidate / "variants").rglob(f"{variant_id}.json"))
            payload = json.loads(variant_path.read_text(encoding="utf-8"))
            analysis_dir = candidate / payload["analysis"]["path"]
            manifest_path = analysis_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest.pop("observationContract", None)
            for descriptor in (manifest.get("datasets") or {}).values():
                if isinstance(descriptor, dict):
                    for field in ("collection", "collectionSchema", "semanticClass", "srlEligible", "sameRecordSemantics"):
                        descriptor.pop(field, None)
            manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            payload.pop("observations", None)
            payload.pop("projection", None)
            variant_path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            analysis_files_before = {
                path.relative_to(candidate).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in analysis_dir.rglob("*") if path.is_file() and path != manifest_path
            }

            report = synchronize_candidate(candidate, database, set())
            self.assertGreaterEqual(report["variantsUpdated"], 1)
            adapted = json.loads(variant_path.read_text(encoding="utf-8"))
            self.assertEqual("omega.sigmascope.observation-contract.v1", adapted["observations"]["schema"])
            self.assertTrue(adapted["observations"]["legacyCompatibility"])
            self.assertEqual("omega.sigmascope.projection-contract.v1", adapted["projection"]["schema"])
            self.assertEqual(payload["analysis"]["analysisId"], adapted["analysis"]["analysisId"])
            analysis_files_after = {
                path.relative_to(candidate).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in analysis_dir.rglob("*") if path.is_file() and path != manifest_path
            }
            self.assertEqual(analysis_files_before, analysis_files_after, "compatibility adaptation must not rewrite retained observation bytes")

    def test_failed_revalidation_restores_last_known_good_current_pointer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-retain-") as td:
            root = Path(td)
            database, variant_id, plugin_id = self.make_catalog_with_security(root)
            previous = _current_rows(database)
            with closing(sqlite3.connect(database)) as db:
                source_id = int(db.execute("SELECT source_id FROM plugin_variants WHERE variant_id=?", (variant_id,)).fetchone()[0])
                db.execute(
                    """INSERT INTO plugin_security_scans(scan_id,plugin_id,variant_id,source_id,artifact_sha256,
                       scanner_version,status,scanned_at_utc,report_json,error)
                       VALUES(9002,?,?,?,?,?,'failed','2026-08-17T01:00:00Z','{}','network failure')""",
                    (plugin_id, variant_id, source_id, "b" * 64, sigmascope.SCANNER_VERSION),
                )
                db.execute(
                    """UPDATE plugin_security_current SET scan_id=9002,artifact_sha256=?,status='failed',error='network failure'
                       WHERE variant_id=?""",
                    ("b" * 64, variant_id),
                )
                db.commit()
            successful, failed = _restore_last_known_good(database, previous)
            self.assertEqual(successful, [])
            self.assertEqual(failed, [variant_id])
            with closing(sqlite3.connect(database)) as db:
                current = db.execute("SELECT scan_id,status,artifact_sha256 FROM plugin_security_current WHERE variant_id=?", (variant_id,)).fetchone()
                self.assertEqual(current, (9001, "complete", "a" * 64))


    def test_full_noop_pipeline_builds_valid_candidate_and_marketplace_without_network(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-full-pipeline-") as td:
            root = Path(td)
            database, _variant_id, _plugin_id = self.make_catalog_with_security(root)
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            self.assertTrue(validate_snapshot(evidence)["ok"])

            base = root / "base.sqlite"
            shutil.copy2(database, base)
            with closing(sqlite3.connect(base)) as db:
                sigmascope.ensure_schema(db)
                db.execute("PRAGMA foreign_keys=OFF")
                for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchall():
                    db.execute(f'DELETE FROM "{row[0]}"')
                db.execute("PRAGMA foreign_keys=ON")
                db.commit()

            descriptor = root / "built" / "catalog.json"
            self.assertTrue(descriptor.is_file())
            args = SimpleNamespace(
                base_database=base,
                descriptor=descriptor,
                current_evidence=evidence,
                candidate_evidence=root / "candidate",
                work_dir=root / "work",
                publication_output=root / "publication",
                previous_marketplace_descriptor=None,
                marketplace_download_url="https://example.invalid/catalog-latest/omega-marketplace.sqlite.zip",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
                source_overrides=common.ROOT / "sources" / "source-overrides.json",
                max_scans=0,
                rescan_after_hours=168,
                max_batch_seconds=0,
                internal_names="",
                skip_source=True,
                osv_timeout=1.0,
                max_osv_packages=2000,
                github_output=None,
            )

            def fake_collect(index_path, output, timeout=20.0, max_packages=2000):
                import collect_public_advisories
                packages = collect_public_advisories.observed_nuget_index(Path(index_path), max_packages)
                document = {
                    "schema": "omega.public-advisories.v1",
                    "generatedAtUtc": "2026-08-17T00:00:00Z",
                    "source": "OSV",
                    "ecosystem": "NuGet",
                    "queriedPackages": len(packages),
                    "matchedPackages": 0,
                    "advisories": [],
                }
                Path(output).write_text(__import__("json").dumps(document, indent=2) + "\n", encoding="utf-8")
                return document

            with patch("production_sigmascope_v2_pipeline.collect_public_advisories.collect_from_nuget_index", side_effect=fake_collect):
                result = run_pipeline(args)

            self.assertTrue(result["candidate"]["validation"]["ok"], result["candidate"]["validation"] )
            self.assertEqual(result["osv"]["gate"], "pass")
            self.assertTrue((root / "candidate" / "index.json").is_file())
            self.assertTrue((root / "publication" / "omega-marketplace.sqlite").is_file())
            self.assertTrue((root / "publication" / "omega-marketplace.sqlite.zip").is_file())
            self.assertEqual(result["summary"]["nugetPackageVersionPairs"], 1)
            root_index = json.loads((root / "candidate" / "index.json").read_text(encoding="utf-8"))
            osv = root_index["source"]["osv"]
            self.assertEqual(osv["schema"], "omega.security-evidence.osv-coverage.v1")
            self.assertEqual(osv["inputPackageVersionPairs"], 1)
            self.assertEqual(osv["expectedQueryPackageVersionPairs"], 1)
            self.assertEqual(osv["queriedPackageVersionPairs"], 1)
            self.assertEqual(osv["queryGate"], "pass")
            variant_file = next((root / "candidate" / "variants").rglob("*.json"))
            payload = json.loads(variant_file.read_text(encoding="utf-8"))
            self.assertEqual(payload["presentation"]["schema"], "omega.evidence.presentation.v1")
            self.assertIn("projectRepository", payload["presentation"])
            self.assertIn("plugin", payload["presentation"])
            for name in ("dependencyResolutions", "dependencyIssues", "advisoryMatches"):
                self.assertNotIn(name, payload.get("derived") or {})
                descriptor = (payload.get("derivedEvidence") or {}).get(name)
                self.assertIsInstance(descriptor, dict)
                self.assertIn("recordDigest", descriptor)
                for file_info in descriptor.get("files") or []:
                    self.assertLessEqual(int(file_info.get("bytes") or 0), 32 * 1024 * 1024)


    def test_full_incremental_pipeline_merges_fresh_deps_json_analysis(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-incremental-pipeline-") as td:
            root = Path(td)
            database, variant_id, _plugin_id = self.make_catalog_with_security(root)
            # The published baseline came from Sigmascope generation 2.4.0; 2.5.0 must refresh it.
            with closing(sqlite3.connect(database)) as db:
                db.execute("UPDATE plugin_security_scans SET scanner_version='2.4.0' WHERE scan_id=9001")
                db.execute("UPDATE plugin_security_current SET scanner_version='2.4.0' WHERE variant_id=?", (variant_id,))
                db.commit()
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            self.assertTrue(validate_snapshot(evidence)["ok"])

            base = root / "base.sqlite"
            shutil.copy2(database, base)
            with closing(sqlite3.connect(base)) as db:
                sigmascope.ensure_schema(db)
                db.execute("PRAGMA foreign_keys=OFF")
                for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%'").fetchall():
                    db.execute(f'DELETE FROM "{row[0]}"')
                db.execute("PRAGMA foreign_keys=ON")
                db.commit()

            deps = {
                "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0/win-x64"},
                "targets": {
                    ".NETCoreApp,Version=v8.0/win-x64": {
                        "Example.Package/9.8.7": {"runtime": {"lib/net8.0/Example.Package.dll": {}}}
                    }
                },
                "libraries": {"Example.Package/9.8.7": {"type": "package", "serviceable": True, "sha512": ""}},
            }
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("FixturePlugin.deps.json", json.dumps(deps))
            artifact = buffer.getvalue()

            args = SimpleNamespace(
                base_database=base,
                descriptor=root / "built" / "catalog.json",
                current_evidence=evidence,
                candidate_evidence=root / "candidate",
                work_dir=root / "work",
                publication_output=root / "publication",
                previous_marketplace_descriptor=None,
                marketplace_download_url="https://example.invalid/catalog-latest/omega-marketplace.sqlite.zip",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
                source_overrides=common.ROOT / "sources" / "source-overrides.json",
                max_scans=1,
                rescan_after_hours=168,
                max_batch_seconds=0,
                internal_names="",
                skip_source=True,
                osv_timeout=1.0,
                max_osv_packages=2000,
                github_output=None,
            )

            def fake_collect(index_path, output, timeout=20.0, max_packages=2000):
                import collect_public_advisories
                packages = collect_public_advisories.observed_nuget_index(Path(index_path), max_packages)
                document = {
                    "schema": "omega.public-advisories.v1",
                    "generatedAtUtc": "2026-08-17T00:00:00Z",
                    "source": "OSV",
                    "ecosystem": "NuGet",
                    "queriedPackages": len(packages),
                    "matchedPackages": 0,
                    "advisories": [],
                }
                Path(output).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                return document

            with patch("sigmascope.request_bytes", return_value=(artifact, "https://example.invalid/plugin.zip")), \
                 patch("production_sigmascope_v2_pipeline.collect_public_advisories.collect_from_nuget_index", side_effect=fake_collect):
                result = run_pipeline(args)

            self.assertEqual(len(result["successfulVariantIds"]), 1)
            successful_variant_id = result["successfulVariantIds"][0]
            self.assertTrue(result["candidate"]["validation"]["ok"], result["candidate"]["validation"] )
            self.assertGreaterEqual(result["summary"]["nugetPackageVersionPairs"], 1)
            self.assertGreaterEqual(result["osv"]["queriedPackages"], 1)
            variant_files = list((root / "candidate" / "variants").rglob(f"{successful_variant_id}.json"))
            self.assertEqual(len(variant_files), 1)
            payload = json.loads(variant_files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["current"]["scanner_version"], sigmascope.SCANNER_VERSION)
            analysis_path = payload["analysis"]["path"]
            dependency_rows = __import__("security_evidence_v2").read_dataset_rows(root / "candidate", analysis_path, "dependencies")
            self.assertTrue(any(row.get("kind") == "nuget-resolved" and row.get("name") == "Example.Package" and row.get("resolved_version") == "9.8.7" for row in dependency_rows))


    def test_persistent_queue_selects_exact_variant_and_records_provenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-queue-pipeline-") as td:
            root = Path(td)
            database, variant_id, _plugin_id = self.make_catalog_with_security(root)
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
                "queueSeedRevision": "queue-seed-v1-fixture",
                "catalogRevision": "cat-json-v1-fixture",
                "definitionsRevision": "defs-v1-fixture",
                "scannerRevision": "scanner-v1-fixture",
                "scannerBundleSha256": "b" * 64,
                "ruleSetRevision": "rules-v1-fixture",
                "artifactAnalysisRevision": "artifact-analysis-v1-fixture",
                "sourceAnalysisRevision": "source-analysis-v1-fixture",
                "sourceObservationRevision": "source-observations-v1-fixture",
                "counts": {"queued": 1},
                "items": [{
                    "queueKey": f"variant-{variant_id}",
                    "workType": "artifact",
                    "targetFingerprint": "artifact-target-v2-fixture",
                    "variantId": variant_id,
                    "pluginId": int(variant[1]),
                    "sourceId": int(variant[2]),
                    "internalName": str(variant[3]),
                    "name": str(variant[4]),
                    "sourceName": str(variant[5]),
                    "assemblyVersion": str(variant[6]),
                    "artifactChannel": "stable",
                    "artifactUrl": str(variant[7]),
                    "repositoryUrl": "https://github.com/example/plugin",
                    "sourceRepositoryUrl": "",
                    "catalogRevision": "cat-json-v1-fixture",
                    "definitionsRevision": "defs-v1-fixture",
                    "artifactAnalysisRevision": "artifact-analysis-v1-fixture",
                    "sourceAnalysisRevision": "source-analysis-v1-fixture",
                    "ruleSetRevision": "rules-v1-fixture",
                    "reasons": ["artifact_analysis_changed"],
                    "primaryReason": "artifact_analysis_changed",
                    "priority": 750,
                    "currentScanId": 9001,
                    "currentScannedAtUtc": "2026-08-17T00:00:00Z",
                    "currentArtifactSha256": "a" * 64,
                    "enqueuedAtUtc": "2026-08-19T00:00:00Z",
                }],
            }), encoding="utf-8")

            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("fixture.txt", "queue provenance fixture")
            artifact = buffer.getvalue()
            args = SimpleNamespace(
                base_database=base, descriptor=None, current_evidence=evidence,
                candidate_evidence=root / "candidate", work_dir=root / "work", publication_output=None,
                previous_marketplace_descriptor=None, marketplace_download_url="",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
                source_overrides=common.ROOT / "sources" / "source-overrides.json", max_scans=1,
                rescan_after_hours=168, max_batch_seconds=0, internal_names="", variant_ids="", skip_source=True,
                osv_timeout=1.0, max_osv_packages=2000, github_output=None, skip_marketplace=True,
                frozen_advisories=None, catalog_revision="cat-json-v1-fixture", definitions_revision="defs-v1-fixture",
                scanner_revision="scanner-v1-fixture", scanner_bundle_sha256="b" * 64,
                artifact_analysis_revision="artifact-analysis-v1-fixture", source_analysis_revision="source-analysis-v1-fixture",
                rule_set_revision="rules-v1-fixture", queue_seed=queue_seed,
            )

            def fake_collect(index_path, output, timeout=20.0, max_packages=2000):
                import collect_public_advisories
                packages = collect_public_advisories.observed_nuget_index(Path(index_path), max_packages)
                document = {
                    "schema": "omega.public-advisories.v1", "generatedAtUtc": "2026-08-19T00:00:00Z",
                    "source": "OSV", "ecosystem": "NuGet", "queriedPackages": len(packages),
                    "matchedPackages": 0, "advisories": [],
                }
                Path(output).write_text(json.dumps(document), encoding="utf-8")
                return document

            with patch("sigmascope.request_bytes", return_value=(artifact, str(variant[7]))), \
                 patch("production_sigmascope_v2_pipeline.collect_public_advisories.collect_from_nuget_index", side_effect=fake_collect):
                result = run_pipeline(args)

            self.assertEqual(variant_id, int(result["queue"]["selected"]["variantId"]))
            self.assertEqual("artifact_analysis_changed", result["queue"]["selected"]["primaryReason"] )
            self.assertTrue(result["queue"]["stateChanged"])
            queue_state = json.loads((root / "candidate" / "scanner-queue.json").read_text(encoding="utf-8"))
            self.assertEqual("complete", queue_state["items"][f"variant-{variant_id}"]["state"] )
            source_followup = queue_state["items"].get(f"source-variant-{variant_id}")
            self.assertIsNotNone(source_followup)
            self.assertEqual("source", source_followup["workType"])
            self.assertEqual("pending", source_followup["state"])
            self.assertGreater(int(source_followup["priority"]), int(queue_state["items"][f"variant-{variant_id}"]["priority"]))
            root_index = json.loads((root / "candidate" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(scan_queue.STATE_SCHEMA, root_index["scannerQueue"]["schema"] )
            variant_file = next((root / "candidate" / "variants").rglob(f"{variant_id}.json"))
            payload = json.loads(variant_file.read_text(encoding="utf-8"))
            provenance = payload["current"]["report_json"]["scanProvenance"]
            self.assertEqual("rules-v1-fixture", provenance["ruleSetRevision"] )
            self.assertEqual("defs-v1-fixture", provenance["definitionsRevision"] )
            self.assertEqual("scanner-v1-fixture", provenance["scannerRevision"] )
            self.assertEqual("b" * 64, provenance["scannerBundleSha256"] )
            self.assertEqual("artifact-analysis-v1-fixture", provenance["artifactAnalysisRevision"] )
            self.assertEqual("source-analysis-v1-fixture", provenance["sourceAnalysisRevision"] )
            self.assertEqual("artifact_analysis_changed", provenance["primaryReason"] )
            self.assertEqual("artifact", provenance["workType"] )
            self.assertEqual("artifact", payload["current"]["report_json"]["workType"] )
            self.assertFalse(payload["current"]["report_json"]["source"]["available"] )


    def test_source_queue_worker_attaches_source_without_artifact_download(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-source-queue-") as td:
            root = Path(td)
            database, variant_id, _plugin_id = self.make_catalog_with_security(root)
            with closing(sqlite3.connect(database)) as db:
                db.row_factory = sqlite3.Row
                variant = db.execute(
                    "SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,s.name,v.assembly_version,v.download_link_install "
                    "FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id JOIN sources s ON s.source_id=v.source_id "
                    "WHERE v.variant_id=?", (variant_id,)
                ).fetchone()
                report = {
                    "schema": "omega.plugin-security.scan.v1", "workType": "artifact", "artifactSha256": "a" * 64,
                    "artifactAnalysisRevision": "scanner-v1-fixture+rules-v1-fixture", "resolvedArtifactUrl": str(variant[7]),
                    "source": {"available": False, "repository": "https://github.com/example/plugin", "commit": "", "attribution": {"confidence": 0}},
                    "findings": [{"ruleId": "fixture.rule", "severity": "caution", "category": "fixture", "title": "Fixture", "description": "Fixture finding", "evidence": ["fixture"]}],
                    "capabilities": [], "automation": {"level": "none", "capabilities": [], "findings": []},
                    "dependencyIntelligence": sigmascope.empty_dependency_intelligence("artifact"),
                    "scanProvenance": {"scannerRevision": "scanner-v1-fixture", "ruleSetRevision": "rules-v1-fixture"},
                }
                db.execute("UPDATE plugin_security_scans SET source_available=0,source_repository=?,source_commit='',report_json=? WHERE scan_id=9001",
                           ("https://github.com/example/plugin", json.dumps(report)))
                db.execute("UPDATE plugin_security_current SET source_available=0,source_repository=?,source_commit='',report_json=? WHERE variant_id=?",
                           ("https://github.com/example/plugin", json.dumps(report), variant_id))
                db.commit()
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            evidence_index = json.loads((evidence / "index.json").read_text(encoding="utf-8"))
            evidence_index.setdefault("revisions", {})["catalogIdentityEpoch"] = catalog_json_store.IDENTITY_EPOCH
            (evidence / "index.json").write_text(json.dumps(evidence_index), encoding="utf-8")
            base = root / "base.sqlite"
            shutil.copy2(database, base)
            queue_seed = root / "source-queue.json"
            queue_seed.write_text(json.dumps({
                "schema": scan_queue.SEED_SCHEMA, "queueSeedRevision": "queue-seed-v1-source", "catalogRevision": "cat-json-v1-source",
                "catalogIdentityEpoch": catalog_json_store.IDENTITY_EPOCH, "definitionsRevision": "defs-v1-source",
                "scannerRevision": "scanner-v1-fixture", "scannerBundleSha256": "c" * 64, "ruleSetRevision": "rules-v1-fixture",
                "artifactAnalysisRevision": "artifact-analysis-v1-fixture", "sourceAnalysisRevision": "source-analysis-v1-fixture",
                "sourceObservationRevision": "source-observations-v1-fixture",
                "baselineSecurityRebuild": False, "rescanAfterHours": 168, "counts": {"queued": 1},
                "items": [{
                    "queueKey": f"source-variant-{variant_id}", "workType": "source", "targetFingerprint": "source-target-v2-fixture",
                    "variantId": variant_id, "pluginId": int(variant[1]), "sourceId": int(variant[2]), "internalName": str(variant[3]),
                    "name": str(variant[4]), "sourceName": str(variant[5]), "assemblyVersion": str(variant[6]), "artifactChannel": "stable",
                    "artifactUrl": str(variant[7]), "repositoryUrl": "https://github.com/example/plugin", "sourceRepositoryUrl": "",
                    "catalogRevision": "cat-json-v1-source", "catalogIdentityEpoch": catalog_json_store.IDENTITY_EPOCH,
                    "definitionsRevision": "defs-v1-source", "scannerRevision": "scanner-v1-fixture", "ruleSetRevision": "rules-v1-fixture",
                    "artifactAnalysisRevision": "artifact-analysis-v1-fixture", "sourceAnalysisRevision": "source-analysis-v1-fixture",
                    "reasons": ["source_followup"], "primaryReason": "source_followup", "priority": 925,
                    "currentScanId": 9001, "currentScannedAtUtc": "2026-08-17T00:00:00Z", "currentArtifactSha256": "a" * 64,
                    "enqueuedAtUtc": "2026-08-19T00:00:00Z",
                }],
            }), encoding="utf-8")
            args = SimpleNamespace(
                base_database=base, descriptor=None, current_evidence=evidence, candidate_evidence=root / "candidate", work_dir=root / "work",
                publication_output=None, previous_marketplace_descriptor=None, marketplace_download_url="",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
                source_overrides=common.ROOT / "sources" / "source-overrides.json", max_scans=1, rescan_after_hours=168,
                max_batch_seconds=0, internal_names="", variant_ids="", skip_source=False, osv_timeout=1.0, max_osv_packages=2000,
                github_output=None, skip_marketplace=True, frozen_advisories=None, catalog_revision="cat-json-v1-source",
                definitions_revision="defs-v1-source", scanner_revision="scanner-v1-fixture", scanner_bundle_sha256="c" * 64,
                artifact_analysis_revision="artifact-analysis-v1-fixture", source_analysis_revision="source-analysis-v1-fixture",
                rule_set_revision="rules-v1-fixture", queue_seed=queue_seed,
            )
            source = {
                "available": True, "repository": "https://github.com/example/plugin", "commit": "b" * 40, "branch": "v1.0.0",
                "treeSha256": "d" * 40, "filesScanned": 2, "dependencyIntelligence": sigmascope.empty_dependency_intelligence("source"),
                "scope": {"primaryProject": "src/Plugin/Plugin.csproj"},
                "provenance": {"identityMatched": True, "versionMatched": True, "selectedRefKind": "version-tag", "selectedRef": "v1.0.0"}, "error": "",
            }
            def fake_collect(index_path, output, timeout=20.0, max_packages=2000):
                import collect_public_advisories
                packages = collect_public_advisories.observed_nuget_index(Path(index_path), max_packages)
                document = {"schema": "omega.public-advisories.v1", "generatedAtUtc": "2026-08-19T00:00:00Z", "source": "OSV", "ecosystem": "NuGet",
                            "queriedPackages": len(packages), "matchedPackages": 0, "advisories": []}
                Path(output).write_text(json.dumps(document), encoding="utf-8")
                return document
            with patch("sigmascope.request_bytes", side_effect=AssertionError("source work must not download plugin artifact")), \
                 patch("sigmascope.fetch_source", side_effect=[dict(source), dict(source)]) as fetch, \
                 patch("production_sigmascope_v2_pipeline.collect_public_advisories.collect_from_nuget_index", side_effect=fake_collect):
                result = run_pipeline(args)
            self.assertEqual("source", result["queue"]["selected"]["workType"])
            self.assertEqual(2, fetch.call_count)
            queue_state = json.loads((root / "candidate" / "scanner-queue.json").read_text(encoding="utf-8"))
            self.assertEqual("complete", queue_state["items"][f"source-variant-{variant_id}"]["state"])
            variant_file = next((root / "candidate" / "variants").rglob(f"{variant_id}.json"))
            payload = json.loads(variant_file.read_text(encoding="utf-8"))
            current = payload["current"]
            self.assertEqual("a" * 64, current["artifact_sha256"])
            self.assertTrue(current["source_available"])
            self.assertEqual("source", current["report_json"]["workType"])
            self.assertEqual(70, current["report_json"]["source"]["attribution"]["confidence"])
            cache_descriptor = payload["derivedEvidence"]["sourceAnalysisCache"]
            cache_rows = read_record_dataset(root / "candidate", cache_descriptor)
            self.assertEqual(1, len(cache_rows))
            self.assertTrue(cache_rows[0]["analysisPayload"]["analysisComplete"])
            self.assertEqual("source-analysis-v1-fixture", cache_rows[0]["sourceAnalysisRevision"])

            # Simulate the next 15-minute worker: materialize compact Evidence v2, then
            # resolve the same immutable source revision.  The source body must not be
            # inspected again because the complete source-analysis payload survived transport.
            transported_db = root / "transported-source-cache.sqlite"
            materialized = materialize_current_state(base, root / "candidate", transported_db)
            self.assertGreaterEqual(int(materialized["sourceAnalysisCachesRestored"]), 1)
            with closing(sqlite3.connect(transported_db)) as transported:
                transported.row_factory = sqlite3.Row
                complete_cache = transported.execute(
                    "SELECT status,analysis_payload_json FROM source_analyses WHERE definitions_revision='source-analysis-v1-fixture' AND status='complete' AND source_root_path='src/Plugin'"
                ).fetchone()
                self.assertIsNotNone(complete_cache)
                self.assertEqual("complete", complete_cache["status"])
                self.assertTrue(json.loads(complete_cache["analysis_payload_json"])["analysisComplete"])
                source_row = transported.execute("""
                    SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,v.author,v.assembly_version,
                           v.testing_assembly_version,v.download_link_install,v.download_link_update,v.download_link_testing,v.repo_url,
                           s.name AS source_name,s.url AS source_url,s.source_repo_url
                      FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id JOIN sources s ON s.source_id=v.source_id
                     WHERE v.variant_id=?
                """, (variant_id,)).fetchone()
                def resolve_only(*_args, **kwargs):
                    if kwargs.get("analyze", True):
                        raise AssertionError("transported complete source analysis must not fetch source bodies again")
                    return dict(source)
                with patch("sigmascope.fetch_source", side_effect=resolve_only) as transported_fetch:
                    reused = sigmascope.scan_source_row(
                        source_row, token="", db=transported, source_analysis_revision="source-analysis-v1-fixture"
                    )
                self.assertEqual(1, transported_fetch.call_count)
                self.assertTrue(reused["sourceAnalysisReused"])

            with closing(sqlite3.connect(root / "work" / "omega-security-v2-working.sqlite")) as check_db:
                artifact_dependencies = check_db.execute(
                    "SELECT COUNT(*) FROM plugin_security_dependencies d JOIN plugin_security_current c ON c.scan_id=d.scan_id WHERE c.variant_id=? AND d.origin='artifact'",
                    (variant_id,),
                ).fetchone()[0]
                self.assertGreaterEqual(artifact_dependencies, 1, "source projection must preserve normalized artifact dependency evidence")


    def test_advisory_queue_reprojects_without_artifact_or_source_scan(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-advisory-queue-") as td:
            root = Path(td)
            database, _variant_id, _plugin_id = self.make_catalog_with_security(root)
            evidence = root / "evidence"
            migrate(database, evidence, reset=True)
            evidence_index = json.loads((evidence / "index.json").read_text(encoding="utf-8"))
            evidence_index.setdefault("revisions", {})["catalogIdentityEpoch"] = catalog_json_store.IDENTITY_EPOCH
            evidence_index["revisions"]["advisoryRevision"] = "osv-v1-old"
            (evidence / "index.json").write_text(json.dumps(evidence_index), encoding="utf-8")
            base = root / "base.sqlite"
            shutil.copy2(database, base)

            queue_seed = root / "advisory-queue.json"
            queue_seed.write_text(json.dumps({
                "schema": scan_queue.SEED_SCHEMA,
                "queueSeedRevision": "queue-seed-v2-advisory",
                "catalogRevision": "cat-json-v1-advisory",
                "catalogIdentityEpoch": catalog_json_store.IDENTITY_EPOCH,
                "definitionsRevision": "defs-v1-advisory",
                "scannerRevision": "scanner-v1-fixture",
                "scannerBundleSha256": "d" * 64,
                "ruleSetRevision": "rules-v1-fixture",
                "advisoryRevision": "osv-v1-new",
                "baselineSecurityRebuild": False,
                "counts": {"queued": 1, "advisory_changed": 1},
                "items": [{
                    "queueKey": "advisory-projection",
                    "workType": "advisory",
                    "targetFingerprint": "advisory-target-v1-fixture",
                    "variantId": 0,
                    "pluginId": 0,
                    "sourceId": 0,
                    "internalName": "",
                    "name": "Frozen advisory projection",
                    "sourceName": "",
                    "assemblyVersion": "",
                    "artifactChannel": "",
                    "artifactUrl": "",
                    "repositoryUrl": "",
                    "sourceRepositoryUrl": "",
                    "catalogRevision": "cat-json-v1-advisory",
                    "catalogIdentityEpoch": catalog_json_store.IDENTITY_EPOCH,
                    "definitionsRevision": "defs-v1-advisory",
                    "scannerRevision": "scanner-v1-fixture",
                    "scannerBundleSha256": "d" * 64,
                    "ruleSetRevision": "rules-v1-fixture",
                    "advisoryRevision": "osv-v1-new",
                    "previousAdvisoryRevision": "osv-v1-old",
                    "reasons": ["advisory_changed"],
                    "primaryReason": "advisory_changed",
                    "priority": 800,
                    "currentScanId": 0,
                    "currentScannedAtUtc": "",
                    "currentArtifactSha256": "",
                    "enqueuedAtUtc": "2026-08-19T00:00:00Z",
                }],
            }), encoding="utf-8")

            frozen = root / "osv-advisories.json"
            frozen.write_text(json.dumps({
                "schema": "omega.public-advisories.v1",
                "generatedAtUtc": "2026-08-19T00:00:00Z",
                "source": "OSV",
                "ecosystem": "NuGet",
                "queriedPackages": 0,
                "matchedPackages": 0,
                "queriedPackageVersionPairs": [],
                "advisories": [],
            }), encoding="utf-8")

            args = SimpleNamespace(
                base_database=base, descriptor=None, current_evidence=evidence,
                candidate_evidence=root / "candidate", work_dir=root / "work", publication_output=None,
                previous_marketplace_descriptor=None, marketplace_download_url="",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
                source_overrides=common.ROOT / "sources" / "source-overrides.json",
                max_scans=1, max_batch_seconds=0, internal_names="", variant_ids="", skip_source=False,
                osv_timeout=1.0, max_osv_packages=2000, github_output=None, skip_marketplace=True,
                frozen_advisories=frozen, catalog_revision="cat-json-v1-advisory",
                definitions_revision="defs-v1-advisory", scanner_revision="scanner-v1-fixture",
                scanner_bundle_sha256="d" * 64, rule_set_revision="rules-v1-fixture",
                advisory_revision="osv-v1-new", queue_seed=queue_seed,
            )

            with patch("sigmascope.request_bytes", side_effect=AssertionError("advisory work must not download plugin artifacts")), \
                 patch("sigmascope.fetch_source", side_effect=AssertionError("advisory work must not fetch source")):
                result = run_pipeline(args)

            self.assertEqual("advisory", result["queue"]["selected"]["workType"])
            self.assertEqual(0, result["scan"]["selected"])
            queue_state = json.loads((root / "candidate" / "scanner-queue.json").read_text(encoding="utf-8"))
            self.assertEqual("complete", queue_state["items"]["advisory-projection"]["state"])
            root_index = json.loads((root / "candidate" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual("osv-v1-new", root_index["revisions"]["advisoryRevision"])
            self.assertTrue(result["publicationRequired"])


    def test_first_baseline_worker_establishes_new_identity_epoch_and_discards_legacy_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-first-baseline-worker-") as td:
            root = Path(td)
            database, variant_id, _plugin_id = self.make_catalog_with_security(root)
            legacy_evidence = root / "legacy-evidence"
            migrate(database, legacy_evidence, reset=True)
            legacy_index = json.loads((legacy_evidence / "index.json").read_text(encoding="utf-8"))
            self.assertFalse((legacy_index.get("revisions") or {}).get("catalogIdentityEpoch"))
            self.assertEqual(1, int((legacy_index.get("counts") or {}).get("currentVariants") or 0))

            # Reproduce the live pre-epoch branch condition: transport hashes are
            # internally consistent, but the legacy plugins-index summary no longer
            # matches the canonical variant payload. A clean epoch reset must be able
            # to discard this state instead of trying to validate/inherit it.
            plugins_entry = legacy_index["indexes"]["plugins"]
            plugins_path = legacy_evidence / str(plugins_entry["path"])
            plugins_doc = json.loads(plugins_path.read_text(encoding="utf-8"))
            self.assertTrue(plugins_doc["currentVariants"])
            plugins_doc["currentVariants"][0]["summary"] = {"status": "stale-legacy-summary"}
            plugins_bytes = (json.dumps(plugins_doc, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
            plugins_path.write_bytes(plugins_bytes)
            plugins_entry["bytes"] = len(plugins_bytes)
            plugins_entry["sha256"] = hashlib.sha256(plugins_bytes).hexdigest()
            (legacy_evidence / "index.json").write_text(
                json.dumps(legacy_index, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            stale_validation = validate_snapshot(legacy_evidence, require_no_orphans=False)
            self.assertFalse(stale_validation["ok"])
            self.assertTrue(
                any("plugins index summary mismatch" in error for error in stale_validation.get("errors") or []),
                stale_validation,
            )

            # The clean canonical epoch deliberately starts from catalog identity only.
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
                "queueSeedRevision": "queue-seed-v1-baseline-fixture",
                "catalogRevision": "cat-json-v1-baseline-fixture",
                "catalogIdentityEpoch": catalog_json_store.IDENTITY_EPOCH,
                "definitionsRevision": "defs-v1-baseline-fixture",
                "scannerRevision": "scanner-v1-baseline-fixture",
                "scannerBundleSha256": "a" * 64,
                "ruleSetRevision": "rules-v1-baseline-fixture",
                "baselineSecurityRebuild": True,
                "previousEvidenceIdentityEpoch": "",
                "rescanAfterHours": 168,
                "counts": {"queued": 1},
                "items": [{
                    "queueKey": f"variant-{variant_id}",
                    "targetFingerprint": "scan-target-v1-baseline-fixture",
                    "variantId": variant_id,
                    "pluginId": int(variant[1]),
                    "sourceId": int(variant[2]),
                    "internalName": str(variant[3]),
                    "name": str(variant[4]),
                    "sourceName": str(variant[5]),
                    "assemblyVersion": str(variant[6]),
                    "artifactChannel": "stable",
                    "artifactUrl": str(variant[7]),
                    "catalogRevision": "cat-json-v1-baseline-fixture",
                    "catalogIdentityEpoch": catalog_json_store.IDENTITY_EPOCH,
                    "definitionsRevision": "defs-v1-baseline-fixture",
                    "ruleSetRevision": "rules-v1-baseline-fixture",
                    "reasons": ["baseline_scan"],
                    "primaryReason": "baseline_scan",
                    "priority": 950,
                    "currentScanId": 0,
                    "currentScannedAtUtc": "",
                    "currentArtifactSha256": "",
                    "enqueuedAtUtc": "2026-08-19T00:00:00Z",
                }],
            }), encoding="utf-8")

            artifact_buffer = io.BytesIO()
            with zipfile.ZipFile(artifact_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("fixture.txt", "new identity epoch baseline")
            artifact = artifact_buffer.getvalue()
            args = SimpleNamespace(
                base_database=base, descriptor=None, current_evidence=legacy_evidence,
                candidate_evidence=root / "candidate", work_dir=root / "work", publication_output=None,
                previous_marketplace_descriptor=None, marketplace_download_url="",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
                source_overrides=common.ROOT / "sources" / "source-overrides.json", max_scans=1,
                rescan_after_hours=168, max_batch_seconds=0, internal_names="", variant_ids="", skip_source=True,
                osv_timeout=1.0, max_osv_packages=2000, github_output=None, skip_marketplace=True,
                frozen_advisories=None, catalog_revision="cat-json-v1-baseline-fixture",
                definitions_revision="defs-v1-baseline-fixture", scanner_revision="scanner-v1-baseline-fixture",
                scanner_bundle_sha256="a" * 64, rule_set_revision="rules-v1-baseline-fixture", queue_seed=queue_seed,
            )

            def fake_collect(index_path, output, timeout=20.0, max_packages=2000):
                import collect_public_advisories
                packages = collect_public_advisories.observed_nuget_index(Path(index_path), max_packages)
                document = {
                    "schema": "omega.public-advisories.v1", "generatedAtUtc": "2026-08-19T00:00:00Z",
                    "source": "OSV", "ecosystem": "NuGet", "queriedPackages": len(packages),
                    "matchedPackages": 0, "advisories": [],
                }
                Path(output).write_text(json.dumps(document), encoding="utf-8")
                return document

            with patch("sigmascope.request_bytes", return_value=(artifact, str(variant[7]))), \
                 patch("production_sigmascope_v2_pipeline.collect_public_advisories.collect_from_nuget_index", side_effect=fake_collect):
                result = run_pipeline(args)

            self.assertTrue(result["baseline"]["ok"])
            self.assertTrue(result["baseline"]["discarded"])
            self.assertFalse(result["baseline"]["validated"])
            self.assertEqual("catalog_identity_epoch_changed", result["baseline"]["reason"])
            self.assertTrue(result["materialized"]["baselineSecurityRebuild"])
            self.assertFalse(result["materialized"]["evidenceInherited"])
            self.assertEqual(0, result["materialized"]["currentVariantsMaterialized"])
            self.assertEqual("baseline_scan", result["queue"]["selected"]["primaryReason"])
            self.assertEqual([variant_id], result["successfulVariantIds"])

            root_index = json.loads((root / "candidate" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(catalog_json_store.IDENTITY_EPOCH, root_index["revisions"]["catalogIdentityEpoch"])
            self.assertTrue(root_index["source"]["scan"]["baselineSecurityRebuild"])
            self.assertEqual(1, int(root_index["counts"]["currentVariants"]))

            variant_files = list((root / "candidate" / "variants").rglob("*.json"))
            self.assertEqual(1, len(variant_files), "legacy variant descriptors must not survive the epoch reset")
            payload = json.loads(variant_files[0].read_text(encoding="utf-8"))
            provenance = payload["current"]["report_json"]["scanProvenance"]
            self.assertEqual(catalog_json_store.IDENTITY_EPOCH, provenance["catalogIdentityEpoch"])
            self.assertTrue(provenance["baselineSecurityRebuild"])
            self.assertEqual("baseline_scan", provenance["primaryReason"])

            # The same immutable daily seed still says this was a baseline generation.
            # That flag is provenance, not a command to erase the newly published
            # same-epoch evidence every 15 minutes. The next worker must inherit the
            # first scan and completed queue state rather than lease it again.
            second_args = SimpleNamespace(**vars(args))
            second_args.current_evidence = root / "candidate"
            second_args.candidate_evidence = root / "candidate-2"
            second_args.work_dir = root / "work-2"
            with patch("production_sigmascope_v2_pipeline.collect_public_advisories.collect_from_nuget_index", side_effect=fake_collect):
                second = run_pipeline(second_args)

            self.assertFalse(second["materialized"]["baselineSecurityRebuild"])
            self.assertTrue(second["materialized"]["queueSeedRequestedBaseline"])
            self.assertTrue(second["materialized"]["evidenceInherited"])
            self.assertEqual(1, second["materialized"]["currentVariantsMaterialized"])
            self.assertEqual({}, second["queue"]["selected"], "completed baseline target must not be leased again")
            self.assertEqual(1, int((second["queue"]["summary"].get("states") or {}).get("complete") or 0))

            # Conversely, same-epoch evidence is authoritative and remains fail-closed.
            # Only an incompatible epoch is eligible for the intentional discard path.
            invalid_same_epoch = root / "invalid-same-epoch"
            shutil.copytree(root / "candidate-2", invalid_same_epoch)
            invalid_index = json.loads((invalid_same_epoch / "index.json").read_text(encoding="utf-8"))
            invalid_plugins_entry = invalid_index["indexes"]["plugins"]
            invalid_plugins_path = invalid_same_epoch / str(invalid_plugins_entry["path"])
            invalid_plugins_doc = json.loads(invalid_plugins_path.read_text(encoding="utf-8"))
            invalid_plugins_doc["currentVariants"][0]["summary"] = {"status": "same-epoch-corruption"}
            invalid_plugins_bytes = (json.dumps(invalid_plugins_doc, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
            invalid_plugins_path.write_bytes(invalid_plugins_bytes)
            invalid_plugins_entry["bytes"] = len(invalid_plugins_bytes)
            invalid_plugins_entry["sha256"] = hashlib.sha256(invalid_plugins_bytes).hexdigest()
            (invalid_same_epoch / "index.json").write_text(
                json.dumps(invalid_index, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            invalid_args = SimpleNamespace(**vars(args))
            invalid_args.current_evidence = invalid_same_epoch
            invalid_args.candidate_evidence = root / "candidate-invalid"
            invalid_args.work_dir = root / "work-invalid"
            with self.assertRaisesRegex(RuntimeError, "published Security Evidence v2 baseline failed intrinsic validation"):
                run_pipeline(invalid_args)

    def test_osv_gate_rejects_candidate_when_exact_nuget_versions_are_not_queried(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-osv-gate-") as td:
            root = Path(td)
            database, _variant_id, _plugin_id = self.make_catalog_with_security(root)
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
                db.commit()
            args = SimpleNamespace(
                base_database=base, descriptor=root / "built" / "catalog.json", current_evidence=evidence,
                candidate_evidence=root / "candidate", work_dir=root / "work", publication_output=root / "publication",
                previous_marketplace_descriptor=None,
                marketplace_download_url="https://example.invalid/catalog-latest/omega-marketplace.sqlite.zip",
                evidence_index_url="https://example.invalid/security-evidence-v2/index.json",
                source_overrides=common.ROOT / "sources" / "source-overrides.json", max_scans=0,
                rescan_after_hours=168, max_batch_seconds=0, internal_names="", skip_source=True,
                osv_timeout=1.0, max_osv_packages=2000, github_output=None,
            )
            def incomplete_collect(index_path, output, timeout=20.0, max_packages=2000):
                document = {
                    "schema": "omega.public-advisories.v1", "generatedAtUtc": "2026-08-17T00:00:00Z",
                    "source": "OSV", "ecosystem": "NuGet", "queriedPackages": 0, "matchedPackages": 0, "advisories": [],
                }
                Path(output).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                return document
            with patch("production_sigmascope_v2_pipeline.collect_public_advisories.collect_from_nuget_index", side_effect=incomplete_collect):
                with self.assertRaisesRegex(RuntimeError, "OSV publication gate failed"):
                    run_pipeline(args)
            self.assertFalse((root / "candidate" / "index.json").exists())

    def test_semantic_security_revision_ignores_transport_scan_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-revision-") as td:
            root = Path(td)
            database, variant_id, plugin_id = self.make_catalog_with_security(root)
            with closing(sqlite3.connect(database)) as db:
                db.row_factory = sqlite3.Row
                before = _semantic_security_revision(db)
                old_scan = dict(db.execute("SELECT * FROM plugin_security_scans WHERE scan_id=9001").fetchone())
                old_scan["scan_id"] = 9003
                columns = list(old_scan)
                db.execute(
                    f"INSERT INTO plugin_security_scans({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
                    tuple(old_scan[c] for c in columns),
                )
                for table in ("plugin_security_findings", "plugin_security_dependencies"):
                    rows = db.execute(f"SELECT * FROM {table} WHERE scan_id=9001").fetchall()
                    info = db.execute(f"PRAGMA table_info({table})").fetchall()
                    pk = next(str(row[1]) for row in info if int(row[5]) == 1)
                    for source in rows:
                        row = dict(source)
                        row.pop(pk, None)
                        row["scan_id"] = 9003
                        cols = list(row)
                        db.execute(
                            f"INSERT INTO {table}({','.join(cols)}) VALUES({','.join('?' for _ in cols)})",
                            tuple(row[c] for c in cols),
                        )
                db.execute("UPDATE plugin_security_current SET scan_id=9003 WHERE variant_id=?", (variant_id,))
                db.commit()
                after = _semantic_security_revision(db)
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()

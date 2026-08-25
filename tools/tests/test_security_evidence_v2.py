from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

from migrate_security_evidence_v2 import _resolve_source_database, migrate
from publish_security_evidence_v2 import preflight, validate_audit_report, validate_snapshot_report
from security_evidence_download import DownloadedEvidence, parse_sidecar, safe_extract_sqlite
from security_evidence_v2 import (
    MAX_PUBLISH_FILE_BYTES, compact_report_for_transport, read_record_dataset, sha256_file, validate_snapshot,
    variant_index_summary, write_record_dataset,
)
from validate_security_evidence_v2 import infer_database_from_migration_state, validate
import definition_packs
from production_sigmascope_v2_pipeline import materialize_definition_provenance_index
from evidence_contract_reader import read_workbench_relationship_index


class SecurityEvidenceV2Tests(unittest.TestCase):
    def make_database(self, path: Path) -> Path:
        db = sqlite3.connect(path)
        db.executescript("""
        CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT INTO catalog_meta VALUES('security_revision','sec-test');
        INSERT INTO catalog_meta VALUES('evidence_revision','ev-test');
        INSERT INTO catalog_meta VALUES('catalog_revision','cat-test');
        INSERT INTO catalog_meta VALUES('base_revision','base-test');
        INSERT INTO catalog_meta VALUES('security_scanner_version','2.4.0');

        CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY,internal_name TEXT,name TEXT,author TEXT);
        INSERT INTO plugins VALUES(1,'FixturePlugin','Fixture Plugin','Tester');

        CREATE TABLE sources(source_id INTEGER PRIMARY KEY,name TEXT,url TEXT);
        INSERT INTO sources VALUES(1,'Mirror A','https://example.invalid/a.json');
        INSERT INTO sources VALUES(2,'Mirror B','https://example.invalid/b.json');

        CREATE TABLE plugin_variants(variant_id INTEGER PRIMARY KEY,plugin_id INTEGER,source_id INTEGER,assembly_version TEXT);
        INSERT INTO plugin_variants VALUES(1,1,1,'1.0.0');
        INSERT INTO plugin_variants VALUES(2,1,2,'1.0.0');

        CREATE TABLE plugin_security_scans(
          scan_id INTEGER PRIMARY KEY,plugin_id INTEGER,variant_id INTEGER,source_id INTEGER,
          artifact_sha256 TEXT,scanner_version TEXT,status TEXT,highest_severity TEXT,
          informational_count INTEGER,caution_count INTEGER,high_count INTEGER,critical_count INTEGER,
          scanned_at_utc TEXT,report_json TEXT
        );
        INSERT INTO plugin_security_scans VALUES(10,1,1,1,
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','2.4.0','complete','high',0,0,1,0,
          '2026-08-17T00:00:00Z','{"fixture":true}');
        INSERT INTO plugin_security_scans VALUES(11,1,2,2,
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','2.4.0','complete','high',0,0,1,0,
          '2026-08-17T00:01:00Z','{"fixture":true}');

        CREATE TABLE plugin_security_current(
          variant_id INTEGER PRIMARY KEY,scan_id INTEGER,status TEXT,artifact_sha256 TEXT,scanner_version TEXT,
          highest_severity TEXT,informational_count INTEGER,caution_count INTEGER,high_count INTEGER,critical_count INTEGER
        );
        INSERT INTO plugin_security_current VALUES(1,10,'complete','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','2.4.0','high',0,0,1,0);
        INSERT INTO plugin_security_current VALUES(2,11,'complete','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','2.4.0','high',0,0,1,0);

        CREATE TABLE plugin_security_findings(
          finding_id INTEGER PRIMARY KEY,scan_id INTEGER,rule_id TEXT,severity TEXT,category TEXT,title TEXT,description TEXT,evidence_json TEXT
        );
        INSERT INTO plugin_security_findings VALUES(1,10,'network.http','high','network','Network','Fixture','["HttpClient"]');
        INSERT INTO plugin_security_findings VALUES(2,11,'network.http','high','network','Network','Fixture','["HttpClient"]');

        CREATE TABLE plugin_security_dependencies(
          dependency_id INTEGER PRIMARY KEY,scan_id INTEGER,origin TEXT,kind TEXT,name TEXT,version TEXT,
          version_requirement TEXT,resolved_version TEXT,path TEXT,status TEXT,requirement TEXT,evidence_json TEXT,
          relationship TEXT,relationship_confidence TEXT,relationship_evidence_json TEXT
        );
        INSERT INTO plugin_security_dependencies VALUES(100,10,'artifact','nuget-lock','Newtonsoft.Json','13.0.3','[13.0.3,)','13.0.3','packages.lock.json','known','required','[]','','','[]');
        INSERT INTO plugin_security_dependencies VALUES(101,11,'artifact','nuget-lock','Newtonsoft.Json','13.0.3','[13.0.3,)','13.0.3','packages.lock.json','known','required','[]','','','[]');
        """)
        db.commit()
        db.close()
        return path

    def test_migration_deduplicates_identical_mirror_evidence_and_validates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            index = migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            self.assertEqual(index["counts"]["currentVariants"], 2)
            self.assertEqual(index["counts"]["analyses"], 1)
            self.assertEqual(index["counts"]["artifactGroups"], 1)
            self.assertEqual(index["counts"]["nugetPackageVersionPairs"], 1)
            first = json.loads((output / "variants" / "0000" / "1.json").read_text(encoding="utf-8"))
            second = json.loads((output / "variants" / "0000" / "2.json").read_text(encoding="utf-8"))
            self.assertEqual(first["analysis"]["analysisId"], second["analysis"]["analysisId"])
            plugins_index = json.loads((output / "indexes" / "plugins.json").read_text(encoding="utf-8"))
            first_index = next(row for row in plugins_index["currentVariants"] if row["variantId"] == 1)
            self.assertEqual(64, len(first_index["variantSha256"]))
            self.assertEqual("FixturePlugin", first_index["summary"]["canonical_name"])
            self.assertEqual("high", first_index["summary"]["highest_severity"])
            report = validate(database, output)
            self.assertTrue(report["ok"], report)
            publication = preflight(output)
            self.assertGreater(publication["files"], 0)
            self.assertEqual(publication["evidenceRevision"], "ev-test")

    def test_variant_index_summary_preserves_pre_lifecycle_contract_shape(self) -> None:
        payload = {
            "variantId": 107,
            "pluginId": 1,
            "sourceId": 1,
            "plugin": {"internal_name": "FixturePlugin", "canonical_name": "Fixture Plugin"},
            "variant": {"name": "Fixture Plugin", "author": "Tester", "assembly_version": "1.0.0"},
            "source": {"name": "Fixture", "url": "https://example.invalid/pluginmaster.json"},
            "current": {"scan_id": 10, "status": "complete", "highest_severity": "none"},
        }
        legacy = variant_index_summary(payload, lifecycle_contract_version=0)
        self.assertNotIn("lifecycle_state", legacy)
        self.assertNotIn("lifecycle_reason", legacy)
        self.assertNotIn("lifecycle_terminal", legacy)
        self.assertEqual(legacy, variant_index_summary(payload))

        payload["lifecycle"] = {
            "schema": "omega.security-evidence.variant-lifecycle.v1",
            "state": "active",
            "reason": "",
            "terminal": False,
            "rescanEligible": True,
        }
        modern = variant_index_summary(payload, lifecycle_contract_version=1)
        self.assertEqual("active", modern["lifecycle_state"])
        self.assertFalse(modern["lifecycle_terminal"])
        self.assertEqual(modern, variant_index_summary(payload))

    def test_oversized_legacy_report_is_compacted_out_of_variant_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            huge_report = {
                "schema": "omega.plugin-security.report.v1",
                "opaqueLegacyEvidence": "x" * (18 * 1024 * 1024),
                "source": {
                    "repository": "https://example.invalid/source",
                    "commit": "abc123",
                    "error": "temporary source lookup failure",
                    "candidates": ["https://github.com/example/Plugin"],
                    "provenance": {
                        "schema": "omega.plugin-source-provenance.v1",
                        "confidence": "very-high",
                        "selectedRef": "1.2.0.2",
                        "identityMatched": True,
                        "versionMatched": True,
                        "artifactOriginMatched": True,
                    },
                    "dependencyIntelligence": {"fingerprints": {"relevantSourceSha256": "b" * 64}},
                },
                "highestSeverity": "caution",
                "counts": {"informational": 1, "caution": 2, "high": 0, "critical": 0},
                "capabilities": ["Network access", "Filesystem access"],
                "automation": {"level": "ui", "capabilities": [{"id": "fixture", "label": "Fixture"}]},
                "dependencyIntelligence": {
                    "networkEndpoints": [
                        {
                            "url": "https://api.example.invalid/v1/status",
                            "host": "api.example.invalid",
                            "origin": "artifact",
                            "classification": "unrecognised-host",
                            "purpose": "unrecognised public host",
                            "severity": "caution",
                            "reason": "forensic detail that should stay normalized elsewhere",
                            "evidence": ["fixture"],
                        }
                    ]
                },
            }
            encoded = json.dumps(huge_report, separators=(",", ":"))
            with closing(sqlite3.connect(database)) as db:
                db.execute("ALTER TABLE plugin_security_current ADD COLUMN report_json TEXT NOT NULL DEFAULT '{}'")
                db.execute("UPDATE plugin_security_scans SET highest_severity='none',informational_count=0,caution_count=0,high_count=0,critical_count=0,report_json=? WHERE scan_id=10", (encoded,))
                db.execute("UPDATE plugin_security_current SET highest_severity='none',informational_count=0,caution_count=0,high_count=0,critical_count=0,report_json=? WHERE variant_id=1", (encoded,))
                db.commit()

            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            variant_path = output / "variants" / "0000" / "1.json"
            self.assertLess(variant_path.stat().st_size, 1024 * 1024)
            text = variant_path.read_text(encoding="utf-8")
            self.assertNotIn("opaqueLegacyEvidence", text)
            payload = json.loads(text)
            for field in ("scan", "current"):
                report = payload[field]["report_json"]
                self.assertEqual(report["schema"], "omega.security-evidence.scan-summary.v2")
                self.assertEqual(
                    report["source"]["dependencyIntelligence"]["fingerprints"]["relevantSourceSha256"],
                    "b" * 64,
                )
                self.assertEqual(report["source"]["error"], "temporary source lookup failure")
                self.assertEqual(report["source"]["candidates"], ["https://github.com/example/Plugin"])
                self.assertEqual(report["source"]["provenance"]["confidence"], "very-high")
                self.assertTrue(report["source"]["provenance"]["versionMatched"])
                self.assertEqual(report["automation"]["level"], "ui")
                self.assertEqual(report["highestSeverity"], "caution")
                self.assertEqual(report["counts"], {"informational": 1, "caution": 2, "high": 0, "critical": 0})
                self.assertEqual(report["capabilities"], ["Network access", "Filesystem access"])
                self.assertEqual(
                    report["intelligence"]["networkEndpoints"],
                    [{
                        "url": "https://api.example.invalid/v1/status",
                        "host": "api.example.invalid",
                        "origin": "artifact",
                        "classification": "unrecognised-host",
                        "purpose": "unrecognised public host",
                    }],
                )
            report = validate(database, output)
            self.assertTrue(report["ok"], report)
            intrinsic = validate_snapshot(output)
            self.assertTrue(intrinsic["ok"], intrinsic)


    def test_secondary_security_v3_transport_keeps_yara_member_attribution_and_review_provenance(self) -> None:
        artifact_sha = "a" * 64
        target_sha = "b" * 64
        row = {
            "artifact_sha256": artifact_sha,
            "report_json": {
                "artifactSha256": artifact_sha,
                "secondarySecurityContractVersion": 3,
                "secondarySecurity": {
                    "schema": "omega.sigmascope.secondary-security.v1",
                    "artifactSha256": artifact_sha,
                    "semantics": "supplemental-evidence-only",
                    "matchCount": 1,
                    "engines": [{
                        "schema": "omega.sigmascope.secondary-engine-result.v1",
                        "engine": "yara",
                        "status": "complete",
                        "available": True,
                        "enabled": True,
                        "revision": "secondary-v1-fixture",
                        "version": "YARA 4.test",
                        "policyRevision": "policy-fixture",
                        "scanScope": {
                            "schema": "omega.sigmascope.yara-scan-scope.v1",
                            "artifactContainerScanned": True,
                            "archiveDetected": True,
                            "archiveMemberCandidates": 1,
                            "archiveMembersScanned": 1,
                            "archiveMembersSkipped": 0,
                            "archiveMemberBytesScanned": 123,
                            "targetCount": 2,
                            "truncated": False,
                            "skipReasons": {},
                        },
                        "matches": [{
                            "kind": "rule",
                            "value": "Omega_Process_Injection_Classic member-0001.dll",
                            "rule": "Omega_Process_Injection_Classic",
                            "provenance": {"kind": "first-party", "source": "omega-core-execution.yar"},
                            "license": "LicenseRef-Omega-First-Party",
                            "reviewedAtUtc": "2026-08-20T14:00:00Z",
                            "reviewer": "Omega security-services maintainers",
                            "reviewedRuleSha256": "c" * 64,
                            "ruleClass": "compound-abuse",
                            "confidence": "high",
                            "falsePositiveExpectation": "low",
                            "scope": "fixture",
                            "target": {"kind": "archive-member", "path": "Plugin.dll", "sha256": target_sha, "bytes": 123},
                        }],
                    }],
                },
            },
        }
        compact = compact_report_for_transport(row)
        secondary = compact["secondarySecurity"]
        self.assertEqual(3, compact["secondarySecurityContractVersion"])
        engine = secondary["engines"][0]
        self.assertEqual(2, engine["scanScope"]["targetCount"])
        match = engine["matches"][0]
        self.assertEqual("Plugin.dll", match["target"]["path"])
        self.assertEqual(target_sha, match["target"]["sha256"])
        self.assertEqual("compound-abuse", match["ruleClass"])
        self.assertEqual("high", match["confidence"])
        self.assertEqual("c" * 64, match["reviewedRuleSha256"])

    def test_migration_promotes_report_only_observations_into_first_class_datasets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-v2-observation-export-") as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            report = {
                "artifactIdentity": {"sha256": "a" * 64, "byteCount": 1234},
                "manifestObservation": {"internalName": "FixturePlugin", "assemblyVersion": "1.0.0"},
                "package": {
                    "binaryClassifications": [{
                        "path": "FixturePlugin.dll", "format": "pe", "role": "plugin-assembly", "managed": True,
                    }],
                },
                "dependencyIntelligence": {
                    "nativeImports": [{
                        "binaryPath": "FixturePlugin.dll", "library": "kernel32.dll", "entryPoint": "CreateFileW",
                    }],
                    "networkEndpoints": [{
                        "host": "api.example.invalid", "origin": "artifact", "classification": "unrecognised-host",
                        "concreteDestinationEvidence": True,
                    }],
                    "staticPatternMatches": [{
                        "origin": "artifact", "pattern": "Process.Start",
                        "evidenceLabel": "metadata:FixturePlugin.dll",
                        "evidence": ["metadata:FixturePlugin.dll: Process.Start"],
                    }],
                },
                "source": {
                    "developerProfile": {
                        "schema": "omega.plugin-profile-observation.v1", "status": "valid",
                        "profile": {"schema": "omega.plugin-profile.v1", "capabilities": []},
                    },
                    "attribution": {"confidence": 70, "coverageLabel": "version-correlated"},
                    "provenance": {"repository": "https://github.com/example/fixture", "selectedRef": "1.0.0"},
                    "dependencyIntelligence": {
                        "sourceFiles": [{"path": "FixturePlugin/Plugin.cs", "sha256": "b" * 64}],
                        "sourceBuildIntelligence": {
                            "schema": "omega.sigmascope.source-build-intelligence.v1", "contractVersion": 1,
                            "projects": [{"origin": "source", "path": "FixturePlugin/FixturePlugin.csproj", "role": "primary", "sdk": "Dalamud.NET.Sdk/13.0.0", "targetFrameworks": ["net10.0-windows"], "runtimeIdentifiers": [], "packageReferenceCount": 1, "projectReferenceCount": 0, "importCount": 0, "conditionalItemCount": 0}],
                            "edges": [],
                            "inputs": [{"origin": "source", "path": "FixturePlugin/FixturePlugin.csproj", "kind": "project", "role": "primary", "sha256": "c" * 64, "bytes": 123}],
                            "environment": [{"origin": "source", "path": "global.json", "kind": "dotnet-sdk", "sdkVersion": "10.0.100", "rollForward": "latestPatch", "packageSources": []}],
                            "dependencies": [{"origin": "source", "sourceKind": "msbuild", "path": "FixturePlugin/FixturePlugin.csproj", "projectPath": "FixturePlugin/FixturePlugin.csproj", "kind": "nuget", "name": "DalamudPackager", "versionExpression": "13.0.0", "condition": "", "privateAssets": "all", "includeAssets": "", "excludeAssets": "", "aliases": "", "direct": True, "transitive": False}],
                            "releaseWorkflows": [{"origin": "source", "path": ".github/workflows/release.yml", "name": "Release", "triggers": ["push"], "jobs": ["build"], "runners": ["ubuntu-latest"], "actions": ["actions/upload-artifact@v4"], "dotnetVerbs": ["publish"], "dotnetTargets": ["FixturePlugin/FixturePlugin.csproj"], "uploadsArtifacts": True, "downloadsArtifacts": False, "publishesRelease": False, "truncated": False, "sha256": "d" * 64, "bytes": 100, "identityMatched": True}],
                        },
                    },
                },
                "secondarySecurity": {"schema": "omega.sigmascope.secondary-security.v3", "engines": []},
            }
            with closing(sqlite3.connect(database)) as db:
                db.execute(
                    "UPDATE plugin_security_scans SET report_json=? WHERE scan_id=10",
                    (json.dumps(report, sort_keys=True),),
                )
                db.commit()

            output = root / "v2"
            index = migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            self.assertTrue(index["revisions"]["observationContractRevision"].startswith("observations-v1-"))
            self.assertTrue(index["revisions"]["projectionContractRevision"].startswith("projection-contract-v1-"))
            variant = json.loads((output / "variants" / "0000" / "1.json").read_text(encoding="utf-8"))
            manifest = json.loads((output / variant["analysis"]["path"] / "manifest.json").read_text(encoding="utf-8"))
            datasets = manifest["datasets"]
            for name in (
                "nativeImports", "networkEndpoints", "staticPatternMatches", "sourceFiles",
                "sourceBuildProjects", "sourceBuildEdges", "sourceBuildInputs", "sourceBuildEnvironment",
                "sourceDependencyDeclarations", "sourceReleaseWorkflows", "binaryClassifications",
                "developerProfile", "sourceAttribution", "sourceProvenance", "secondarySecurity",
                "artifactIdentity", "manifestObservation",
            ):
                self.assertIn(name, datasets)
                self.assertEqual("retained", manifest["observationContract"]["collections"][datasets[name]["collection"]]["completeness"])
            self.assertEqual("omega.sigmascope.observation-contract.v1", manifest["observationContract"]["schema"])
            self.assertFalse(variant["observations"]["legacyCompatibility"])
            self.assertIn("networkEndpoints", variant["observations"]["collections"])
            self.assertEqual("retained", variant["observations"]["collections"]["networkEndpoints"]["completeness"])
            validation = validate_snapshot(output)
            self.assertTrue(validation["ok"], validation)

    def test_resume_reuses_completed_variant_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            first_mtime = (output / "variants" / "0000" / "1.json").stat().st_mtime_ns
            migrate(database, output, resume=True, chunk_bytes=1024 * 1024)
            self.assertEqual(first_mtime, (output / "variants" / "0000" / "1.json").stat().st_mtime_ns)
            self.assertTrue(validate(database, output)["ok"])

    def test_parity_validator_detects_semantic_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            variant = output / "variants" / "0000" / "1.json"
            payload = json.loads(variant.read_text(encoding="utf-8"))
            payload["current"]["highest_severity"] = "none"
            variant.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            report = validate(database, output)
            self.assertFalse(report["ok"])
            self.assertTrue(any("variant 1 current" in item for item in report["errors"]))


    def test_filtered_migration_exports_only_selected_current_variants(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "subset"
            index = migrate(database, output, reset=True, chunk_bytes=1024 * 1024, variant_ids={1})
            self.assertEqual(index["migrationMode"], "incremental-subset")
            self.assertEqual(index["counts"]["currentVariants"], 1)
            self.assertTrue((output / "variants" / "0000" / "1.json").is_file())
            self.assertFalse((output / "variants" / "0000" / "2.json").exists())

    def test_intrinsic_snapshot_validator_verifies_hashes_and_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            report = validate_snapshot(output)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["checkedVariants"], 2)
            self.assertEqual(report["checkedAnalyses"], 1)
            report_path = output / "validation-report.json"
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            accepted = validate_snapshot_report(output, report_path)
            self.assertEqual(accepted["indexSha256"], sha256_file(output / "index.json"))

            finding = next((output / "artifacts").rglob("findings.json"))
            finding.write_text("[]\n", encoding="utf-8")
            broken = validate_snapshot(output)
            self.assertFalse(broken["ok"])
            self.assertTrue(any("sha256" in error or "record" in error for error in broken["errors"]))



    def test_sharded_workbench_relationship_index_is_readable_and_shard_tamper_is_rejected(self) -> None:
        import hashlib
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024)

            relationship = read_workbench_relationship_index(output)
            self.assertEqual("omega.security-evidence.workbench-relationships.v2", relationship["schema"])
            self.assertTrue(relationship["readOnly"])
            self.assertFalse(relationship["policyInput"])

            index = json.loads((output / "index.json").read_text(encoding="utf-8"))
            manifest_entry = index["indexes"]["workbenchRelationships"]
            manifest_path = output / manifest_entry["path"]
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            shard = next(
                (file_info for descriptor in manifest["datasets"].values() for file_info in descriptor.get("files") or []
                 if str(file_info.get("encoding") or "") == "jsonl+gzip"),
                None,
            )
            if shard is None:
                # Empty test relations legitimately use a tiny inline JSON dataset; force
                # a manifest-level digest failure instead so the v2 integrity path is still covered.
                manifest["datasets"]["endpoints"]["recordDigest"] = "0" * 64
                manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
                data = manifest_path.read_bytes()
                manifest_entry["sha256"] = hashlib.sha256(data).hexdigest()
                manifest_entry["bytes"] = len(data)
                (output / "index.json").write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            else:
                shard_path = output / shard["path"]
                shard_path.write_bytes(shard_path.read_bytes() + b"tamper")
            report = validate_snapshot(output)
            self.assertFalse(report["ok"], report)
            self.assertTrue(any("workbenchRelationships" in error for error in report["errors"]), report)

    def test_intrinsic_validator_rejects_workbench_relationship_write_authority(self) -> None:
        import hashlib
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            index_path = output / "index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            entry = index["indexes"]["workbenchRelationships"]
            relationship_path = output / entry["path"]
            payload = json.loads(relationship_path.read_text(encoding="utf-8"))
            payload["readOnly"] = False
            relationship_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            data = relationship_path.read_bytes()
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            entry["bytes"] = len(data)
            index_path.write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            report = validate_snapshot(output)
            self.assertFalse(report["ok"])
            self.assertTrue(any("workbenchRelationships index is not explicitly read-only" in error for error in report["errors"]), report)

    def test_intrinsic_validator_rejects_definition_provenance_policy_authority(self) -> None:
        import hashlib
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            definitions = root / "definitions"
            definitions.mkdir(parents=True, exist_ok=True)
            descriptor = definition_packs.freeze_pack_root(ROOT / "security-definitions" / "packs", definitions, include_local=False)
            index_path = output / "index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            revision = str((index.get("source") or {}).get("definitionsRevision") or "")
            (definitions / "index.json").write_text(json.dumps({
                "schema": "omega.definitions.v1", "definitionsRevision": revision,
                "ruleSetRevision": "legacy-test", "srlDefinitionPacks": descriptor,
            }, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            provenance_entry = materialize_definition_provenance_index(output, definitions)
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index.setdefault("indexes", {})["definitionProvenance"] = provenance_entry
            index_path.write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            self.assertTrue(validate_snapshot(output)["ok"], validate_snapshot(output))

            provenance_path = output / provenance_entry["path"]
            payload = json.loads(provenance_path.read_text(encoding="utf-8"))
            payload["policyInput"] = True
            provenance_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            data = provenance_path.read_bytes()
            index = json.loads(index_path.read_text(encoding="utf-8"))
            entry = index["indexes"]["definitionProvenance"]
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            entry["bytes"] = len(data)
            index_path.write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            report = validate_snapshot(output)
            self.assertFalse(report["ok"])
            self.assertTrue(any("definition provenance incorrectly declares itself a policy input" in error for error in report["errors"]), report)

    def test_intrinsic_validator_accepts_failed_current_variant_artifact_group(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            with closing(sqlite3.connect(database)) as db:
                db.execute("UPDATE plugin_security_scans SET status='failed',artifact_sha256='' WHERE scan_id=11")
                db.execute("UPDATE plugin_security_current SET status='failed',artifact_sha256='' WHERE variant_id=2")
                db.commit()
            output = root / "v2"
            index = migrate(database, output, reset=True, chunk_bytes=1024 * 1024)
            self.assertEqual(index["counts"]["currentVariants"], 2)
            self.assertEqual(index["counts"]["analyses"], 1)
            self.assertEqual(index["counts"]["artifactGroups"], 2)
            report = validate_snapshot(output)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["checkedVariants"], 2)
            self.assertEqual(report["checkedAnalyses"], 1)

    def test_download_current_source_resolution_records_verified_context(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            archive = root / "evidence.zip"
            archive.write_bytes(b"fixture")
            downloaded = DownloadedEvidence(
                database=database,
                archive=archive,
                release_tag="security-evidence-latest",
                asset_name="omega-security-evidence.sqlite.zip",
                asset_bytes=7,
                asset_sha256="a" * 64,
            )
            from unittest.mock import patch
            with patch("migrate_security_evidence_v2.download_current_database", return_value=downloaded):
                resolved, context = _resolve_source_database(None, True, root / "cache")
            self.assertEqual(resolved, database.resolve())
            self.assertEqual(context["mode"], "download-current")
            self.assertEqual(context["assetSha256"], "a" * 64)
            self.assertEqual(context["databasePath"], str(database.resolve()))

    def test_validator_can_infer_migration_source_database(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            output = root / "v2"
            migrate(database, output, reset=True, chunk_bytes=1024 * 1024, source_context={"mode": "local"})
            self.assertEqual(infer_database_from_migration_state(output), database.resolve())
            self.assertTrue(validate(infer_database_from_migration_state(output), output)["ok"])

    def test_publication_audit_gate_rejects_failures_and_optional_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report = root / "audit.json"
            report.write_text(json.dumps({"counts": {"pass": 10, "warn": 0, "fail": 0}}), encoding="utf-8")
            self.assertEqual(validate_audit_report(report)["counts"]["fail"], 0)

            report.write_text(json.dumps({"counts": {"pass": 9, "warn": 0, "fail": 1}}), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "failing checks"):
                validate_audit_report(report)

            report.write_text(json.dumps({"counts": {"pass": 9, "warn": 1, "fail": 0}}), encoding="utf-8")
            self.assertEqual(validate_audit_report(report)["counts"]["warn"], 1)
            with self.assertRaisesRegex(RuntimeError, "warnings"):
                validate_audit_report(report, strict_warnings=True)

    def test_large_derived_record_dataset_uses_bounded_compressed_shards(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows = [
                {"component_key": f"component-{i}", "evidence": "x" * 512, "status": "resolved"}
                for i in range(6000)
            ]
            descriptor = write_record_dataset(
                root, root / "derived" / "variants" / "0000" / "1", "dependency-resolutions", rows,
                inline_bytes=1024, chunk_bytes=1024 * 1024,
            )
            self.assertEqual(descriptor["records"], len(rows))
            self.assertGreaterEqual(len(descriptor["files"]), 1)
            self.assertTrue(all(item["encoding"] == "jsonl+gzip" for item in descriptor["files"]))
            self.assertTrue(all(int(item["bytes"]) <= MAX_PUBLISH_FILE_BYTES for item in descriptor["files"]))
            self.assertEqual(read_record_dataset(root, descriptor), rows)

    def test_download_helper_sidecar_and_safe_sqlite_extraction(self) -> None:
        import zipfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite")
            bundle = root / "evidence.zip"
            with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.write(database, "nested/omega-security-evidence.sqlite")
            extracted = safe_extract_sqlite(bundle, root / "out")
            self.assertEqual(extracted.read_bytes()[:16], b"SQLite format 3\x00")
            self.assertEqual(parse_sidecar("abc " + "f" * 64 + "  file.zip"), "f" * 64)


if __name__ == "__main__":
    unittest.main()

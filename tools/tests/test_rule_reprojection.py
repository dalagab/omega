from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
CATALOG = ROOT / "tools" / "catalog"
for path in (SECURITY, CATALOG):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import analysis_revision
import definition_packs
from migrate_security_evidence_v2 import migrate
import rule_reprojection
import security_evidence_v2


class RuleReprojectionTests(unittest.TestCase):
    def make_database(self, path: Path, *, include_static_observations: bool = True, zero_hits: bool = False) -> Path:
        matches = [] if zero_hits else [
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
        ]
        report = {
            "schema": "omega.plugin-security.scan.v1",
            "artifactAnalysisRevision": "artifact-analysis-fixture",
            "sourceAnalysisRevision": "source-analysis-fixture",
            "dependencyIntelligence": {
                "staticPatternMatchContractVersion": 1 if include_static_observations else 0,
                "staticPatternMatches": matches if include_static_observations else [],
            },
        }
        db = sqlite3.connect(path)
        db.executescript("""
        CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT INTO catalog_meta VALUES('security_revision','sec-test');
        INSERT INTO catalog_meta VALUES('evidence_revision','ev-test');
        INSERT INTO catalog_meta VALUES('catalog_revision','cat-test');
        INSERT INTO catalog_meta VALUES('base_revision','base-test');
        INSERT INTO catalog_meta VALUES('security_scanner_version','2.15.0');

        CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY,internal_name TEXT,name TEXT,author TEXT);
        INSERT INTO plugins VALUES(1,'FixturePlugin','Fixture Plugin','Tester');
        CREATE TABLE sources(source_id INTEGER PRIMARY KEY,name TEXT,url TEXT);
        INSERT INTO sources VALUES(1,'Fixture','https://example.invalid/pluginmaster.json');
        CREATE TABLE plugin_variants(variant_id INTEGER PRIMARY KEY,plugin_id INTEGER,source_id INTEGER,assembly_version TEXT);
        INSERT INTO plugin_variants VALUES(1,1,1,'1.0.0');
        CREATE TABLE plugin_security_scans(
          scan_id INTEGER PRIMARY KEY,plugin_id INTEGER,variant_id INTEGER,source_id INTEGER,
          artifact_sha256 TEXT,scanner_version TEXT,status TEXT,highest_severity TEXT,
          informational_count INTEGER,caution_count INTEGER,high_count INTEGER,critical_count INTEGER,
          scanned_at_utc TEXT,report_json TEXT
        );
        CREATE TABLE plugin_security_current(
          variant_id INTEGER PRIMARY KEY,scan_id INTEGER,status TEXT,artifact_sha256 TEXT,scanner_version TEXT,
          highest_severity TEXT,informational_count INTEGER,caution_count INTEGER,high_count INTEGER,critical_count INTEGER
        );
        CREATE TABLE plugin_security_findings(
          finding_id INTEGER PRIMARY KEY,scan_id INTEGER,rule_id TEXT,severity TEXT,category TEXT,title TEXT,description TEXT,evidence_json TEXT
        );
        CREATE TABLE plugin_security_dependencies(
          dependency_id INTEGER PRIMARY KEY,scan_id INTEGER,origin TEXT,kind TEXT,name TEXT,version TEXT,
          version_requirement TEXT,resolved_version TEXT,path TEXT,status TEXT,requirement TEXT,evidence_json TEXT,
          relationship TEXT,relationship_confidence TEXT,relationship_evidence_json TEXT
        );
        """)
        artifact = "a" * 64
        counts = (0, 0, 0, 0) if zero_hits else (1, 1, 1, 0)
        highest = "none" if zero_hits else "high"
        encoded = json.dumps(report, separators=(",", ":"))
        db.execute(
            "INSERT INTO plugin_security_scans VALUES(10,1,1,1,?,'2.15.0','complete',?,?,?,?,?,'2026-08-21T11:50:00Z',?)",
            (artifact, highest, *counts, encoded),
        )
        db.execute(
            "INSERT INTO plugin_security_current VALUES(1,10,'complete',?,'2.15.0',?,?,?,?,?)",
            (artifact, highest, *counts),
        )
        if not zero_hits:
            rows = [
                (1, 10, "network.http", "informational", "network", "Network access", "legacy", '[]'),
                (2, 10, "process.launch", "caution", "process", "Process execution", "legacy", '[]'),
                (3, 10, "compound.network-execute", "high", "compound", "Network plus process execution", "legacy", '[]'),
            ]
            db.executemany("INSERT INTO plugin_security_findings VALUES(?,?,?,?,?,?,?,?)", rows)
        db.commit()
        db.close()
        return path

    def compiled(self) -> dict:
        return definition_packs.compile_pack_root(ROOT / "security-definitions" / "packs")["compiledRuleSet"]

    def evidence(self, root: Path, **kwargs) -> Path:
        database = self.make_database(root / "evidence.sqlite", **kwargs)
        evidence = root / "v2"
        migrate(database, evidence, reset=True, chunk_bytes=1024 * 1024)
        return evidence

    def test_compatible_retained_observations_reproject_without_legacy_findings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-reproject-compatible-") as td:
            root = Path(td)
            evidence = self.evidence(root)
            # Phase-10 reprojection must not require the old projection as an input.
            _entry, payload = next(iter(security_evidence_v2.iter_variant_entries(evidence)))
            analysis_path = str((payload.get("analysis") or {}).get("path") or "")
            manifest_path = evidence / analysis_path / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            findings = manifest["datasets"].pop("findings")
            for item in findings.get("files") or []:
                (evidence / str(item["path"])).unlink()
            manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

            plan = rule_reprojection.plan_reprojection(evidence, self.compiled())
            self.assertTrue(plan["auditOk"], plan)
            self.assertTrue(plan["allVariantsReprojectable"], plan)
            self.assertEqual(1, plan["reprojectedVariants"])
            self.assertEqual(0, plan["reanalysisRequiredVariants"])
            projection = plan["projections"][0]
            self.assertEqual(["network.http", "process.launch"], [f for f in projection["facts"] if f in {"network.http", "process.launch"}])
            self.assertEqual(["compound.network-execute"], [row["ruleId"] for row in projection["findings"]])
            self.assertFalse(projection["productionWriteBack"])

    def test_missing_observation_gets_precise_targeted_reanalysis_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-reproject-missing-") as td:
            root = Path(td)
            evidence = self.evidence(root, include_static_observations=False)
            plan = rule_reprojection.plan_reprojection(evidence, self.compiled())
            self.assertTrue(plan["auditOk"], plan)
            self.assertEqual(0, plan["reprojectedVariants"])
            self.assertEqual(1, plan["reanalysisRequiredVariants"])
            request = plan["reanalysisRequests"][0]
            self.assertEqual(["staticPatternMatches"], request["missingCollections"])
            self.assertEqual("missing observation collection staticPatternMatches", request["reason"])
            self.assertFalse(request["queueMutationAuthorized"])

    def test_complete_zero_hit_observation_reprojects_as_exact_negative(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-reproject-zero-") as td:
            root = Path(td)
            evidence = self.evidence(root, zero_hits=True)
            plan = rule_reprojection.plan_reprojection(evidence, self.compiled())
            self.assertTrue(plan["allVariantsReprojectable"], plan)
            projection = plan["projections"][0]
            self.assertEqual([], projection["facts"])
            self.assertEqual([], projection["findings"])
            self.assertEqual([], projection["matchedRuleIds"])

    def test_materialized_projection_set_is_deterministic_and_tamper_detecting(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-reproject-materialize-") as td:
            root = Path(td)
            evidence = self.evidence(root)
            plan = rule_reprojection.plan_reprojection(evidence, self.compiled())
            out_a = root / "projection-a"
            out_b = root / "projection-b"
            index_a = rule_reprojection.materialize_projection_set(out_a, plan)
            index_b = rule_reprojection.materialize_projection_set(out_b, plan)
            self.assertEqual(index_a, index_b)
            files_a = {p.relative_to(out_a).as_posix(): p.read_bytes() for p in out_a.rglob("*") if p.is_file()}
            files_b = {p.relative_to(out_b).as_posix(): p.read_bytes() for p in out_b.rglob("*") if p.is_file()}
            self.assertEqual(files_a, files_b)
            self.assertTrue(rule_reprojection.verify_projection_set(out_a)["ok"])
            variant_file = next((out_a / "variants").glob("*.json"))
            variant_file.write_text(variant_file.read_text(encoding="utf-8") + " ", encoding="utf-8")
            validation = rule_reprojection.verify_projection_set(out_a)
            self.assertFalse(validation["ok"])
            self.assertTrue(any("sha256 mismatch" in item for item in validation["errors"]))

    def test_analysis_request_sidecar_is_hash_pinned_and_tamper_detected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-reproject-analysis-requests-") as td:
            root = Path(td)
            evidence = self.evidence(root)
            plan = rule_reprojection.plan_reprojection(evidence, self.compiled())
            output = root / "projection"
            index = rule_reprojection.materialize_projection_set(output, plan)
            deep_entry = index["analysisRequests"]
            self.assertEqual("analysis-requests.json", deep_entry["path"])
            self.assertTrue(rule_reprojection.verify_projection_set(output)["ok"])
            deep_path = output / deep_entry["path"]
            deep_path.write_text(deep_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
            validation = rule_reprojection.verify_projection_set(output)
            self.assertFalse(validation["ok"])
            self.assertTrue(any("sha256 mismatch for analysis-requests.json" in item for item in validation["errors"]))

    def test_rule_only_revision_changes_projection_not_analysis_revisions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-reproject-revision-") as td:
            root = Path(td)
            evidence = self.evidence(root)
            compiled_a = self.compiled()
            plan_a = rule_reprojection.plan_reprojection(evidence, compiled_a)
            analysis_before = analysis_revision.compute(ROOT)
            compiled_b = json.loads(json.dumps(compiled_a))
            compiled_b["ruleSetRevision"] = "srl-ruleset-v1-rule-only-test-change"
            plan_b = rule_reprojection.plan_reprojection(evidence, compiled_b)
            analysis_after = analysis_revision.compute(ROOT)
            self.assertNotEqual(plan_a["projectionSetRevision"], plan_b["projectionSetRevision"])
            self.assertNotEqual(plan_a["projections"][0]["projectionRevision"], plan_b["projections"][0]["projectionRevision"])
            self.assertEqual(analysis_before["artifactAnalysisRevision"], analysis_after["artifactAnalysisRevision"])
            self.assertEqual(analysis_before["sourceAnalysisRevision"], analysis_after["sourceAnalysisRevision"])

    def test_tampered_required_observation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-reproject-tamper-") as td:
            root = Path(td)
            evidence = self.evidence(root)
            _entry, payload = next(iter(security_evidence_v2.iter_variant_entries(evidence)))
            analysis_path = str((payload.get("analysis") or {}).get("path") or "")
            manifest = json.loads((evidence / analysis_path / "manifest.json").read_text(encoding="utf-8"))
            descriptor = manifest["datasets"]["staticPatternMatches"]
            data_path = evidence / descriptor["files"][0]["path"]
            data_path.write_text(data_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
            plan = rule_reprojection.plan_reprojection(evidence, self.compiled())
            self.assertFalse(plan["auditOk"], plan)
            self.assertEqual(1, plan["auditErrorVariants"])
            self.assertIn("sha256 mismatch", plan["variants"][0]["reason"])

    def test_cli_materializes_same_nonproduction_projection_set(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-reproject-cli-") as td:
            root = Path(td)
            evidence = self.evidence(root)
            output = root / "projection"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "security" / "rule_reprojection.py"),
                    "--evidence-v2", str(evidence),
                    "--output", str(output),
                ],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            report = json.loads(proc.stdout)
            self.assertTrue(report["materialized"]["validation"]["ok"], report)
            index = json.loads((output / "index.json").read_text(encoding="utf-8"))
            self.assertFalse(index["productionRuleEvaluationEnabled"])
            self.assertFalse(index["productionWriteBack"])
            self.assertFalse(index["queueMutationAuthorized"])


if __name__ == "__main__":
    unittest.main()

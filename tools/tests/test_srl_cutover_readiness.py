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

import definitions_snapshot
from migrate_security_evidence_v2 import migrate
import srl_cutover_readiness


class SrlCutoverReadinessTests(unittest.TestCase):
    def make_database(
        self,
        path: Path,
        *,
        static_contract: bool = True,
        zero_hits: bool = False,
        baseline_mismatch: bool = False,
    ) -> Path:
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
            "dependencyIntelligence": {
                "staticPatternMatchContractVersion": 1 if static_contract else 0,
                "staticPatternMatches": matches if static_contract else [],
            },
        }
        db = sqlite3.connect(path)
        db.executescript("""
        CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT INTO catalog_meta VALUES('security_revision','sec-cutover');
        INSERT INTO catalog_meta VALUES('evidence_revision','ev-cutover');
        INSERT INTO catalog_meta VALUES('catalog_revision','cat-cutover');
        INSERT INTO catalog_meta VALUES('base_revision','base-cutover');
        INSERT INTO catalog_meta VALUES('security_scanner_version','2.15.0');
        CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY,internal_name TEXT,name TEXT,author TEXT);
        INSERT INTO plugins VALUES(1,'CutoverFixture','Cutover Fixture','Tester');
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
        encoded = json.dumps(report, separators=(",", ":"))
        artifact = "a" * 64
        if zero_hits:
            highest, counts = "none", (0, 0, 0, 0)
        else:
            highest, counts = "high", (1, 1, 1, 0)
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
                (1, 10, "network.http", "informational", "network", "Network access", "legacy", '["metadata:Fixture.dll: System.Net.Http.HttpClient"]'),
            ]
            if not baseline_mismatch:
                rows.extend([
                    (2, 10, "process.launch", "caution", "process", "Process execution", "legacy", '["metadata:Fixture.dll: Process.Start"]'),
                    (3, 10, "compound.network-execute", "high", "compound", "Network plus process execution", "The artifact references both network access and process/shell execution. This combination can download and execute external content; manual review is recommended.", "[]"),
                ])
            db.executemany("INSERT INTO plugin_security_findings VALUES(?,?,?,?,?,?,?,?)", rows)
        db.commit()
        db.close()
        return path

    def build_definitions(self, root: Path) -> Path:
        evidence = root / "definitions-input-evidence"
        (evidence / "indexes").mkdir(parents=True)
        (evidence / "indexes" / "nuget.json").write_text(
            json.dumps({"schema": "omega.security-evidence.nuget-index.v2", "packages": []}), encoding="utf-8"
        )
        (evidence / "index.json").write_text(
            json.dumps({"revisions": {"evidenceRevision": "fixture"}, "indexes": {"nuget": {"path": "indexes/nuget.json"}}}),
            encoding="utf-8",
        )
        advisories = root / "advisories.json"
        advisories.write_text(
            json.dumps({
                "schema": "omega.public-advisories.v1", "source": "OSV", "ecosystem": "NuGet",
                "queriedPackages": 0, "matchedPackages": 0, "advisories": [],
            }), encoding="utf-8"
        )
        secondary = root / "secondary"
        (secondary / "yara").mkdir(parents=True)
        (secondary / "clamav").mkdir(parents=True)
        definitions = root / "definitions"
        definitions_snapshot.build_snapshot(
            repo_root=ROOT,
            evidence_root=evidence,
            output=definitions,
            source_commit="cutover-fixture",
            advisories_input=advisories,
            secondary_security_input=secondary,
            definition_packs_input=ROOT / "security-definitions" / "packs",
        )
        return definitions

    def build_evidence(self, root: Path, **kwargs) -> Path:
        db = self.make_database(root / "catalog.sqlite", **kwargs)
        evidence = root / "evidence-v2"
        migrate(db, evidence, reset=True, chunk_bytes=1024 * 1024)
        return evidence

    def test_complete_compatible_corpus_is_ready_for_review_but_never_authorized(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-cutover-ready-") as td:
            root = Path(td)
            report = srl_cutover_readiness.build_report(self.build_definitions(root), self.build_evidence(root))
            self.assertTrue(report["cutoverReadyForReview"], report)
            self.assertEqual("ready-for-human-review", report["readinessState"])
            self.assertEqual(1, report["summary"]["currentVariants"])
            self.assertEqual(1, report["summary"]["compatibleExactVariants"])
            self.assertEqual(0, report["summary"]["reanalysisRequiredVariants"])
            self.assertTrue(report["manualApprovalRequired"])
            self.assertFalse(report["activationAuthorized"])
            self.assertFalse(report["hardCodedBaselineRemovalAuthorized"])
            self.assertFalse(report["productionWriteBack"])
            self.assertFalse(report["queueMutationAuthorized"])
            self.assertEqual(64, len(report["auditImplementationSha256"]))
            self.assertTrue(all(gate["passed"] for gate in report["gates"]), report["gates"])

    def test_missing_observation_blocks_cutover_with_precise_reanalysis_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-cutover-missing-") as td:
            root = Path(td)
            report = srl_cutover_readiness.build_report(
                self.build_definitions(root), self.build_evidence(root, static_contract=False)
            )
            self.assertFalse(report["cutoverReadyForReview"], report)
            self.assertEqual(1, report["summary"]["reanalysisRequiredVariants"])
            self.assertEqual(["staticPatternMatches"], report["reanalysisRequests"][0]["missingCollections"])
            self.assertTrue(any(item["reason"] == "missing observation collection staticPatternMatches" for item in report["reasonSummary"]))

    def test_legacy_baseline_mismatch_blocks_cutover_even_when_reprojection_is_possible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-cutover-mismatch-") as td:
            root = Path(td)
            report = srl_cutover_readiness.build_report(
                self.build_definitions(root), self.build_evidence(root, baseline_mismatch=True)
            )
            self.assertFalse(report["cutoverReadyForReview"], report)
            self.assertEqual(1, report["summary"]["mismatchedVariants"])
            self.assertEqual(1, report["summary"]["reprojectedVariants"])
            parity = next(item for item in report["gates"] if item["id"] == "replay.parity")
            self.assertFalse(parity["passed"])

    def test_complete_zero_hit_observation_is_a_valid_cutover_negative(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-cutover-zero-") as td:
            root = Path(td)
            report = srl_cutover_readiness.build_report(
                self.build_definitions(root), self.build_evidence(root, zero_hits=True)
            )
            self.assertTrue(report["cutoverReadyForReview"], report)
            self.assertEqual(1, report["summary"]["compatibleExactVariants"])

    def test_filtered_or_limited_run_is_diagnostic_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-cutover-filtered-") as td:
            root = Path(td)
            definitions = self.build_definitions(root)
            evidence = self.build_evidence(root)
            report = srl_cutover_readiness.build_report(definitions, evidence, variant_ids=[1])
            self.assertFalse(report["cutoverReadyForReview"], report)
            self.assertFalse(next(item for item in report["gates"] if item["id"] == "corpus.full")["passed"])
            limited = srl_cutover_readiness.build_report(definitions, evidence, limit=1)
            self.assertFalse(limited["cutoverReadyForReview"], limited)

    def test_cli_require_ready_returns_three_for_blocked_corpus_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-cutover-cli-") as td:
            root = Path(td)
            definitions = self.build_definitions(root)
            evidence = self.build_evidence(root, static_contract=False)
            output = root / "readiness.json"
            proc = subprocess.run(
                [
                    sys.executable, str(SECURITY / "srl_cutover_readiness.py"),
                    "--definitions-root", str(definitions),
                    "--evidence-v2", str(evidence),
                    "--output", str(output),
                    "--summary", "--require-ready",
                ],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
            )
            self.assertEqual(3, proc.returncode, proc.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(report["cutoverReadyForReview"])
            summary = json.loads(proc.stdout)
            self.assertFalse(summary["activationAuthorized"])

    def test_cutover_workflow_is_retired_but_preserved_read_only(self) -> None:
        self.assertFalse((ROOT / ".github" / "workflows" / "srl-cutover-readiness.yml").exists())
        workflow = (ROOT / ".github" / "retired-workflows" / "cutover" / "srl-cutover-readiness.yml").read_text(encoding="utf-8")
        caller = (ROOT / "docs" / "retired-workflow-callers" / "srl-cutover-readiness-main.yml").read_text(encoding="utf-8")
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertIn("ref: catalog-data", workflow)
        self.assertIn("ref: security-evidence-v2", workflow)
        self.assertIn("ref: sigmascope", workflow)
        self.assertIn("--require-ready", workflow)
        self.assertIn("actions/upload-artifact@v7", workflow)
        self.assertNotIn("push", workflow.casefold())
        self.assertIn("uses: dalagab/omega/.github/workflows/srl-cutover-readiness.yml@sigmascope", caller)
        self.assertIn("contents: read", caller)
        self.assertNotIn("contents: write", caller)


if __name__ == "__main__":
    unittest.main()

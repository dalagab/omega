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

import definition_packs
from migrate_security_evidence_v2 import migrate
import srl_evidence_replay


class SrlEvidenceReplayTests(unittest.TestCase):
    def make_database(self, path: Path, *, include_static_observations: bool) -> Path:
        report = {
            "schema": "omega.plugin-security.scan.v1",
            "dependencyIntelligence": {
                "staticPatternMatchContractVersion": 1 if include_static_observations else 0,
                "staticPatternMatches": ([
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
                ] if include_static_observations else []),
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
        encoded = json.dumps(report, separators=(",", ":"))
        artifact = "a" * 64
        db.execute(
            "INSERT INTO plugin_security_scans VALUES(10,1,1,1,?,'2.15.0','complete','high',1,1,1,0,'2026-08-21T11:50:00Z',?)",
            (artifact, encoded),
        )
        db.execute(
            "INSERT INTO plugin_security_current VALUES(1,10,'complete',?,'2.15.0','high',1,1,1,0)",
            (artifact,),
        )
        rows = [
            (1, 10, "network.http", "informational", "network", "Network access", "References HTTP/network client APIs.", '["metadata:Fixture.dll: System.Net.Http.HttpClient"]'),
            (2, 10, "process.launch", "caution", "process", "Process execution", "References APIs that can launch external programs or shell commands.", '["metadata:Fixture.dll: Process.Start"]'),
            (3, 10, "compound.network-execute", "high", "compound", "Network plus process execution", "The artifact references both network access and process/shell execution. This combination can download and execute external content; manual review is recommended.", "[]"),
        ]
        db.executemany("INSERT INTO plugin_security_findings VALUES(?,?,?,?,?,?,?,?)", rows)
        db.commit()
        db.close()
        return path

    def compiled(self) -> dict:
        return definition_packs.compile_pack_root(ROOT / "security-definitions" / "packs")["compiledRuleSet"]

    def test_retained_static_pattern_observations_replay_exactly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-srl-replay-compatible-") as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite", include_static_observations=True)
            evidence = root / "v2"
            migrate(database, evidence, reset=True, chunk_bytes=1024 * 1024)
            report = srl_evidence_replay.replay_evidence_root(evidence, self.compiled())
            self.assertTrue(report["auditOk"], report)
            self.assertTrue(report["cutoverReady"], report)
            self.assertEqual(1, report["matchedVariants"])
            self.assertEqual(0, report["rescanRequiredVariants"])
            variant = report["variants"][0]
            self.assertEqual(["network.http", "process.launch"], variant["srlPrimitiveFacts"])
            self.assertTrue(variant["compoundMatched"])

    def test_legacy_evidence_without_static_observations_is_targeted_for_reanalysis(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-srl-replay-legacy-") as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite", include_static_observations=False)
            evidence = root / "v2"
            migrate(database, evidence, reset=True, chunk_bytes=1024 * 1024)
            report = srl_evidence_replay.replay_evidence_root(evidence, self.compiled())
            self.assertTrue(report["auditOk"], report)
            self.assertFalse(report["cutoverReady"])
            self.assertEqual(0, report["evaluatedVariants"])
            self.assertEqual(1, report["rescanRequiredVariants"])
            variant = report["variants"][0]
            self.assertTrue(variant["rescanRequired"])
            self.assertIn("required collection", variant["reason"])
            self.assertIn("staticPatternMatches", variant["replayAudit"]["missingCollections"])

    def test_complete_zero_hit_collection_replays_as_negative_not_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-srl-replay-empty-complete-") as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite", include_static_observations=True)
            with sqlite3.connect(database) as db:
                report = json.loads(db.execute("SELECT report_json FROM plugin_security_scans WHERE scan_id=10").fetchone()[0])
                report["dependencyIntelligence"]["staticPatternMatches"] = []
                db.execute("UPDATE plugin_security_scans SET report_json=? WHERE scan_id=10", (json.dumps(report, separators=(",", ":")),))
                db.execute("DELETE FROM plugin_security_findings WHERE scan_id=10")
                db.execute("UPDATE plugin_security_scans SET highest_severity='none',informational_count=0,caution_count=0,high_count=0,critical_count=0 WHERE scan_id=10")
                db.execute("UPDATE plugin_security_current SET highest_severity='none',informational_count=0,caution_count=0,high_count=0,critical_count=0 WHERE variant_id=1")
                db.commit()
            evidence = root / "v2"
            migrate(database, evidence, reset=True, chunk_bytes=1024 * 1024)
            report = srl_evidence_replay.replay_evidence_root(evidence, self.compiled())
            self.assertTrue(report["auditOk"], report)
            self.assertTrue(report["cutoverReady"], report)
            self.assertEqual(1, report["evaluatedVariants"])
            self.assertEqual(0, report["rescanRequiredVariants"])
            self.assertEqual([], report["variants"][0]["srlPrimitiveFacts"])


    def test_missing_baseline_dataset_is_an_audit_error_not_a_clean_negative(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-srl-replay-missing-baseline-") as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite", include_static_observations=True)
            with sqlite3.connect(database) as db:
                report = json.loads(db.execute("SELECT report_json FROM plugin_security_scans WHERE scan_id=10").fetchone()[0])
                report["dependencyIntelligence"]["staticPatternMatches"] = []
                db.execute("UPDATE plugin_security_scans SET report_json=? WHERE scan_id=10", (json.dumps(report, separators=(",", ":")),))
                db.execute("DELETE FROM plugin_security_findings WHERE scan_id=10")
                db.commit()
            evidence = root / "v2"
            migrate(database, evidence, reset=True, chunk_bytes=1024 * 1024)
            variant = next(iter(srl_evidence_replay.security_evidence_v2.iter_variant_entries(evidence)))[1]
            analysis_path = str((variant.get("analysis") or {}).get("path") or "")
            manifest_path = evidence / analysis_path / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["datasets"].pop("findings", None)
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            report = srl_evidence_replay.replay_evidence_root(evidence, self.compiled())
            self.assertFalse(report["auditOk"], report)
            self.assertFalse(report["cutoverReady"], report)
            self.assertEqual(1, report["auditErrorVariants"])
            self.assertTrue(report["variants"][0]["auditError"])

    def test_producer_rule_replay_cli_uses_retained_evidence_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-srl-replay-cli-") as td:
            root = Path(td)
            database = self.make_database(root / "evidence.sqlite", include_static_observations=True)
            evidence = root / "v2"
            migrate(database, evidence, reset=True, chunk_bytes=1024 * 1024)
            proc = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "security" / "srl_evidence_replay.py"), "--evidence-root", str(evidence)],
                cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
            )
            report = json.loads(proc.stdout)
            self.assertTrue(report["cutoverReady"], report)
            self.assertEqual(1, report["matchedVariants"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
from pathlib import Path
import shutil
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
import srl_migration_parity
import sigmascope


class SrlMigrationParityTests(unittest.TestCase):
    def test_scanner_retains_rule_neutral_static_pattern_observation(self) -> None:
        from collections import defaultdict
        hits = defaultdict(list)
        intel = sigmascope.empty_dependency_intelligence("artifact")
        sigmascope.add_rule_hits("HttpWebRequest", "metadata:Fixture.dll", hits, intel)
        self.assertIn("network.http", hits)
        self.assertEqual(1, intel["staticPatternMatchContractVersion"])
        self.assertTrue(intel["staticPatternMatches"])
        row = intel["staticPatternMatches"][0]
        self.assertIn(row["pattern"], {"WebRequest", "HttpWebRequest"})
        self.assertNotIn("ruleId", row)
        self.assertNotIn("severity", row)

    def test_reviewed_compound_pack_matches_current_hard_coded_projection_exhaustively(self) -> None:
        report = srl_migration_parity.run_pack_root_parity(ROOT / "security-definitions" / "packs")
        self.assertTrue(report["ok"], report.get("mismatches"))
        self.assertEqual(32, report["casesChecked"])
        self.assertEqual(147, report["primitiveCasesChecked"])
        self.assertEqual(0, report["primitiveMismatchCount"])
        self.assertEqual(0, report["mismatchCount"])
        self.assertEqual(16, report["activeRuleCount"])
        self.assertEqual(
            ["compound.credential-network", "compound.network-execute"],
            report["migratedFindingIds"],
        )
        self.assertFalse(report["productionRuleEvaluationEnabled"])

    def test_payload_drift_is_detected_even_when_pack_fixtures_still_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-phase7-parity-drift-") as td:
            packs = Path(td) / "packs"
            target = packs / "omega-core-compound"
            shutil.copytree(ROOT / "security-definitions" / "packs" / "omega-core-compound", target)
            shutil.copytree(
                ROOT / "security-definitions" / "packs" / "omega-core-static-primitives",
                packs / "omega-core-static-primitives",
            )
            rule = target / "rules" / "compound-correlations.yaml"
            text = rule.read_text(encoding="utf-8")
            text = text.replace(
                "title: Network plus process execution",
                "title: Network plus process execution drift",
                1,
            )
            rule.write_text(text, encoding="utf-8")
            report = srl_migration_parity.run_pack_root_parity(packs)
            self.assertFalse(report["ok"])
            self.assertGreater(report["mismatchCount"], 0)
            self.assertTrue(any(item.get("legacy") != item.get("srl") for item in report["mismatches"]))

    def test_daily_definitions_records_and_verifies_phase7_parity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-phase7-definitions-") as td:
            root = Path(td)
            evidence = root / "evidence"
            (evidence / "indexes").mkdir(parents=True)
            (evidence / "indexes" / "nuget.json").write_text(
                json.dumps({"schema": "omega.security-evidence.nuget-index.v2", "packages": []}),
                encoding="utf-8",
            )
            (evidence / "index.json").write_text(
                json.dumps({"revisions": {"evidenceRevision": "fixture"}, "indexes": {"nuget": {"path": "indexes/nuget.json"}}}),
                encoding="utf-8",
            )
            advisories = root / "advisories.json"
            advisories.write_text(
                json.dumps({
                    "schema": "omega.public-advisories.v1",
                    "source": "OSV",
                    "ecosystem": "NuGet",
                    "queriedPackages": 0,
                    "matchedPackages": 0,
                    "advisories": [],
                }),
                encoding="utf-8",
            )
            secondary = root / "secondary"
            (secondary / "yara").mkdir(parents=True)
            (secondary / "clamav").mkdir(parents=True)
            definitions = root / "definitions"

            index = definitions_snapshot.build_snapshot(
                repo_root=ROOT,
                evidence_root=evidence,
                output=definitions,
                source_commit="fixture",
                advisories_input=advisories,
                secondary_security_input=secondary,
                definition_packs_input=ROOT / "security-definitions" / "packs",
            )
            parity = index["srlDefinitionPacks"]["migrationParity"]
            self.assertTrue(parity["ok"])
            self.assertEqual("passed", parity["status"])
            self.assertEqual(32, parity["casesChecked"])
            self.assertEqual(147, parity["primitiveCasesChecked"])
            self.assertEqual(0, parity["primitiveMismatchCount"])
            self.assertEqual(0, parity["mismatchCount"])
            self.assertEqual(index["srlDefinitionPacks"]["ruleSetRevision"], parity["ruleSetRevision"])

            validation = definitions_snapshot.verify_snapshot(definitions_root=definitions)
            self.assertTrue(validation["ok"], validation)

            parity_path = definitions / parity["path"]
            parity_path.write_text(parity_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            tampered = definitions_snapshot.verify_snapshot(definitions_root=definitions)
            self.assertFalse(tampered["ok"])
            self.assertTrue(any("migration parity report SHA-256 mismatch" in item for item in tampered["errors"]), tampered)


if __name__ == "__main__":
    unittest.main()

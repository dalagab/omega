from __future__ import annotations

import json
from pathlib import Path
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
import definitions_snapshot

RULE = """
schema: omega.sigmascope.rule.v1
id: capability.process.execute.pack-fixture
kind: observation
status: reviewed
requires: [managedCallSites]
selectors:
  process_start:
    collection: managedCallSites
    where:
      targetDeclaringType: {equals-ci: System.Diagnostics.Process}
      targetName: {equals-ci: Start}
condition: process_start
emit:
  fact: process.execute.pack-fixture
  confidence: high
  title: Process execution fixture
"""

FIXTURE = """
schema: omega.sigmascope.rule-fixture.v1
name: process execution pack fixture
observations:
  managedCallSites:
    - targetDeclaringType: System.Diagnostics.Process
      targetName: Start
expected:
  facts: [process.execute.pack-fixture]
  matchedRules: [capability.process.execute.pack-fixture]
"""


def write_pack(root: Path, pack_id: str = "core-fixture", trust: str = "core", rule_status: str = "reviewed") -> Path:
    pack = root / pack_id
    (pack / "rules").mkdir(parents=True)
    (pack / "fixtures").mkdir(parents=True)
    (pack / "rules" / "process.yaml").write_text(RULE.replace("status: reviewed", f"status: {rule_status}"), encoding="utf-8")
    (pack / "fixtures" / "positive.yaml").write_text(FIXTURE, encoding="utf-8")
    review = """
review:
  reviewer: unit-test
  reviewedAtUtc: 2026-08-21T00:00:00Z
""" if trust in {"core", "reviewed"} else ""
    rule_review = """
    review:
      reviewer: unit-test
      reviewedAtUtc: 2026-08-21T00:00:00Z
""" if trust in {"core", "reviewed"} else ""
    manifest = f"""
schema: omega.sigmascope.definition-pack.v1
id: {pack_id}
title: Unit test pack
trustTier: {trust}
license: test-only
provenance:
  kind: first-party-test
  source: unit-test
{review}compatibility:
  minimumSrlEngineVersion: 1
  minimumObservationContractVersion: 1
  ruleSchema: omega.sigmascope.rule.v1
  fixtureSchema: omega.sigmascope.rule-fixture.v1
  observationContractSchema: omega.sigmascope.observation-contract.v1
rules:
  - path: rules/process.yaml
    ids: [capability.process.execute.pack-fixture]
    license: test-only
    provenance:
      kind: first-party-test
      source: unit-test/rules/process.yaml
{rule_review}fixtures:
  - path: fixtures/positive.yaml
"""
    (pack / "pack.yaml").write_text(manifest, encoding="utf-8")
    return pack / "pack.yaml"


class DefinitionPackTests(unittest.TestCase):
    def test_core_pack_compiles_fixtures_and_freezes_deterministically(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-") as td:
            root = Path(td)
            packs = root / "packs"
            write_pack(packs)
            first = definition_packs.compile_pack_root(packs)
            second = definition_packs.compile_pack_root(packs)
            self.assertEqual(first["definitionPackRevision"], second["definitionPackRevision"])
            self.assertEqual(first["ruleSetRevision"], second["ruleSetRevision"])
            self.assertEqual(1, first["activeRuleCount"])
            self.assertEqual(1, first["packs"][0]["fixtures"][0]["passed"])

            definitions = root / "definitions"
            descriptor = definition_packs.freeze_pack_root(packs, definitions)
            validation = definition_packs.verify_frozen(definitions, descriptor)
            self.assertTrue(validation["ok"], validation)
            loaded = definition_packs.load_frozen_ruleset(definitions, descriptor)
            self.assertEqual(descriptor["ruleSetRevision"], loaded["ruleSetRevision"])
            self.assertEqual(1, len(loaded["rules"]))

    def test_experimental_pack_is_frozen_but_not_active(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-exp-") as td:
            packs = Path(td) / "packs"
            write_pack(packs, pack_id="experimental-fixture", trust="experimental")
            compiled = definition_packs.compile_pack_root(packs)
            self.assertEqual(1, compiled["totalRuleCount"])
            self.assertEqual(0, compiled["activeRuleCount"])
            self.assertFalse(compiled["packs"][0]["productionEligible"])

    def test_local_pack_is_excluded_from_daily_freeze(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-local-") as td:
            packs = Path(td) / "packs"
            write_pack(packs, pack_id="local-fixture", trust="local")
            daily = definition_packs.compile_pack_root(packs)
            self.assertEqual([], daily["packs"])
            local = definition_packs.compile_pack_root(packs, include_local=True)
            self.assertEqual(1, len(local["packs"]))

    def test_production_pack_rejects_non_reviewed_rule(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-review-") as td:
            packs = Path(td) / "packs"
            manifest = write_pack(packs, rule_status="experimental")
            with self.assertRaisesRegex(definition_packs.DefinitionPackError, "non-reviewed"):
                definition_packs.compile_pack(manifest)

    def test_production_pack_requires_positive_fixture_coverage_per_rule(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-coverage-") as td:
            packs = Path(td) / "packs"
            manifest = write_pack(packs)
            fixture = manifest.parent / "fixtures" / "positive.yaml"
            fixture.write_text(FIXTURE.replace("  matchedRules: [capability.process.execute.pack-fixture]\n", ""), encoding="utf-8")
            with self.assertRaisesRegex(definition_packs.DefinitionPackError, "lacks a positive matchedRules fixture"):
                definition_packs.compile_pack(manifest)

    def test_fixture_failure_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-fixture-") as td:
            packs = Path(td) / "packs"
            manifest = write_pack(packs)
            fixture = manifest.parent / "fixtures" / "positive.yaml"
            fixture.write_text(FIXTURE.replace("process.execute.pack-fixture", "wrong.fact"), encoding="utf-8")
            with self.assertRaisesRegex(definition_packs.DefinitionPackError, "fixtures failed"):
                definition_packs.compile_pack(manifest)

    def test_duplicate_rule_id_across_packs_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-dup-") as td:
            packs = Path(td) / "packs"
            write_pack(packs, pack_id="one", trust="experimental")
            write_pack(packs, pack_id="two", trust="experimental")
            with self.assertRaisesRegex(definition_packs.DefinitionPackError, "duplicate rule ID across packs"):
                definition_packs.compile_pack_root(packs)

    def test_declared_rule_ids_must_match_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-ids-") as td:
            packs = Path(td) / "packs"
            manifest = write_pack(packs)
            text = manifest.read_text(encoding="utf-8").replace(
                "ids: [capability.process.execute.pack-fixture]", "ids: [different.rule]"
            )
            manifest.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(definition_packs.DefinitionPackError, "do not match compiled rules"):
                definition_packs.compile_pack(manifest)

    def test_frozen_manifest_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-manifest-tamper-") as td:
            root = Path(td)
            packs = root / "packs"
            write_pack(packs)
            definitions = root / "definitions"
            descriptor = definition_packs.freeze_pack_root(packs, definitions)
            frozen_manifest = definitions / "srl" / "packs" / "core-fixture" / "pack.yaml"
            frozen_manifest.write_text(frozen_manifest.read_text(encoding="utf-8") + "\n# tamper\n", encoding="utf-8")
            validation = definition_packs.verify_frozen(definitions, descriptor)
            self.assertFalse(validation["ok"])
            self.assertTrue(any("SHA-256 mismatch" in item for item in validation["errors"]), validation)

    def test_frozen_rule_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-tamper-") as td:
            root = Path(td)
            packs = root / "packs"
            write_pack(packs)
            definitions = root / "definitions"
            descriptor = definition_packs.freeze_pack_root(packs, definitions)
            frozen_rule = definitions / "srl" / "packs" / "core-fixture" / "rules" / "process.yaml"
            frozen_rule.write_text(frozen_rule.read_text(encoding="utf-8") + "\n# tamper\n", encoding="utf-8")
            validation = definition_packs.verify_frozen(definitions, descriptor)
            self.assertFalse(validation["ok"])
            self.assertTrue(any("SHA-256 mismatch" in item for item in validation["errors"]), validation)

    def test_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-path-") as td:
            packs = Path(td) / "packs"
            manifest = write_pack(packs)
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("rules/process.yaml", "../outside.yaml"), encoding="utf-8")
            with self.assertRaisesRegex(definition_packs.DefinitionPackError, "inside the pack directory"):
                definition_packs.compile_pack(manifest)

    def test_daily_definitions_freezes_srl_without_repurposing_scanner_rule_revision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-definition-pack-definitions-") as td:
            root = Path(td)
            evidence = root / "evidence"
            (evidence / "indexes").mkdir(parents=True)
            (evidence / "indexes" / "nuget.json").write_text(json.dumps({"schema": "omega.security-evidence.nuget-index.v2", "packages": []}), encoding="utf-8")
            (evidence / "index.json").write_text(json.dumps({"revisions": {"evidenceRevision": "fixture"}, "indexes": {"nuget": {"path": "indexes/nuget.json"}}}), encoding="utf-8")
            advisories = root / "advisories.json"
            advisories.write_text(json.dumps({"schema": "omega.public-advisories.v1", "source": "OSV", "ecosystem": "NuGet", "queriedPackages": 0, "matchedPackages": 0, "advisories": []}), encoding="utf-8")
            secondary = root / "secondary"
            (secondary / "yara").mkdir(parents=True)
            (secondary / "clamav").mkdir(parents=True)
            empty_packs = root / "empty-packs"
            empty_packs.mkdir()
            reviewed_packs = root / "reviewed-packs"
            write_pack(reviewed_packs)

            first = definitions_snapshot.build_snapshot(
                repo_root=ROOT, evidence_root=evidence, output=root / "defs-empty", source_commit="fixture",
                advisories_input=advisories, secondary_security_input=secondary, definition_packs_input=empty_packs,
            )
            second = definitions_snapshot.build_snapshot(
                repo_root=ROOT, evidence_root=evidence, output=root / "defs-reviewed", source_commit="fixture",
                advisories_input=advisories, secondary_security_input=secondary, definition_packs_input=reviewed_packs,
            )
            self.assertEqual(first["ruleSetRevision"], second["ruleSetRevision"], "SRL pack changes must not silently repurpose the current scanner queue identity")
            self.assertNotEqual(first["definitionsRevision"], second["definitionsRevision"])
            self.assertNotEqual(first["srlDefinitionPacks"]["ruleSetRevision"], second["srlDefinitionPacks"]["ruleSetRevision"])
            report = definitions_snapshot.verify_snapshot(definitions_root=root / "defs-reviewed")
            self.assertTrue(report["ok"], report)
            self.assertEqual(second["srlDefinitionPacks"]["definitionPackRevision"], report["srlDefinitionPackRevision"])


if __name__ == "__main__":
    unittest.main()

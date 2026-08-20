from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import common
import definitions_snapshot


class SecondaryDefinitionsTests(unittest.TestCase):
    def _build(self, root: Path, name: str, input_root: Path | None = None, asset_manifest: Path | None = None) -> dict:
        evidence = root / f"evidence-{name}"
        evidence.mkdir()
        output = root / f"definitions-{name}"
        return definitions_snapshot.build_snapshot(
            repo_root=common.ROOT,
            evidence_root=evidence,
            output=output,
            secondary_security_input=input_root,
            secondary_security_asset_manifest=asset_manifest,
        )

    @staticmethod
    def _write_reviewed_yara(root: Path, *, status: str = "enabled") -> None:
        yara = root / "yara"
        (root / "clamav").mkdir(parents=True, exist_ok=True)
        yara.mkdir(parents=True, exist_ok=True)
        policy = json.loads((common.ROOT / "security-definitions" / "yara" / "policy.json").read_text(encoding="utf-8"))
        (yara / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
        (yara / "fixture.yar").write_text("rule Fixture { condition: true }\n", encoding="utf-8")
        metadata = {
            "schema": "omega.sigmascope.yara-rule-metadata.v2",
            "ruleFile": "fixture.yar",
            "ruleNames": ["Fixture"],
            "status": status,
            "provenance": {"kind": "first-party-test", "source": "tools/tests/test_secondary_definitions.py"},
            "license": "test-only",
            "reviewedAtUtc": "2026-08-20T00:00:00Z",
            "reviewedRuleSha256": __import__("hashlib").sha256((yara / "fixture.yar").read_bytes()).hexdigest(),
            "reviewer": "unit-test",
            "ruleClass": "tooling",
            "confidence": "low",
            "falsePositiveExpectation": "high",
            "scope": "test fixture",
            "reviewNotes": "Synthetic always-true test rule; never production material.",
        }
        (yara / "fixture.yar.metadata.json").write_text(json.dumps(metadata), encoding="utf-8")

    @staticmethod
    def _fake_yara(root: Path) -> Path:
        bindir = root / "bin"
        bindir.mkdir(exist_ok=True)
        exe = bindir / "yara"
        exe.write_text("#!/bin/sh\necho 'YARA 4.test'\n", encoding="utf-8")
        exe.chmod(0o755)
        return bindir


    def test_repository_omega_core_rules_are_reviewed_and_enabled_as_four_files_fourteen_rules(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-yara-core-") as td:
            root = Path(td)
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                index = self._build(root, "omega-core")
            yara_summary = next(item for item in index["secondarySecurity"]["engines"] if item["engine"] == "yara")
            self.assertEqual("configured", yara_summary["status"])
            self.assertEqual(4, yara_summary["fileCount"])
            frozen = json.loads((root / "definitions-omega-core" / "secondary-security" / "index.json").read_text(encoding="utf-8"))
            yara_engine = next(item for item in frozen["engines"] if item["engine"] == "yara")
            self.assertEqual(14, yara_engine["enabledRuleCount"])
            self.assertTrue(all(item["enabled"] for item in yara_engine["files"]))
            for item in yara_engine["files"]:
                metadata = item["metadata"]
                self.assertEqual("omega.sigmascope.yara-rule-metadata.v2", metadata["schema"])
                self.assertEqual(item["sha256"], metadata["reviewedRuleSha256"])

    def test_yara_definition_change_invalidates_artifact_analysis_revision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-secondary-definitions-") as td:
            root = Path(td)
            empty = root / "empty"
            (empty / "yara").mkdir(parents=True)
            (empty / "clamav").mkdir(parents=True)
            baseline = self._build(root, "baseline", empty)

            configured = root / "configured"
            self._write_reviewed_yara(configured)
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                with_rule = self._build(root, "configured", configured)

            self.assertNotEqual(baseline["secondarySecurity"]["revision"], with_rule["secondarySecurity"]["revision"])
            self.assertNotEqual(baseline["artifactAnalysisRevision"], with_rule["artifactAnalysisRevision"])
            self.assertEqual("configured", with_rule["secondarySecurity"]["engines"][0]["status"])
            validation = definitions_snapshot.verify_snapshot(definitions_root=root / "definitions-configured")
            self.assertTrue(validation["ok"], validation["errors"])

    def test_secondary_definition_tampering_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-secondary-tamper-") as td:
            root = Path(td)
            configured = root / "configured"
            self._write_reviewed_yara(configured)
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                self._build(root, "tamper", configured)
            frozen_rule = root / "definitions-tamper" / "secondary-security" / "yara" / "fixture.yar"
            frozen_rule.write_text("rule Tampered { condition: true }\n", encoding="utf-8")
            validation = definitions_snapshot.verify_snapshot(definitions_root=root / "definitions-tamper")
            self.assertFalse(validation["ok"])
            self.assertTrue(any("secondary security definition" in item for item in validation["errors"]))

    def test_unreviewed_yara_rule_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-yara-policy-") as td:
            root = Path(td)
            configured = root / "configured"
            (configured / "yara").mkdir(parents=True)
            (configured / "clamav").mkdir(parents=True)
            (configured / "yara" / "fixture.yar").write_text("rule Fixture { condition: true }\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "policy.json"):
                self._build(root, "unreviewed", configured)



    def test_duplicate_rule_names_across_reviewed_files_fail_closed(self) -> None:
        import hashlib
        with tempfile.TemporaryDirectory(prefix="omega-yara-duplicate-names-") as td:
            root = Path(td)
            configured = root / "configured"
            self._write_reviewed_yara(configured)
            yara = configured / "yara"
            second = yara / "second.yar"
            second.write_text("rule Fixture { condition: false }\n", encoding="utf-8")
            metadata = {
                "schema": "omega.sigmascope.yara-rule-metadata.v2",
                "ruleFile": "second.yar", "ruleNames": ["Fixture"], "status": "enabled",
                "provenance": {"kind": "first-party-test", "source": "unit-test"},
                "license": "test-only", "reviewedAtUtc": "2026-08-20T00:00:00Z",
                "reviewedRuleSha256": hashlib.sha256(second.read_bytes()).hexdigest(),
                "reviewer": "unit-test", "ruleClass": "tooling", "confidence": "low",
                "falsePositiveExpectation": "high", "scope": "fixture",
                "reviewNotes": "duplicate-name fixture",
            }
            (yara / "second.yar.metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                with self.assertRaisesRegex(RuntimeError, "duplicated across files"):
                    self._build(root, "duplicate-names", configured)

    def test_enabled_yara_review_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-yara-review-hash-") as td:
            root = Path(td)
            configured = root / "configured"
            self._write_reviewed_yara(configured)
            metadata_path = configured / "yara" / "fixture.yar.metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["reviewedRuleSha256"] = "0" * 64
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                with self.assertRaisesRegex(RuntimeError, "reviewedRuleSha256"):
                    self._build(root, "hash-mismatch", configured)

    def test_metadata_rule_names_must_match_exact_rule_declarations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-yara-rule-names-") as td:
            root = Path(td)
            configured = root / "configured"
            self._write_reviewed_yara(configured)
            metadata_path = configured / "yara" / "fixture.yar.metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["ruleNames"] = ["DifferentRule"]
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                with self.assertRaisesRegex(RuntimeError, "ruleNames"):
                    self._build(root, "name-mismatch", configured)


if __name__ == "__main__":
    unittest.main()

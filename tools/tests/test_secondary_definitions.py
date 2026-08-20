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
            "schema": "omega.sigmascope.yara-rule-metadata.v1",
            "ruleFile": "fixture.yar",
            "ruleNames": ["Fixture"],
            "status": status,
            "provenance": {"kind": "first-party-test", "source": "tools/tests/test_secondary_definitions.py"},
            "license": "test-only",
            "reviewedAtUtc": "2026-08-20T00:00:00Z",
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


if __name__ == "__main__":
    unittest.main()

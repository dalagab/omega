from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import common  # noqa: F401
import secondary_security_assets as assets
import security_secondary_engines as secondary


class SecondarySecurityEngineTests(unittest.TestCase):
    def test_no_frozen_definitions_keeps_engines_disabled_and_evidence_only(self) -> None:
        artifact = b"omega-secondary-engine-fixture"
        digest = hashlib.sha256(artifact).hexdigest()
        result = secondary.scan_artifact_bytes(artifact, digest)
        self.assertEqual(secondary.SCHEMA, result["schema"])
        self.assertEqual(digest, result["artifactSha256"])
        self.assertEqual("supplemental-evidence-only", result["semantics"])
        self.assertEqual(0, result["matchCount"])
        self.assertEqual({"yara", "clamav"}, {item["engine"] for item in result["engines"]})
        self.assertTrue(all(item["status"] == "disabled" for item in result["engines"]))
        self.assertTrue(all(not item["enabled"] for item in result["engines"]))

    def test_artifact_hash_binding_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "artifact hash"):
            secondary.scan_artifact_bytes(b"different bytes", "0" * 64)

    def test_configured_rule_without_executable_is_reported_not_promoted_to_finding(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rule = Path(td) / "fixture.yar"
            rule.write_text('rule Fixture { condition: true }\n', encoding="utf-8")
            artifact = Path(td) / "artifact.bin"
            artifact.write_bytes(b"fixture")
            result = secondary.run_yara(artifact, [rule], executable="omega-yara-definitely-missing")
        self.assertEqual("unavailable", result["status"])
        self.assertTrue(result["enabled"])
        self.assertFalse(result["available"])
        self.assertEqual([], result["matches"])
        self.assertTrue(result["revision"].startswith("secondary-v1-"))

    def test_identity_pinned_yara_and_clamav_results_keep_provenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-secondary-success-") as td:
            root = Path(td)
            bindir = root / "bin"
            bindir.mkdir()
            yara = bindir / "yara"
            yara.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then echo 'YARA 4.test'; exit 0; fi\n"
                "echo 'FixtureRule artifact.bin'\n",
                encoding="utf-8",
            )
            yara.chmod(0o755)
            clamscan = bindir / "clamscan"
            clamscan.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then echo 'ClamAV test'; exit 0; fi\n"
                "echo 'artifact.bin: Test.Signature FOUND'\n"
                "exit 1\n",
                encoding="utf-8",
            )
            clamscan.chmod(0o755)
            rule = root / "fixture.yar"
            rule.write_text("rule FixtureRule { condition: true }\n", encoding="utf-8")
            dbdir = root / "clamav"
            dbdir.mkdir()
            database = dbdir / "main.cvd"
            database.write_bytes(b"database-fixture")
            artifact = b"artifact-fixture"
            digest = hashlib.sha256(artifact).hexdigest()
            metadata = {
                "ruleNames": ["FixtureRule"],
                "provenance": {"kind": "first-party-test", "source": "unit-test"},
                "license": "test-only",
                "falsePositiveExpectation": "low",
                "scope": "fixture",
            }
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                yara_identity = assets.executable_identity("yara")
                clamav_identity = assets.executable_identity("clamscan")
                result = secondary.scan_artifact_bytes(
                    artifact,
                    digest,
                    yara_rules=[rule],
                    clamav_databases=[database],
                    yara_executable_identity=yara_identity,
                    clamav_executable_identity=clamav_identity,
                    yara_policy_revision="policy-sha-fixture",
                    yara_rule_metadata=[metadata],
                )
            engines = {item["engine"]: item for item in result["engines"]}
            self.assertEqual("complete", engines["yara"]["status"])
            self.assertTrue(engines["yara"]["executableIdentity"]["verified"])
            self.assertEqual("FixtureRule", engines["yara"]["matches"][0]["rule"])
            self.assertEqual("first-party-test", engines["yara"]["matches"][0]["provenance"]["kind"])
            self.assertEqual("complete", engines["clamav"]["status"])
            self.assertTrue(engines["clamav"]["executableIdentity"]["verified"])
            self.assertEqual(2, result["matchCount"])


if __name__ == "__main__":
    unittest.main()

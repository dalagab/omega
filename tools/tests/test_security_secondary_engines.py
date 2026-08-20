from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
import zipfile
import io
from pathlib import Path
from unittest import mock

import common  # noqa: F401
import secondary_security_assets as assets
import security_secondary_engines as secondary
import sigmascope


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
                "for last; do :; done\n"
                "echo \"FixtureRule $last/0000-artifact.bin\"\n",
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
                "reviewedAtUtc": "2026-08-20T00:00:00Z",
                "reviewer": "unit-test",
                "reviewedRuleSha256": hashlib.sha256(rule.read_bytes()).hexdigest(),
                "ruleClass": "tooling",
                "confidence": "high",
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



    def test_reused_legacy_secondary_evidence_is_not_falsely_upgraded_to_contract_v3(self) -> None:
        base = {"artifactSha256": "a" * 64, "artifactBytes": 10, "resolvedArtifactUrl": "https://example.invalid/a.zip"}
        payload = {
            "artifactSha256": "a" * 64,
            "artifactBytes": 10,
            "resolvedArtifactUrl": "https://example.invalid/a.zip",
            "secondarySecurity": {
                "schema": secondary.SCHEMA, "artifactSha256": "a" * 64,
                "semantics": "supplemental-evidence-only", "engines": [], "matchCount": 0,
            },
        }
        sigmascope._apply_artifact_analysis(base, payload, "1.0.0", reused=True)
        self.assertEqual(2, base["secondarySecurityContractVersion"])

        fresh = dict(payload)
        fresh["secondarySecurityContractVersion"] = 3
        base2 = {"artifactSha256": "a" * 64, "artifactBytes": 10, "resolvedArtifactUrl": "https://example.invalid/a.zip"}
        sigmascope._apply_artifact_analysis(base2, fresh, "1.0.0", reused=False)
        self.assertEqual(3, base2["secondarySecurityContractVersion"])


    def test_yara_member_materialization_rejects_unsafe_archive_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-yara-unsafe-member-") as td:
            root = Path(td)
            bindir = root / "bin"
            bindir.mkdir()
            yara = bindir / "yara"
            yara.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then echo 'YARA 4.test'; exit 0; fi\n"
                "for last; do :; done\n"
                "echo \"FixtureRule $last/member-0001.dll\"\n",
                encoding="utf-8",
            )
            yara.chmod(0o755)
            rule = root / "fixture.yar"
            rule.write_text("rule FixtureRule { condition: true }\n", encoding="utf-8")
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("../escape.dll", b"should-never-materialize-by-name")
                archive.writestr("safe/Plugin.dll", b"safe-member")
            artifact = payload.getvalue()
            digest = hashlib.sha256(artifact).hexdigest()
            metadata = {
                "ruleNames": ["FixtureRule"],
                "provenance": {"kind": "first-party-test", "source": "unit-test"},
                "license": "test-only", "reviewedAtUtc": "2026-08-20T00:00:00Z",
                "reviewer": "unit-test", "reviewedRuleSha256": hashlib.sha256(rule.read_bytes()).hexdigest(),
                "ruleClass": "tooling", "confidence": "high", "falsePositiveExpectation": "low", "scope": "fixture",
            }
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                identity = assets.executable_identity("yara")
                result = secondary.scan_artifact_bytes(
                    artifact, digest, yara_rules=[rule], yara_executable_identity=identity,
                    yara_policy_revision="policy-fixture", yara_rule_metadata=[metadata],
                )
            engine = next(item for item in result["engines"] if item["engine"] == "yara")
            self.assertEqual(1, engine["scanScope"]["skipReasons"]["unsafe-path"])
            self.assertEqual(1, engine["scanScope"]["archiveMembersScanned"])
            self.assertEqual("safe/Plugin.dll", engine["matches"][0]["target"]["path"])

    def test_yara_scans_bounded_zip_members_and_attributes_match_to_original_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-yara-members-") as td:
            root = Path(td)
            bindir = root / "bin"
            bindir.mkdir()
            yara = bindir / "yara"
            yara.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then echo 'YARA 4.test'; exit 0; fi\n"
                "for last; do :; done\n"
                "if grep -aq 'omega-member-marker' \"$last/member-0001.dll\"; then echo \"FixtureRule $last/member-0001.dll\"; fi\n",
                encoding="utf-8",
            )
            yara.chmod(0o755)
            rule = root / "fixture.yar"
            rule.write_text("rule FixtureRule { condition: true }\n", encoding="utf-8")
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("Plugin.dll", b"omega-member-marker")
                archive.writestr("icon.png", b"not-interesting")
            artifact = payload.getvalue()
            digest = hashlib.sha256(artifact).hexdigest()
            metadata = {
                "ruleNames": ["FixtureRule"],
                "provenance": {"kind": "first-party-test", "source": "unit-test"},
                "license": "test-only",
                "reviewedAtUtc": "2026-08-20T00:00:00Z",
                "reviewer": "unit-test",
                "reviewedRuleSha256": hashlib.sha256(rule.read_bytes()).hexdigest(),
                "ruleClass": "tooling",
                "confidence": "high",
                "falsePositiveExpectation": "low",
                "scope": "fixture",
            }
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                identity = assets.executable_identity("yara")
                result = secondary.scan_artifact_bytes(
                    artifact, digest, yara_rules=[rule], yara_executable_identity=identity,
                    yara_policy_revision="policy-fixture", yara_rule_metadata=[metadata],
                )
            engine = next(item for item in result["engines"] if item["engine"] == "yara")
            self.assertEqual("complete", engine["status"])
            self.assertTrue(engine["scanScope"]["archiveDetected"])
            self.assertEqual(1, engine["scanScope"]["archiveMembersScanned"])
            self.assertEqual(1, engine["scanScope"]["skipReasons"]["non-code-resource"])
            self.assertEqual("archive-member", engine["matches"][0]["target"]["kind"])
            self.assertEqual("Plugin.dll", engine["matches"][0]["target"]["path"])
            self.assertEqual("high", engine["matches"][0]["confidence"])


if __name__ == "__main__":
    unittest.main()

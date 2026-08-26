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

    def test_capability_registry_is_frozen_as_first_class_definitions_payload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-capability-definitions-") as td:
            root = Path(td)
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                index = self._build(root, "capabilities")
            descriptor = index.get("capabilityRegistry") or {}
            self.assertEqual("omega.sigmascope.capability-registry.v1", descriptor.get("schema"))
            self.assertTrue(str(descriptor.get("revision") or "").startswith("capabilities-v1-"))
            self.assertEqual("capabilities/registry.json", descriptor.get("path"))
            self.assertGreaterEqual(int(descriptor.get("capabilityCount") or 0), 30)
            self.assertGreaterEqual(int(descriptor.get("categoryCount") or 0), 10)
            frozen = root / "definitions-capabilities" / "capabilities" / "registry.json"
            self.assertTrue(frozen.is_file())
            self.assertEqual(definitions_snapshot.sha256_file(frozen), descriptor.get("sha256"))
            validation = definitions_snapshot.verify_snapshot(definitions_root=root / "definitions-capabilities")
            self.assertTrue(validation["ok"], validation["errors"])


    def test_semantic_service_and_api_registries_are_frozen_first_class_payloads(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-semantic-definitions-") as td:
            root = Path(td)
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                index = self._build(root, "semantic-registries")
            service = index.get("serviceRegistry") or {}
            api = index.get("semanticApiRegistry") or {}
            self.assertEqual("omega.service-registry.v1", service.get("schema"))
            self.assertTrue(str(service.get("revision") or "").startswith("services-v1-"))
            self.assertEqual("semantic/service-registry.json", service.get("path"))
            self.assertGreaterEqual(int(service.get("serviceCount") or 0), 7)
            self.assertEqual("omega.semantic-api-registry.v1", api.get("schema"))
            self.assertTrue(str(api.get("revision") or "").startswith("semantic-apis-v1-"))
            self.assertEqual("semantic/api-registry.json", api.get("path"))
            self.assertGreaterEqual(int(api.get("sourceMatcherCount") or 0), 8)
            definitions = root / "definitions-semantic-registries"
            self.assertTrue((definitions / service["path"]).is_file())
            self.assertTrue((definitions / api["path"]).is_file())
            worker = definitions / "worker"
            self.assertTrue((worker / "security-definitions/services/registry.json").is_file())
            self.assertTrue((worker / "security-definitions/semantic-apis/registry.json").is_file())
            validation = definitions_snapshot.verify_snapshot(definitions_root=definitions)
            self.assertTrue(validation["ok"], validation["errors"])
            self.assertEqual(service["revision"], validation["serviceRegistryRevision"])
            self.assertEqual(api["revision"], validation["semanticApiRegistryRevision"])

    def test_semantic_registry_tampering_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-semantic-definitions-tamper-") as td:
            root = Path(td)
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                self._build(root, "semantic-tamper")
            definitions = root / "definitions-semantic-tamper"
            frozen = definitions / "semantic/service-registry.json"
            document = json.loads(frozen.read_text(encoding="utf-8"))
            document["services"][0]["purpose"] = "tampered"
            frozen.write_text(json.dumps(document), encoding="utf-8")
            validation = definitions_snapshot.verify_snapshot(definitions_root=definitions)
            self.assertFalse(validation["ok"])
            self.assertTrue(any("serviceRegistry" in item for item in validation["errors"]))

    def test_capability_registry_tampering_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-capability-definitions-tamper-") as td:
            root = Path(td)
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                self._build(root, "capability-tamper")
            frozen = root / "definitions-capability-tamper" / "capabilities" / "registry.json"
            document = json.loads(frozen.read_text(encoding="utf-8"))
            document["capabilities"][0]["description"] = "tampered"
            frozen.write_text(json.dumps(document), encoding="utf-8")
            validation = definitions_snapshot.verify_snapshot(definitions_root=root / "definitions-capability-tamper")
            self.assertFalse(validation["ok"])
            self.assertTrue(any("capability registry" in item for item in validation["errors"]))

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


    def test_component_and_collector_registries_are_frozen_as_platform_definitions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-platform-registries-") as td:
            root = Path(td)
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                index = self._build(root, "platform-registries")
                report = definitions_snapshot.verify_snapshot(definitions_root=root / "definitions-platform-registries")
            self.assertTrue(report["ok"], report.get("errors"))
            component = index["componentRegistry"]
            collector = index["collectorRegistry"]
            topology = index["executionTopology"]
            self.assertEqual("omega.component-registry.v1", component["schema"])
            self.assertEqual("omega.collector-registry.v1", collector["schema"])
            self.assertEqual("omega.execution-topology.v1", topology["schema"])
            self.assertTrue((root / "definitions-platform-registries" / component["path"]).is_file())
            self.assertTrue((root / "definitions-platform-registries" / collector["path"]).is_file())
            self.assertTrue((root / "definitions-platform-registries" / topology["path"]).is_file())
            self.assertGreaterEqual(component["componentCount"], 8)
            self.assertGreaterEqual(collector["collectorCount"], 16)
            self.assertGreaterEqual(topology["nodeCount"], 10)

    def test_platform_registry_tampering_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-platform-registry-tamper-") as td:
            root = Path(td)
            bindir = self._fake_yara(root)
            with mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}):
                index = self._build(root, "platform-tamper")
                target = root / "definitions-platform-tamper" / index["componentRegistry"]["path"]
                target.write_text('{}\n', encoding="utf-8")
                report = definitions_snapshot.verify_snapshot(definitions_root=root / "definitions-platform-tamper")
            self.assertFalse(report["ok"])
            self.assertTrue(any("componentRegistry" in error for error in report["errors"]), report["errors"])

if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import common  # noqa: F401
import analysis_broker
import authenticode_collector
import collector_evidence_adapter
import collector_evidence_audit
import collector_results
import definitions_snapshot
import observation_inventory
import security_evidence_v2
import srl
import srl_evidence_replay
from test_rule_reprojection import RuleReprojectionTests


class AuthenticodeCollectorTests(unittest.TestCase):
    def request(self) -> dict:
        return {
            "observation": "binarySignatureTrust",
            "subject": {"type": "variant", "variantId": 1, "artifactSha256": "a" * 64},
            "reason": "Collect exact Authenticode trust evidence.",
            "requestedBy": {"componentId": "omega.stigma-1", "ruleId": "fixture.authenticode"},
        }

    def valid_platform_record(self) -> dict:
        return {
            "schema": authenticode_collector.PROBE_SCHEMA,
            "status": "Valid",
            "statusMessage": "Signature verified.",
            "signer": {
                "subject": "CN=Example Publisher",
                "issuer": "CN=Example CA",
                "thumbprint": "AABB",
                "serialNumber": "1234",
                "notBeforeUtc": "2026-01-01T00:00:00Z",
                "notAfterUtc": "2027-01-01T00:00:00Z",
                "signatureAlgorithm": "1.2.840.113549.1.1.11",
                "publicKeyAlgorithm": "1.2.840.113549.1.1.1",
            },
            "timestamper": None,
        }

    def test_windows_status_is_projected_conservatively(self) -> None:
        row = authenticode_collector.observation_from_platform_record(
            artifact_sha256="a" * 64, path="plugin.dll", file_sha256="b" * 64,
            record=self.valid_platform_record(),
        )
        self.assertTrue(row["signaturePresent"])
        self.assertTrue(row["digestValid"])
        self.assertTrue(row["chainValid"])
        self.assertFalse(row["timestampPresent"])
        self.assertEqual("CN=Example Publisher", row["publisher"])
        self.assertEqual("valid", row["validationStatus"])

        not_trusted = dict(self.valid_platform_record())
        not_trusted["status"] = "NotTrusted"
        row = authenticode_collector.observation_from_platform_record(
            artifact_sha256="a" * 64, path="plugin.dll", file_sha256="b" * 64,
            record=not_trusted,
        )
        self.assertTrue(row["signaturePresent"])
        self.assertFalse(row["chainValid"])
        self.assertNotIn("digestValid", row)  # do not overclaim from platform status alone


    def test_standalone_pe_obeys_same_per_file_bound_as_zip_members(self) -> None:
        with mock.patch.object(authenticode_collector, "MAX_PE_FILE_BYTES", 4):
            with self.assertRaisesRegex(ValueError, "Standalone PE exceeds"):
                authenticode_collector._archive_pe_members(b"MZabc")

    def test_probe_preserves_safe_pe_suffix_for_windows_file_type_handling(self) -> None:
        self.assertEqual(".dll", authenticode_collector._probe_suffix("native/helper.DLL"))
        self.assertEqual(".exe", authenticode_collector._probe_suffix("tool.exe"))
        self.assertEqual(".bin", authenticode_collector._probe_suffix("artifact"))

    def test_authenticode_probe_is_part_of_frozen_worker_bundle(self) -> None:
        files = definitions_snapshot.worker_bundle_files(common.ROOT)
        self.assertIn("tools/security/authenticode_probe.ps1", files)
        self.assertIn("tools/security/authenticode_collector.py", files)
        self.assertIn("tools/security/collector_results.py", files)
        self.assertIn("tools/security/collector_evidence_adapter.py", files)
        self.assertIn("tools/security/collector_evidence_audit.py", files)

    def test_generic_result_is_content_addressed_and_tamper_detecting(self) -> None:
        row = authenticode_collector.observation_from_platform_record(
            artifact_sha256="a" * 64, path="plugin.dll", file_sha256="b" * 64,
            record=self.valid_platform_record(),
        )
        result = collector_results.build_result(
            self.request(), collector_id=authenticode_collector.COLLECTOR_ID,
            collections={"binarySignatureTrust": [row]}, work_item_id="work-1",
            generated_at_utc="2026-08-25T18:00:00Z",
        )
        self.assertEqual("complete", collector_results.validate_result(result)["status"])
        tampered = json.loads(json.dumps(result))
        tampered["collections"]["binarySignatureTrust"]["rows"][0]["publisher"] = "CN=Other"
        with self.assertRaisesRegex(ValueError, "does not reproduce"):
            collector_results.validate_result(tampered)

    def test_result_ingests_into_evidence_inventory_and_srl(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-auth-evidence-") as td:
            root = Path(td)
            helper = RuleReprojectionTests("test_compatible_retained_observations_reproject_without_legacy_findings")
            current = helper.evidence(root)
            row = authenticode_collector.observation_from_platform_record(
                artifact_sha256="a" * 64, path="plugin.dll", file_sha256="b" * 64,
                record=self.valid_platform_record(),
            )
            result = collector_results.build_result(
                self.request(), collector_id=authenticode_collector.COLLECTOR_ID,
                collections={"binarySignatureTrust": [row]}, work_item_id="work-1",
                generated_at_utc="2026-08-25T18:00:00Z",
            )
            result_path = root / "result.json"
            result_path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            candidate = root / "candidate"
            ingestion = collector_evidence_adapter.ingest(current, candidate, result_path)
            self.assertEqual(["binarySignatureTrust"], ingestion["observations"])
            audit = collector_evidence_audit.audit(current, candidate, result_path)
            self.assertTrue(audit["ok"], audit)

            inventory = observation_inventory.build_inventory(candidate, generated_at="2026-08-25T18:01:00Z")
            matches = [item for item in inventory["records"] if item["observation"] == "binarySignatureTrust"]
            self.assertEqual(1, len(matches))
            self.assertEqual(authenticode_collector.COLLECTOR_ID, matches[0]["collectorId"])

            entry, payload = next(iter(security_evidence_v2.iter_variant_entries(candidate)))
            analysis_path = str((payload.get("analysis") or {}).get("path") or "")
            observations = srl_evidence_replay._load_observations(
                candidate, analysis_path, ["binarySignatureTrust"], variant_payload=payload,
            )
            self.assertEqual("CN=Example Publisher", observations["binarySignatureTrust"][0]["publisher"])
            ruleset = srl.compile_ruleset({
                "schema": "omega.sigmascope.ruleset.v1",
                "rules": [{
                    "schema": "omega.sigmascope.rule.v1",
                    "id": "fixture.signed.publisher",
                    "kind": "observation",
                    "status": "experimental",
                    "requires": ["binarySignatureTrust"],
                    "selectors": {"signed": {"collection": "binarySignatureTrust", "where": {"chainValid": {"equals": True}}}},
                    "condition": "signed",
                    "emit": {"fact": "fixture.signature-chain-valid", "title": "Valid platform signature chain", "confidence": "high"},
                }],
            })
            evaluation = srl.evaluate_ruleset(ruleset, observations, observation_contract=payload["observations"])
            self.assertTrue(evaluation["evaluated"], evaluation)
            self.assertIn("fixture.signature-chain-valid", evaluation["facts"])

    def test_exact_artifact_binding_is_required(self) -> None:
        request = self.request()
        request["subject"] = {"type": "variant", "variantId": 1}
        with tempfile.TemporaryDirectory(prefix="omega-auth-resolve-") as td:
            root = Path(td)
            helper = RuleReprojectionTests("test_compatible_retained_observations_reproject_without_legacy_findings")
            evidence = helper.evidence(root)
            with self.assertRaisesRegex(ValueError, r"variantId \+ subject.artifactSha256"):
                authenticode_collector.resolve_request(evidence, request)


if __name__ == "__main__":
    unittest.main()

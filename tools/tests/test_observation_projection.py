from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import observation_projection as op


class ObservationProjectionTests(unittest.TestCase):
    def test_contract_classifies_observations_away_from_legacy_projections(self) -> None:
        datasets = {
            "calls": {"records": 2, "recordDigest": "a" * 64, "files": []},
            "findings": {"records": 1, "recordDigest": "b" * 64, "files": []},
            "permissions": {"records": 1, "recordDigest": "c" * 64, "files": []},
        }
        annotated = op.annotate_analysis_datasets(datasets)
        self.assertEqual("managedCallSites", annotated["calls"]["collection"])
        self.assertTrue(annotated["calls"]["srlEligible"])
        self.assertEqual("projection", annotated["findings"]["semanticClass"])
        self.assertFalse(annotated["findings"]["srlEligible"])
        self.assertFalse(annotated["permissions"]["srlEligible"])
        contract = op.analysis_observation_contract(datasets)
        self.assertIn("managedCallSites", contract["collections"])
        self.assertNotIn("findings", contract["collections"])
        self.assertNotIn("permissionCandidates", contract["collections"])

    def test_report_observation_rows_exclude_conclusions(self) -> None:
        report = {
            "findings": [{"ruleId": "network.http"}],
            "capabilityIds": ["network.http"],
            "automation": {"capabilities": [{"capabilityId": "automation.action.invoke"}]},
            "behaviorConsistency": {"summary": {"observedUndeclaredCount": 1}},
            "dependencyIntelligence": {
                "nativeImports": [{"library": "kernel32", "entryPoint": "CreateProcessW"}],
                "networkEndpoints": [{"host": "api.example.test", "url": "https://api.example.test"}],
                "staticPatternMatches": [{"origin": "artifact", "pattern": "HttpWebRequest", "evidenceLabel": "metadata:Fixture.dll", "evidence": ["metadata:Fixture.dll: HttpWebRequest"]}],
            },
            "source": {
                "developerProfile": {"schema": "omega.plugin-profile-observation.v1", "status": "valid"},
                "attribution": {"confidence": 70},
                "provenance": {"identityMatched": True},
            },
        }
        rows = op.report_observation_rows(report)
        self.assertEqual("CreateProcessW", rows["nativeImports"][0]["entryPoint"])
        self.assertEqual("api.example.test", rows["networkEndpoints"][0]["host"])
        self.assertEqual("HttpWebRequest", rows["staticPatternMatches"][0]["pattern"])
        flat = json.dumps(rows, sort_keys=True)
        self.assertNotIn("network.http", flat)
        self.assertNotIn("behaviorConsistency", flat)
        self.assertNotIn("automation.action.invoke", flat)

    def test_legacy_compact_endpoint_is_marked_bounded_not_exact(self) -> None:
        report = {
            "schema": "omega.security-evidence.scan-summary.v2",
            "intelligence": {"networkEndpoints": [{"host": "api.example.test", "url": "https://api.example.test"}]},
        }
        contract = op.build_variant_observation_contract({}, report)
        endpoint = contract["collections"]["networkEndpoints"]
        self.assertEqual("bounded-transport", endpoint["completeness"])
        audit = op.replay_audit(contract, ["networkEndpoints"])
        self.assertFalse(audit["reusableWithoutRescan"])
        self.assertEqual(["networkEndpoints"], audit["boundedCompatibilityCollections"])

    def test_full_retained_endpoint_dataset_allows_replay(self) -> None:
        manifest = {
            "datasets": {
                "networkEndpoints": {"records": 2, "recordDigest": "d" * 64, "files": []},
                "calls": {"records": 4, "recordDigest": "e" * 64, "files": []},
            }
        }
        contract = op.build_variant_observation_contract(manifest, {})
        audit = op.replay_audit(contract, ["networkEndpoints", "managedCallSites"])
        self.assertTrue(audit["reusableWithoutRescan"])
        self.assertFalse(audit["rescanRequired"])

    def test_derived_inputs_are_forbidden_for_future_srl(self) -> None:
        contract = op.build_variant_observation_contract({"datasets": {}}, {})
        audit = op.replay_audit(contract, ["behaviorConsistency", "permissionCandidates"])
        self.assertFalse(audit["reusableWithoutRescan"])
        self.assertEqual(["behaviorConsistency", "permissionCandidates"], audit["forbiddenDerivedInputs"])

    def test_projection_identity_changes_with_rules_not_observation_content(self) -> None:
        report_a = {
            "scannerVersion": "2.15.0",
            "scanProvenance": {"ruleSetRevision": "rules-a"},
            "capabilityRegistryRevision": "caps-a",
            "capabilityIds": ["network.http"],
        }
        report_b = {**report_a, "capabilityIds": ["filesystem.write"]}
        self.assertEqual(op.projection_revision(report_a), op.projection_revision(report_b))
        report_c = {**report_a, "scanProvenance": {"ruleSetRevision": "rules-b"}}
        self.assertNotEqual(op.projection_revision(report_a), op.projection_revision(report_c))

    def test_contract_validation_reproduces_variant_identity(self) -> None:
        manifest = {"datasets": {"calls": {"records": 1, "recordDigest": "f" * 64, "files": []}}}
        report = {"scanProvenance": {"ruleSetRevision": "rules-a"}}
        variant = {
            "current": {"report_json": report},
            "observations": op.build_variant_observation_contract(manifest, report),
            "projection": op.build_projection_descriptor(manifest, report),
        }
        self.assertEqual([], op.validation_errors(variant, manifest))
        variant["observations"]["observationDigest"] = "tampered"
        self.assertIn("observation contract digest is not reproducible", op.validation_errors(variant, manifest))

    def test_additive_registry_growth_keeps_prior_v1_evidence_valid(self) -> None:
        manifest = {"datasets": {"calls": {"records": 1, "recordDigest": "f" * 64, "files": []}}}
        report = {"scanProvenance": {"ruleSetRevision": "rules-a"}}
        observations = op.build_variant_observation_contract(manifest, report)
        self.assertNotEqual("observations-v1-16863eebb61bc136", observations["contractRevision"])
        observations["contractRevision"] = "observations-v1-16863eebb61bc136"
        variant = {"current": {"report_json": report}, "observations": observations}
        self.assertEqual([], op.validation_errors(variant, manifest))

        observations["contractRevision"] = "observations-v2-deadbeefdeadbeef"
        self.assertIn("observation contract revision is invalid", op.validation_errors(variant, manifest))


if __name__ == "__main__":
    unittest.main()

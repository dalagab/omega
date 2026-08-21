from __future__ import annotations

import json
import subprocess
import sys
import unittest

import common

SECURITY = common.ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))
import rule_author_reference


class RuleAuthorReferenceTests(unittest.TestCase):
    def test_reference_exposes_real_typed_collections_and_registry(self) -> None:
        reference = rule_author_reference.build_reference()
        self.assertEqual("omega.deltascope.rule-author-reference.v1", reference["schema"])
        self.assertFalse(reference["productionRuleEvaluationEnabled"])
        self.assertIn("managedCallSites", reference["collections"])
        self.assertIn("developerProfile", reference["collections"])
        self.assertGreaterEqual(len(reference["capabilityRegistry"]["capabilities"]), 30)

    def test_same_record_and_non_executable_boundaries_are_explicit(self) -> None:
        reference = rule_author_reference.build_reference()
        self.assertTrue(reference["sameRecordSemantics"])
        self.assertIn("raw SQL", reference["forbiddenRuleActions"])
        self.assertIn("network requests", reference["forbiddenRuleActions"])

    def test_deltascope_observation_schema_cli_is_machine_readable(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(common.ROOT / "tools" / "security" / "deltascope.py"), "observation-schema"],
            cwd=common.ROOT, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual("omega.deltascope.observation-reference.v1", payload["schema"])
        self.assertIn("networkEndpoints", payload["collections"])
        self.assertTrue(payload["collections"]["managedCallSites"]["srlEligible"])
        self.assertFalse(payload["legacyProjectionDatasets"]["findings"]["srlEligible"])

    def test_deltascope_rule_schema_cli_is_machine_readable(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(common.ROOT / "tools" / "security" / "deltascope.py"), "rule-schema"],
            cwd=common.ROOT, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual("omega.deltascope.rule-author-reference.v1", payload["schema"])
        self.assertFalse(payload["productionRuleEvaluationEnabled"])
        self.assertEqual("omega.sigmascope.srl-engine.v1", payload["srlEngine"]["schema"])
        self.assertTrue(payload["srlEngine"]["compilerAvailable"])
        self.assertTrue(payload["srlEngine"]["evaluatorAvailable"])
        self.assertIn("managedCallSites", payload["srlEngine"]["typedCollections"])


if __name__ == "__main__":
    unittest.main()

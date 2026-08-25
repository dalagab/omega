from __future__ import annotations

import json
import sys
import unittest

import common

SECURITY = common.ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))
import rule_author_reference
import observation_projection
import srl


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

    def test_published_observation_reference_is_machine_readable(self) -> None:
        payload = json.loads(json.dumps(observation_projection.build_schema_reference(), sort_keys=True))
        self.assertEqual("omega.deltascope.observation-reference.v1", payload["schema"])
        self.assertIn("networkEndpoints", payload["collections"])
        self.assertTrue(payload["collections"]["managedCallSites"]["srlEligible"])
        self.assertFalse(payload["legacyProjectionDatasets"]["findings"]["srlEligible"])

    def test_published_rule_and_engine_references_are_machine_readable(self) -> None:
        payload = json.loads(json.dumps(rule_author_reference.build_reference(), sort_keys=True))
        engine = json.loads(json.dumps(srl.engine_reference(), sort_keys=True))
        self.assertEqual("omega.deltascope.rule-author-reference.v1", payload["schema"])
        self.assertFalse(payload["productionRuleEvaluationEnabled"])
        self.assertEqual("omega.sigmascope.srl-engine.v1", engine["schema"])
        self.assertTrue(engine["compilerAvailable"])
        self.assertTrue(engine["evaluatorAvailable"])
        self.assertIn("managedCallSites", engine["typedCollections"])


if __name__ == "__main__":
    unittest.main()

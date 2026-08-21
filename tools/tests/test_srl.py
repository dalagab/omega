from __future__ import annotations

from pathlib import Path
import sys
import subprocess
import json
import unittest

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import observation_projection as op
import srl


PROCESS_RULE = """
schema: omega.sigmascope.rule.v1
id: capability.process.execute
kind: observation
status: reviewed
requires: [managedCallSites]
selectors:
  process_start:
    collection: managedCallSites
    where:
      targetDeclaringType:
        equals-ci: System.Diagnostics.Process
      targetName:
        in-ci: [Start]
condition:
  any: [process_start]
emit:
  fact: process.execute
  confidence: high
  title: Process execution capability
"""

NETWORK_RULE = """
schema: omega.sigmascope.rule.v1
id: capability.network.http
kind: observation
status: reviewed
requires: [networkEndpoints]
selectors:
  concrete_http:
    collection: networkEndpoints
    where:
      concreteDestinationEvidence:
        equals: true
condition: concrete_http
emit:
  fact: network.http
  confidence: high
  title: Concrete network destination
"""

CORRELATION_RULE = """
schema: omega.sigmascope.rule.v1
id: compound.network-execute
kind: correlation
status: reviewed
requires: []
selectors:
  network:
    facts:
      any: [network.http, network.socket]
  execute:
    facts:
      any: [process.execute, shell.powershell]
condition:
  all: [network, execute]
emit:
  findingId: compound.network-execute
  title: Network plus process execution
  description: Static evidence contains outbound network and process execution capabilities.
  severity: high
  category: behavior
"""


class SRLTests(unittest.TestCase):
    def test_engine_reference_is_non_executable_and_not_production_enabled(self) -> None:
        ref = srl.engine_reference()
        self.assertEqual("omega.sigmascope.srl-engine.v1", ref["schema"])
        self.assertFalse(ref["productionRuleEvaluationEnabled"])
        self.assertTrue(ref["compilerAvailable"])
        self.assertTrue(ref["evaluatorAvailable"])
        self.assertIn("managedCallSites", ref["typedCollections"])
        self.assertNotIn("behaviorConsistency", ref["typedCollections"])

    def test_compile_process_rule_is_deterministic(self) -> None:
        a = srl.compile_yaml_text(PROCESS_RULE)
        b = srl.compile_yaml_text(PROCESS_RULE.replace("status: reviewed", "status: reviewed\n"))
        self.assertEqual(a["ruleSetRevision"], b["ruleSetRevision"])
        self.assertEqual(a["rules"][0]["ruleRevision"], b["rules"][0]["ruleRevision"])

    def test_observation_rule_matches_same_call_row_and_emits_fact(self) -> None:
        compiled = srl.compile_yaml_text(PROCESS_RULE)
        observations = {
            "managedCallSites": [
                {"targetDeclaringType": "System.Diagnostics.Process", "targetName": "Start", "origin": "artifact"}
            ]
        }
        result = srl.evaluate_ruleset(compiled, observations)
        self.assertTrue(result["evaluated"])
        self.assertEqual(["process.execute"], result["facts"])
        self.assertTrue(result["rules"][0]["matched"])
        self.assertEqual(1, result["rules"][0]["selectors"][0]["matchCount"])

    def test_same_record_semantics_prevent_cross_row_join(self) -> None:
        compiled = srl.compile_yaml_text(PROCESS_RULE)
        observations = {
            "managedCallSites": [
                {"targetDeclaringType": "System.Diagnostics.Process", "targetName": "Kill"},
                {"targetDeclaringType": "Other.Type", "targetName": "Start"},
            ]
        }
        result = srl.evaluate_ruleset(compiled, observations)
        self.assertEqual([], result["facts"])
        self.assertFalse(result["rules"][0]["matched"])

    def test_boolean_equals_and_fact_correlation(self) -> None:
        doc = {
            "schema": srl.RULESET_SCHEMA,
            "rules": [srl.parse_yaml_text(PROCESS_RULE), srl.parse_yaml_text(NETWORK_RULE), srl.parse_yaml_text(CORRELATION_RULE)],
        }
        compiled = srl.compile_ruleset(doc)
        result = srl.evaluate_ruleset(compiled, {
            "managedCallSites": [{"targetDeclaringType": "System.Diagnostics.Process", "targetName": "Start"}],
            "networkEndpoints": [{"host": "api.example.test", "concreteDestinationEvidence": True}],
        })
        self.assertEqual(["network.http", "process.execute"], result["facts"])
        self.assertEqual(1, len(result["findings"]))
        self.assertEqual("compound.network-execute", result["findings"][0]["findingId"])

    def test_fact_only_correlation_accepts_empty_requires(self) -> None:
        compiled = srl.compile_yaml_text(CORRELATION_RULE)
        result = srl.evaluate_ruleset(compiled, {}, initial_facts=["network.http", "process.execute"])
        self.assertTrue(result["evaluated"])
        self.assertEqual(1, len(result["findings"]))

    def test_count_condition_uses_selector_match_count(self) -> None:
        text = """
schema: omega.sigmascope.rule.v1
id: correlation.multiple-destinations
kind: correlation
requires: [networkEndpoints]
selectors:
  concrete:
    collection: networkEndpoints
    where:
      concreteDestinationEvidence: {equals: true}
condition:
  count: {selector: concrete, gte: 2}
emit:
  title: Multiple concrete destinations
  findingId: correlation.multiple-destinations
"""
        compiled = srl.compile_yaml_text(text)
        result = srl.evaluate_ruleset(compiled, {"networkEndpoints": [
            {"concreteDestinationEvidence": True, "host": "a.test"},
            {"concreteDestinationEvidence": True, "host": "b.test"},
        ]})
        self.assertEqual(1, len(result["findings"]))

    def test_repeated_array_fields_use_same_element(self) -> None:
        text = """
schema: omega.sigmascope.rule.v1
id: consistency.not-expected-process
kind: correlation
requires: [developerProfile]
selectors:
  declaration:
    collection: developerProfile
    where:
      capabilities[].id: {equals: process.execute}
      capabilities[].expected: {equals: false}
condition: declaration
emit:
  title: Developer marks process execution not expected
"""
        compiled = srl.compile_yaml_text(text)
        bad_cross_join = {"developerProfile": [{"capabilities": [
            {"id": "process.execute", "expected": True},
            {"id": "network.http", "expected": False},
        ]}]}
        self.assertEqual([], srl.evaluate_ruleset(compiled, bad_cross_join)["findings"])
        same = {"developerProfile": [{"capabilities": [{"id": "process.execute", "expected": False}]}]}
        self.assertEqual(1, len(srl.evaluate_ruleset(compiled, same)["findings"]))

    def test_compile_rejects_derived_collection(self) -> None:
        bad = PROCESS_RULE.replace("managedCallSites", "behaviorConsistency")
        with self.assertRaises(srl.SRLCompileError):
            srl.compile_yaml_text(bad)

    def test_compile_rejects_unknown_field_and_operator(self) -> None:
        with self.assertRaisesRegex(srl.SRLCompileError, "unknown field"):
            srl.compile_yaml_text(PROCESS_RULE.replace("targetName:", "imaginaryField:"))
        with self.assertRaisesRegex(srl.SRLCompileError, "unknown operator"):
            srl.compile_yaml_text(PROCESS_RULE.replace("equals-ci:", "regex:"))

    def test_compile_rejects_missing_or_unused_requires(self) -> None:
        with self.assertRaisesRegex(srl.SRLCompileError, "requires is missing"):
            srl.compile_yaml_text(PROCESS_RULE.replace("requires: [managedCallSites]", "requires: []"))
        with self.assertRaisesRegex(srl.SRLCompileError, "unused"):
            srl.compile_yaml_text(PROCESS_RULE.replace("requires: [managedCallSites]", "requires: [managedCallSites, networkEndpoints]"))

    def test_yaml_rejects_aliases_tags_and_duplicate_keys(self) -> None:
        with self.assertRaises(srl.SRLParseError):
            srl.parse_yaml_text("x: &a [1]\ny: *a\n")
        with self.assertRaises(srl.SRLParseError):
            srl.parse_yaml_text("x: !!python/object:os.system {}\n")
        with self.assertRaises(srl.SRLParseError):
            srl.parse_yaml_text("x: 1\nx: 2\n")

    def test_historical_bounded_collection_blocks_exact_replay(self) -> None:
        compiled = srl.compile_yaml_text(NETWORK_RULE)
        contract = op.build_variant_observation_contract({}, {
            "schema": "omega.security-evidence.scan-summary.v2",
            "intelligence": {"networkEndpoints": [{"host": "x.test", "concreteDestinationEvidence": True}]},
        })
        result = srl.evaluate_ruleset(compiled, {"networkEndpoints": [{"host": "x.test", "concreteDestinationEvidence": True}]}, observation_contract=contract)
        self.assertFalse(result["evaluated"])
        self.assertEqual(["networkEndpoints"], result["replayAudit"]["boundedCompatibilityCollections"])

    def test_fixture_positive_and_negative(self) -> None:
        compiled = srl.compile_yaml_text(PROCESS_RULE)
        fixture = {
            "schema": srl.FIXTURE_SCHEMA,
            "name": "process positive",
            "observations": {"managedCallSites": [{"targetDeclaringType": "System.Diagnostics.Process", "targetName": "Start"}]},
            "expected": {"facts": ["process.execute"], "matchedRules": ["capability.process.execute"]},
        }
        result = srl.run_fixture(compiled, fixture)
        self.assertTrue(result["passed"], result["failures"])
        fixture["expected"] = {"facts": []}
        result = srl.run_fixture(compiled, fixture)
        self.assertFalse(result["passed"])

    def test_disabled_rule_never_emits(self) -> None:
        compiled = srl.compile_yaml_text(PROCESS_RULE.replace("status: reviewed", "status: disabled"))
        result = srl.evaluate_ruleset(compiled, {"managedCallSites": [{"targetDeclaringType": "System.Diagnostics.Process", "targetName": "Start"}]})
        self.assertTrue(result["rules"][0]["matched"])
        self.assertEqual([], result["facts"])

    def test_deltascope_rule_compile_cli_uses_srl_v1(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "security" / "deltascope.py"), "rule-compile",
             "--rule", str(ROOT / "docs" / "rule-authors" / "examples" / "process-network-rules.yaml")],
            cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(srl.COMPILED_RULESET_SCHEMA, payload["schema"])
        self.assertEqual(3, len(payload["rules"]))

    def test_deltascope_rule_test_cli_passes_shipped_fixture(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "security" / "deltascope.py"), "rule-test",
             "--rule", str(ROOT / "docs" / "rule-authors" / "examples" / "process-network-rules.yaml"),
             "--fixture", str(ROOT / "docs" / "rule-authors" / "examples" / "process-network-positive.fixture.yaml")],
            cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["passed"])


    def test_ruleset_rejects_duplicate_rule_id_and_duplicate_fact_emitter(self) -> None:
        rule = srl.parse_yaml_text(PROCESS_RULE)
        with self.assertRaisesRegex(srl.SRLCompileError, "duplicate rule IDs"):
            srl.compile_ruleset({"schema": srl.RULESET_SCHEMA, "rules": [rule, dict(rule)]})
        second = dict(rule)
        second["id"] = "capability.process.execute.other"
        with self.assertRaisesRegex(srl.SRLCompileError, "emitted by both"):
            srl.compile_ruleset({"schema": srl.RULESET_SCHEMA, "rules": [rule, second]})


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import unittest
import zipfile
import threading
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import observation_projection  # noqa: E402
import rule_lab  # noqa: E402
import developer_view  # noqa: E402


RULESET = """schema: omega.sigmascope.ruleset.v1
rules:
  - schema: omega.sigmascope.rule.v1
    id: candidate.http
    kind: observation
    status: experimental
    requires: [staticPatternMatches]
    selectors:
      http:
        collection: staticPatternMatches
        where:
          pattern:
            starts-with-ci: http
    condition: http
    emit:
      fact: candidate.network.http
      confidence: medium
      title: HTTP literal
  - schema: omega.sigmascope.rule.v1
    id: candidate.http-review
    kind: correlation
    status: experimental
    requires: []
    selectors:
      network:
        facts:
          any: [candidate.network.http]
    condition: network
    emit:
      findingId: candidate.http-review
      title: HTTP candidate review
      description: candidate finding
      severity: caution
      category: behavior
"""


class FakeInspector:
    def __init__(self, *, complete: bool = True, with_match: bool = True) -> None:
        self.complete = complete
        self.with_match = with_match

    def plugin_detail(self, variant_id: int):
        collections = {}
        if self.complete:
            collections["staticPatternMatches"] = {"completeness": "retained"}
        return {
            "identity": {"variant_id": variant_id, "canonical_name": f"Fixture {variant_id}", "internal_name": f"Fixture{variant_id}"},
            "observations": {"contractRevision": observation_projection.contract_revision(), "collections": collections},
            "findings": [],
        }

    def plugin_dataset(self, variant_id: int, name: str):
        if name == "staticPatternMatches":
            return ([{"origin": "artifact", "pattern": "https://", "evidenceLabel": "fixture", "evidence": "fixture.dll"}]
                    if self.with_match else [])
        if name == "findings":
            return []
        raise ValueError(name)

    def list_plugins(self, q="", severity="", status="", known_risk=False, limit=300, offset=0):
        return [{"variant_id": i} for i in range(1, min(limit, 3) + 1)]


class RuleLabTests(unittest.TestCase):
    def test_valid_candidate_compiles_without_writeback(self) -> None:
        result = rule_lab.compile_candidate_text(RULESET)
        self.assertTrue(result["ok"])
        self.assertFalse(result["productionWriteBack"])
        self.assertEqual(["staticPatternMatches"], result["requiredCollections"])
        self.assertEqual(["candidate.http-review"], result["findingIds"])

    def test_yaml_anchor_is_rejected_as_parse_diagnostic(self) -> None:
        result = rule_lab.compile_candidate_text("a: &x 1\nb: *x\n")
        self.assertFalse(result["ok"])
        self.assertEqual("parse", result["diagnostics"][0]["stage"])


    def test_observation_only_candidate_does_not_report_unrelated_baseline_findings_removed(self) -> None:
        observation_only = rule_lab.DEFAULT_EXAMPLE
        baseline = [{"ruleId": "legacy.other", "findingId": "legacy.other", "severity": "high", "category": "x", "title": "Other"}]
        diff = rule_lab.diff_findings(baseline, [], include_ids=[])
        self.assertTrue(diff["clean"])
        self.assertEqual(0, diff["baselineCount"])
        self.assertTrue(rule_lab.compile_candidate_text(observation_only)["ok"])

    def test_finding_diff_reports_added_removed_and_changed(self) -> None:
        baseline = [
            {"ruleId": "a", "findingId": "a", "severity": "caution", "category": "x", "title": "A", "description": "old", "evidence": []},
            {"ruleId": "b", "findingId": "b", "severity": "high", "category": "x", "title": "B", "description": "same", "evidence": []},
        ]
        candidate = [
            {"ruleId": "a", "findingId": "a", "severity": "high", "category": "x", "title": "A", "description": "new", "evidence": []},
            {"ruleId": "c", "findingId": "c", "severity": "caution", "category": "x", "title": "C", "description": "new", "evidence": []},
        ]
        diff = rule_lab.diff_findings(baseline, candidate)
        self.assertFalse(diff["clean"])
        self.assertEqual(1, len(diff["added"]))
        self.assertEqual(1, len(diff["removed"]))
        self.assertEqual(1, len(diff["changed"]))
        self.assertEqual(["severity", "description"], diff["changed"][0]["changedFields"])

    def test_variant_dry_run_uses_retained_observations_and_explains_selectors(self) -> None:
        result = rule_lab.evaluate_variant(FakeInspector(), RULESET, 7)
        self.assertTrue(result["ok"])
        self.assertTrue(result["evaluation"]["evaluated"])
        self.assertIn("candidate.network.http", result["evaluation"]["facts"])
        self.assertEqual(["candidate.http-review"], [x["findingId"] for x in result["evaluation"]["findings"]])
        matched = [r for r in result["explanation"]["rules"] if r["matched"]]
        self.assertEqual(2, len(matched))
        self.assertEqual(1, matched[0]["selectors"][0]["matchCount"])
        self.assertFalse(result["productionWriteBack"])

    def test_missing_required_retained_collection_is_rescan_not_negative(self) -> None:
        result = rule_lab.evaluate_variant(FakeInspector(complete=False), RULESET, 8)
        self.assertTrue(result["ok"])
        self.assertFalse(result["evaluation"]["evaluated"])
        self.assertTrue(result["evaluation"]["replayAudit"]["rescanRequired"])

    def test_exact_fixture_round_trip_passes(self) -> None:
        built = rule_lab.build_fixture(FakeInspector(), RULESET, 9, name="round trip")
        self.assertTrue(built["ok"])
        tested = rule_lab.test_fixture_text(RULESET, built["fixtureYaml"])
        self.assertTrue(tested["ok"])
        self.assertTrue(tested["result"]["passed"])

    def test_fixture_negative_is_explicit_complete_empty_observation(self) -> None:
        built = rule_lab.build_fixture(FakeInspector(with_match=False), RULESET, 10, name="negative")
        self.assertTrue(built["ok"])
        fixture = built["fixture"]
        self.assertEqual([], fixture["observations"]["staticPatternMatches"])
        self.assertEqual([], fixture["expected"]["findingIds"])

    def test_export_bundle_is_deterministic_and_hash_pinned(self) -> None:
        fixture = rule_lab.build_fixture(FakeInspector(), RULESET, 11)["fixtureYaml"]
        first, manifest1 = rule_lab.build_export_bundle(RULESET, fixture_text=fixture, notes="candidate note")
        second, manifest2 = rule_lab.build_export_bundle(RULESET, fixture_text=fixture, notes="candidate note")
        self.assertEqual(first, second)
        self.assertEqual(manifest1, manifest2)
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            names = set(archive.namelist())
            self.assertEqual({"MANIFEST.json", "README.md", "candidate.json", "candidate.yaml", "fixture.yaml"}, names)
            descriptor = json.loads(archive.read("candidate.json"))
            self.assertFalse(descriptor["productionWriteBack"])
            self.assertIn("none", descriptor["promotionAuthority"])

    def test_export_rejects_failing_fixture(self) -> None:
        fixture = """schema: omega.sigmascope.rule-fixture.v1\nname: bad\nobservations:\n  staticPatternMatches: []\nexpected:\n  findingIds: [candidate.http-review]\n"""
        with self.assertRaisesRegex(ValueError, "fixture cannot be exported"):
            rule_lab.build_export_bundle(RULESET, fixture_text=fixture)


    def test_github_ready_export_contains_both_polarity_fixtures(self) -> None:
        positive = rule_lab.build_fixture(FakeInspector(with_match=True), RULESET, 12, name="positive")["fixtureYaml"]
        negative = rule_lab.build_fixture(FakeInspector(with_match=False), RULESET, 13, name="negative")["fixtureYaml"]
        archive_bytes, _manifest = rule_lab.build_export_bundle(
            RULESET, positive_fixture_text=positive, negative_fixture_text=negative, notes="github candidate"
        )
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            self.assertEqual(
                {"MANIFEST.json", "README.md", "candidate.json", "candidate.yaml", "positive-fixture.yaml", "negative-fixture.yaml"},
                set(archive.namelist()),
            )
            descriptor = json.loads(archive.read("candidate.json"))
            self.assertTrue(descriptor["githubProposalReady"])
            self.assertFalse(descriptor["productionWriteBack"])

    def test_github_issue_proposal_is_url_only_and_revalidates_both_fixtures(self) -> None:
        positive = rule_lab.build_fixture(FakeInspector(with_match=True), RULESET, 14, name="positive")["fixtureYaml"]
        negative = rule_lab.build_fixture(FakeInspector(with_match=False), RULESET, 15, name="negative")["fixtureYaml"]
        proposal = rule_lab.build_github_issue_proposal(
            RULESET, pack_id="candidate-http-pack", pack_title="Candidate HTTP rules",
            positive_fixture_text=positive, negative_fixture_text=negative,
            rationale="Retained-evidence candidate", false_positive_expectations="HTTP can be benign",
            provenance="DeltaScope retained Evidence-v2 replay", license_text="MIT",
        )
        self.assertTrue(proposal["ok"], proposal)
        self.assertTrue(proposal["openUrl"].startswith("https://github.com/dalagab/omega/issues/new?"))
        self.assertFalse(proposal["githubApiWrite"])
        self.assertFalse(proposal["repositoryCredentialsRequired"])
        self.assertTrue(proposal["githubSubmissionRequired"])
        self.assertEqual("none", proposal["mutationAuthority"])

    def test_selected_replay_is_bounded_and_summarized(self) -> None:
        report = rule_lab.replay_inspector(FakeInspector(), RULESET, variant_ids=[2, 1, 2], limit=10)
        self.assertTrue(report["ok"])
        self.assertEqual(2, report["variantsChecked"])
        self.assertEqual(2, report["evaluatedVariants"])
        self.assertEqual(2, report["diffCounts"]["added"])
        self.assertFalse(report["productionWriteBack"])

    def test_corpus_replay_obeys_limit(self) -> None:
        report = rule_lab.replay_inspector(FakeInspector(), RULESET, limit=2)
        self.assertEqual(2, report["variantsChecked"])

    def test_reference_exposes_local_only_boundary(self) -> None:
        ref = rule_lab.reference()
        self.assertFalse(ref["productionRuleEvaluationEnabled"])
        self.assertFalse(ref["productionWriteBack"])
        self.assertEqual(1000, ref["limits"]["corpusVariants"])

    def test_editor_intelligence_completes_collections_while_yaml_is_incomplete(self) -> None:
        text = """schema: omega.sigmascope.rule.v1
id: candidate.smart
kind: observation
status: experimental
requires: []
selectors:
  marker:
    collection: 
"""
        result = rule_lab.editor_intelligence(text, cursor_line=8, cursor_column=17)
        labels = {item["label"] for item in result["completions"]}
        self.assertIn("staticPatternMatches", labels)
        self.assertFalse(result["productionWriteBack"])
        self.assertEqual("none", result["mutationAuthority"])

    def test_editor_intelligence_understands_typed_fields_and_operators(self) -> None:
        field_text = """schema: omega.sigmascope.rule.v1
id: candidate.smart
kind: observation
status: experimental
requires: [staticPatternMatches]
selectors:
  marker:
    collection: staticPatternMatches
    where:
      
"""
        fields = rule_lab.editor_intelligence(field_text, cursor_line=10, cursor_column=7)
        field_labels = {item["label"] for item in fields["completions"]}
        self.assertIn("pattern", field_labels)
        self.assertIn("evidenceLabel", field_labels)

        operator_text = field_text.rstrip() + "\n      pattern:\n        \n"
        operators = rule_lab.editor_intelligence(operator_text, cursor_line=11, cursor_column=9)
        operator_labels = {item["label"] for item in operators["completions"]}
        self.assertIn("starts-with-ci", operator_labels)
        self.assertIn("equals-ci", operator_labels)
        self.assertNotIn("gt", operator_labels)

    def test_editor_intelligence_builds_symbol_outline_and_hover_docs(self) -> None:
        line = next(i for i, value in enumerate(RULESET.splitlines(), 1) if "condition: http" in value)
        result = rule_lab.editor_intelligence(RULESET, cursor_line=line, cursor_column=len("    condition: http") + 1)
        self.assertTrue(result["ok"])
        self.assertEqual(2, len(result["symbols"]["rules"]))
        self.assertIn("http", {item["name"] for item in result["symbols"]["selectors"]})
        self.assertIn("candidate.network.http", {item["name"] for item in result["symbols"]["facts"]})
        self.assertTrue(any(item["kind"] == "collection→selector" for item in result["graph"]["edges"]))

    def test_editor_linter_suggests_nearby_operator_typo(self) -> None:
        broken = rule_lab.DEFAULT_EXAMPLE.replace("starts-with-ci", "starts-wth-ci")
        result = rule_lab.editor_intelligence(broken, cursor_line=11, cursor_column=12)
        error = next(item for item in result["diagnostics"] if item["severity"] == "error")
        self.assertEqual(11, error["line"])
        self.assertEqual("starts-with-ci", error["suggestion"])

    def test_editor_formatter_is_safe_deterministic_and_recompiles(self) -> None:
        first = rule_lab.format_candidate_text(RULESET)
        second = rule_lab.format_candidate_text(first["yaml"])
        self.assertTrue(first["ok"])
        self.assertEqual(first["yaml"], second["yaml"])
        self.assertNotIn("&id", first["yaml"])
        self.assertNotIn("*id", first["yaml"])
        self.assertTrue(rule_lab.compile_candidate_text(first["yaml"])["ok"])

    def test_reference_exposes_smart_editor_language_contract(self) -> None:
        ref = rule_lab.reference()
        self.assertTrue(ref["editor"]["liveLint"])
        self.assertTrue(ref["editor"]["contextAwareCompletion"])
        self.assertIn("staticPatternMatches", ref["editor"]["typedCollections"])
        self.assertEqual("dependencyIntelligence.staticPatternMatches", ref["collectionDetails"]["staticPatternMatches"]["source"])
        self.assertIn("pattern", ref["collectionDetails"]["staticPatternMatches"]["fields"])
        self.assertEqual("none", ref["editor"]["mutationAuthority"])

    def test_http_rule_lab_endpoints_are_local_data_only(self) -> None:
        handler = type("TestRuleLabHandler", (developer_view.AppHandler,), {"inspector": FakeInspector()})
        server = developer_view.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            with urllib.request.urlopen(base + "/api/rule-lab/reference", timeout=5) as response:
                ref = json.load(response)
            self.assertFalse(ref["productionWriteBack"])
            self.assertTrue(ref["editor"]["liveLint"])

            with urllib.request.urlopen(base + "/api/rule-lab/collection?name=staticPatternMatches&variant_id=1&limit=10", timeout=5) as response:
                collection = json.load(response)
            self.assertEqual("omega.deltascope.rule-collection-detail.v1", collection["schema"])
            self.assertEqual("dependencyIntelligence.staticPatternMatches", collection["source"])
            self.assertEqual("https://", collection["rows"][0]["pattern"])
            self.assertTrue(collection["currentVersionOnly"])
            self.assertFalse(collection["policyInput"])

            intelligence_request = urllib.request.Request(
                base + "/api/rule-lab/intelligence",
                data=json.dumps({"yaml": RULESET, "line": 8, "column": 12}).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(intelligence_request, timeout=5) as response:
                intelligence = json.load(response)
            self.assertEqual("none", intelligence["mutationAuthority"])
            self.assertTrue(intelligence["symbols"]["rules"])

            format_request = urllib.request.Request(
                base + "/api/rule-lab/format", data=json.dumps({"yaml": RULESET}).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(format_request, timeout=5) as response:
                formatted = json.load(response)
            self.assertTrue(formatted["ok"])

            request = urllib.request.Request(
                base + "/api/rule-lab/evaluate",
                data=json.dumps({"yaml": RULESET, "variantId": 1}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                result = json.load(response)
            self.assertTrue(result["evaluation"]["evaluated"])

            export_request = urllib.request.Request(
                base + "/api/rule-lab/export",
                data=json.dumps({"yaml": RULESET}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(export_request, timeout=5) as response:
                self.assertEqual("application/zip", response.headers.get_content_type())
                self.assertTrue(response.read().startswith(b"PK"))

            positive = rule_lab.build_fixture(FakeInspector(with_match=True), RULESET, 21, name="positive")["fixtureYaml"]
            negative = rule_lab.build_fixture(FakeInspector(with_match=False), RULESET, 22, name="negative")["fixtureYaml"]
            proposal_request = urllib.request.Request(
                base + "/api/rule-lab/proposal",
                data=json.dumps({
                    "yaml": RULESET, "packId": "candidate-http-pack", "packTitle": "Candidate HTTP rules",
                    "positiveFixtureYaml": positive, "negativeFixtureYaml": negative,
                    "rationale": "HTTP candidate", "falsePositiveExpectations": "HTTP may be benign",
                    "provenance": "DeltaScope retained evidence", "license": "MIT",
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(proposal_request, timeout=5) as response:
                proposal = json.load(response)
            self.assertTrue(proposal["ok"])
            self.assertFalse(proposal["githubApiWrite"])
            self.assertIn("issues/new?", proposal["openUrl"])

            promote = urllib.request.Request(
                base + "/api/rule-lab/promote",
                data=b"{}", headers={"Content-Type": "application/json"}, method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(promote, timeout=5)
            self.assertEqual(404, raised.exception.code)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

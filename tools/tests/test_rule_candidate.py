from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

import common

import sys
sys.path.insert(0, str(common.ROOT / "tools" / "security"))

import definition_packs  # noqa: E402
import rule_candidate  # noqa: E402


CANDIDATE_YAML = """schema: omega.sigmascope.ruleset.v1
rules:
  - schema: omega.sigmascope.rule.v1
    id: candidate.network.http
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
      title: Candidate network HTTP fact
  - schema: omega.sigmascope.rule.v1
    id: candidate.network.http-review
    kind: correlation
    status: reviewed
    requires: []
    selectors:
      network:
        facts:
          any: [candidate.network.http]
    condition: network
    emit:
      findingId: candidate.network.http-review
      title: Candidate network HTTP review
      description: Candidate review finding
      severity: caution
      category: behavior
"""

POSITIVE = """schema: omega.sigmascope.rule-fixture.v1
name: positive
observations:
  staticPatternMatches:
    - origin: artifact
      pattern: https://
      evidenceLabel: fixture
      evidence: fixture.dll
expected:
  matchedRules:
    - candidate.network.http
    - candidate.network.http-review
  facts:
    - candidate.network.http
  findingIds:
    - candidate.network.http-review
"""

NEGATIVE = """schema: omega.sigmascope.rule-fixture.v1
name: negative
observations:
  staticPatternMatches: []
expected:
  matchedRules: []
  facts: []
  findingIds: []
"""


def issue_body(pack_id: str = "candidate-http-pack", candidate: str = CANDIDATE_YAML, positive: str = POSITIVE, negative: str = NEGATIVE) -> str:
    return f"""### Candidate pack ID
{pack_id}

### Candidate pack title
Candidate HTTP rules

### Candidate rule YAML
```yaml
{candidate.rstrip()}
```

### Positive fixture YAML
```yaml
{positive.rstrip()}
```

### Negative fixture YAML
```yaml
{negative.rstrip()}
```

### Rationale
Exercise the authorization-gated candidate workflow.

### False-positive expectations
HTTP literals may be benign; this is intentionally caution-only.

### External provenance / source
Rule Lab candidate derived from retained Evidence-v2 observations.

### License
MIT
"""


def issue(pack_id: str = "candidate-http-pack", **kwargs):
    return {
        "number": 321,
        "html_url": "https://github.com/dalagab/omega/issues/321",
        "updated_at": "2026-08-21T16:00:00Z",
        "user": {"login": "untrusted-contributor"},
        "body": issue_body(pack_id=pack_id, **kwargs),
    }


class RuleCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.packs = self.root / "security-definitions" / "packs"
        self.packs.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_issue_parser_requires_bounded_explicit_sections(self) -> None:
        parsed = rule_candidate.parse_issue(issue())
        self.assertEqual("candidate-http-pack", parsed["packId"])
        self.assertEqual("untrusted-contributor", parsed["issueAuthor"])
        self.assertEqual(64, len(parsed["issueBodySha256"]))
        self.assertNotIn("```", parsed["candidateYaml"])

    def test_candidate_validation_requires_positive_and_negative_fixture_behavior(self) -> None:
        result = rule_candidate.validate_issue(issue(), self.packs)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            ["candidate.network.http", "candidate.network.http-review"],
            result["ruleIds"],
        )
        self.assertEqual(["candidate.network.http"], result["emittedFacts"])
        self.assertFalse(result["candidateAuthorIsAuthorization"])
        self.assertFalse(result["productionWriteBack"])

    def test_candidate_self_declared_reviewed_status_is_not_authorization(self) -> None:
        parsed = rule_candidate.parse_issue(issue())
        validated = rule_candidate.validate_candidate(parsed)
        statuses = {row["id"]: row["status"] for row in validated["reviewedDocument"]["rules"]}
        self.assertEqual("reviewed", statuses["candidate.network.http"])
        self.assertEqual("reviewed", statuses["candidate.network.http-review"])
        self.assertFalse(validated["candidateAuthorIsAuthorization"])

    def test_disabled_or_deprecated_candidate_status_is_not_silently_promoted(self) -> None:
        disabled = CANDIDATE_YAML.replace("status: experimental", "status: disabled", 1)
        result = rule_candidate.validate_issue(issue(candidate=disabled), self.packs)
        self.assertFalse(result["ok"])
        self.assertIn("status must be experimental or reviewed", result["errors"][0])

    def test_negative_fixture_that_matches_candidate_is_rejected(self) -> None:
        result = rule_candidate.validate_issue(issue(negative=POSITIVE), self.packs)
        self.assertFalse(result["ok"])
        self.assertIn("negative fixture", result["errors"][0])
        self.assertIn("unexpectedly matches", result["errors"][0])

    def test_positive_fixture_must_cover_every_candidate_rule(self) -> None:
        positive = POSITIVE.replace("    - candidate.network.http-review\n", "")
        # The fixture expectation itself now fails because the evaluator still matches
        # both rules; this is fail-closed before Definition Pack materialization.
        result = rule_candidate.validate_issue(issue(positive=positive), self.packs)
        self.assertFalse(result["ok"])
        self.assertIn("positive fixture", result["errors"][0])

    def test_path_like_pack_ids_are_rejected(self) -> None:
        result = rule_candidate.validate_issue(issue(pack_id="../omega-core-compound"), self.packs)
        self.assertFalse(result["ok"])
        self.assertIn("may not contain paths", result["errors"][0])

    def test_yaml_anchors_are_rejected_by_hardened_srl_parser(self) -> None:
        result = rule_candidate.validate_issue(issue(candidate="a: &x 1\nb: *x\n"), self.packs)
        self.assertFalse(result["ok"])
        self.assertIn("anchors", result["errors"][0].lower())

    def test_existing_definition_pack_cannot_be_overwritten(self) -> None:
        existing = self.packs / "candidate-http-pack"
        existing.mkdir()
        (existing / "sentinel.txt").write_text("keep", encoding="utf-8")
        result = rule_candidate.validate_issue(issue(), self.packs)
        self.assertFalse(result["ok"])
        self.assertIn("already exists", result["errors"][0])
        self.assertEqual("keep", (existing / "sentinel.txt").read_text(encoding="utf-8"))

    def test_materialization_uses_verified_reviewer_not_issue_author(self) -> None:
        result = rule_candidate.materialize_issue(
            issue(),
            self.packs,
            reviewer="github:trusted-maintainer",
            reviewed_at="2026-08-21T17:00:00+00:00",
        )
        self.assertTrue(result["ok"])
        self.assertEqual("github:trusted-maintainer", result["reviewer"])
        self.assertFalse(result["candidateAuthorIsAuthorization"])
        manifest = yaml.safe_load((self.packs / "candidate-http-pack" / "pack.yaml").read_text(encoding="utf-8"))
        self.assertEqual("reviewed", manifest["trustTier"])
        self.assertEqual("github:trusted-maintainer", manifest["review"]["reviewer"])
        self.assertNotEqual("untrusted-contributor", manifest["review"]["reviewer"])
        rules = yaml.safe_load((self.packs / "candidate-http-pack" / "rules" / "candidate.yaml").read_text(encoding="utf-8"))
        self.assertTrue(all(rule["status"] == "reviewed" for rule in rules["rules"]))
        compiled = definition_packs.compile_pack_root(self.packs)
        self.assertEqual(2, compiled["activeRuleCount"])

    def test_materialization_records_issue_hash_and_normal_review_timestamp(self) -> None:
        result = rule_candidate.materialize_issue(
            issue(), self.packs,
            reviewer="github:trusted-maintainer",
            reviewed_at="2026-08-21T19:00:00+02:00",
        )
        self.assertEqual("2026-08-21T17:00:00Z", result["reviewedAtUtc"])
        manifest = (self.packs / "candidate-http-pack" / "pack.yaml").read_text(encoding="utf-8")
        self.assertIn(result["issueBodySha256"], manifest)
        self.assertIn("github-rule-candidate", manifest)

    def test_cli_validation_writes_comment_without_mutation(self) -> None:
        issue_path = self.root / "issue.json"
        result_path = self.root / "result.json"
        comment_path = self.root / "comment.md"
        issue_path.write_text(json.dumps(issue()), encoding="utf-8")
        completed = subprocess.run(
            [
                sys.executable, str(common.ROOT / "tools" / "security" / "rule_candidate.py"), "validate",
                "--issue-json", str(issue_path),
                "--packs-root", str(self.packs),
                "--result", str(result_path),
                "--comment", str(comment_path),
            ],
            cwd=common.ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertTrue(json.loads(result_path.read_text(encoding="utf-8"))["ok"])
        self.assertIn("does **not** authorize promotion", comment_path.read_text(encoding="utf-8"))
        self.assertEqual([], list(self.packs.iterdir()))

    def test_validation_rejects_rule_identity_collision_with_existing_repo_packs(self) -> None:
        colliding = """schema: omega.sigmascope.rule.v1
id: compound.network-execute
kind: correlation
status: experimental
requires: []
selectors:
  network:
    facts:
      any: [network.http]
  execution:
    facts:
      any: [process.launch]
condition:
  all: [network, execution]
emit:
  findingId: compound.network-execute
  title: Collision
  description: collision fixture
  severity: caution
  category: behavior
"""
        positive = """schema: omega.sigmascope.rule-fixture.v1
name: positive
observations: {}
initialFacts: [network.http, process.launch]
expected:
  matchedRules: [compound.network-execute]
  findingIds: [compound.network-execute]
"""
        negative = """schema: omega.sigmascope.rule-fixture.v1
name: negative
observations: {}
expected:
  matchedRules: []
  findingIds: []
"""
        result = rule_candidate.validate_issue(
            issue(pack_id="collision-pack", candidate=colliding, positive=positive, negative=negative),
            common.ROOT / "security-definitions" / "packs",
        )
        self.assertFalse(result["ok"])
        self.assertIn("duplicate", result["errors"][0].lower())

    def test_current_source_definition_pack_root_compiles_fail_closed(self) -> None:
        compiled = definition_packs.compile_pack_root(common.ROOT / "security-definitions" / "packs")
        self.assertFalse(compiled["productionRuleEvaluationEnabled"])
        self.assertGreaterEqual(compiled["activeRuleCount"], 7)
        self.assertGreaterEqual(len(compiled["packs"]), 2)

    def test_github_issue_prefill_uses_issue_form_field_ids_without_write_authority(self) -> None:
        import urllib.parse
        result = rule_candidate.build_issue_prefill(
            pack_id="candidate-http-pack",
            pack_title="Candidate HTTP rules",
            candidate_yaml=CANDIDATE_YAML,
            positive_fixture_yaml=POSITIVE,
            negative_fixture_yaml=NEGATIVE,
            rationale="Exercise the URL-only proposal handoff.",
            false_positive_expectations="HTTP literals may be benign.",
            provenance="DeltaScope retained Evidence-v2 replay",
            license_text="MIT",
            max_url_bytes=100000,
        )
        self.assertTrue(result["ok"])
        self.assertEqual("complete-prefill", result["mode"])
        self.assertFalse(result["manualPasteRequired"])
        self.assertFalse(result["githubApiWrite"])
        self.assertFalse(result["repositoryCredentialsRequired"])
        self.assertEqual("none", result["mutationAuthority"])
        parsed = urllib.parse.urlparse(result["openUrl"])
        self.assertEqual("github.com", parsed.netloc)
        self.assertEqual("/dalagab/omega/issues/new", parsed.path)
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(["sigmascope-rule-candidate.yml"], query["template"])
        self.assertEqual(["candidate-http-pack"], query["candidate-pack-id"])
        self.assertEqual([CANDIDATE_YAML.strip()], query["candidate-rule-yaml"])
        self.assertEqual([POSITIVE.strip()], query["positive-fixture-yaml"])
        self.assertEqual([NEGATIVE.strip()], query["negative-fixture-yaml"])
        self.assertEqual(["MIT"], query["license"])

    def test_github_issue_prefill_falls_back_without_dropping_candidate_validation(self) -> None:
        result = rule_candidate.build_issue_prefill(
            pack_id="candidate-http-pack",
            pack_title="Candidate HTTP rules",
            candidate_yaml=CANDIDATE_YAML,
            positive_fixture_yaml=POSITIVE,
            negative_fixture_yaml=NEGATIVE,
            rationale="R" * 7000,
            false_positive_expectations="F" * 7000,
            provenance="P" * 3000,
            license_text="MIT",
            max_url_bytes=900,
        )
        self.assertTrue(result["ok"])
        self.assertNotEqual("complete-prefill", result["mode"])
        self.assertTrue(result["manualPasteRequired"])
        self.assertLessEqual(result["openUrlBytes"], 900)
        self.assertIn("candidate-rule-yaml", result["omittedFieldIds"])
        self.assertTrue(result["githubWillRevalidate"])
        self.assertIn("candidate.network.http", result["ruleIds"])

    def test_github_issue_prefill_rejects_invalid_negative_fixture_before_opening_browser(self) -> None:
        with self.assertRaisesRegex(rule_candidate.RuleCandidateError, "negative fixture"):
            rule_candidate.build_issue_prefill(
                pack_id="candidate-http-pack", pack_title="Candidate HTTP rules",
                candidate_yaml=CANDIDATE_YAML, positive_fixture_yaml=POSITIVE, negative_fixture_yaml=POSITIVE,
                rationale="rationale", false_positive_expectations="expectations",
                provenance="provenance", license_text="MIT",
            )


if __name__ == "__main__":
    unittest.main()

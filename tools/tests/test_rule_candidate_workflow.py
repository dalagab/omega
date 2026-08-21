from __future__ import annotations

import unittest
import yaml

import common

SECURITY = common.ROOT / "tools" / "security"
import sys
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))
import rule_candidate  # noqa: E402


class RuleCandidateWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow_path = common.ROOT / ".github" / "workflows" / "rule-candidates.yml"
        self.issue_path = common.ROOT / ".github" / "ISSUE_TEMPLATE" / "sigmascope-rule-candidate.yml"
        self.caller_path = common.ROOT / "docs" / "workflow-callers" / "rule-candidates-main.yml"
        self.main_issue_reference_path = common.ROOT / "docs" / "workflow-callers" / "sigmascope-rule-candidate-main.yml"
        self.workflow = self.workflow_path.read_text(encoding="utf-8")
        self.issue = self.issue_path.read_text(encoding="utf-8")
        self.caller = self.caller_path.read_text(encoding="utf-8")
        self.main_issue_reference = self.main_issue_reference_path.read_text(encoding="utf-8")

    def test_workflow_and_issue_template_parse_as_yaml(self) -> None:
        self.assertIsInstance(yaml.safe_load(self.workflow), dict)
        self.assertIsInstance(yaml.safe_load(self.issue), dict)
        self.assertIsInstance(yaml.safe_load(self.caller), dict)

    def test_validation_job_is_contents_read_only_and_comments_diagnostics(self) -> None:
        validate = self.workflow[self.workflow.index("  validate:"):self.workflow.index("\n  promote:\n")]
        self.assertIn("contents: read", validate)
        self.assertNotIn("contents: write", validate)
        self.assertIn("issues: write", validate)
        self.assertIn("rule_candidate.py validate", validate)
        self.assertIn("gh issue comment", validate)
        self.assertIn("persist-credentials: false", validate)

    def test_promotion_authorizes_github_actor_before_checkout_and_issue_fetch(self) -> None:
        promote = self.workflow[self.workflow.index("  promote:"):]
        authorization = promote.index("Verify triggering GitHub actor has repository write authority")
        checkout = promote.index("uses: actions/checkout@v6")
        refetch = promote.index("Re-fetch candidate issue only after authorization")
        self.assertLess(authorization, checkout)
        self.assertLess(authorization, refetch)
        self.assertIn("collaborators/$PROMOTION_ACTOR/permission", promote)
        self.assertIn("admin|write", promote)
        self.assertNotIn("author_association", promote)

    def test_promotion_revalidates_from_scratch_and_opens_normal_pr_only(self) -> None:
        promote = self.workflow[self.workflow.index("  promote:"):]
        self.assertIn("rule_candidate.py promote", promote)
        self.assertIn("Revalidate from scratch and materialize reviewed Definition Pack", promote)
        self.assertIn("gh pr create", promote)
        self.assertIn("--base sigmascope", promote)
        self.assertNotIn("gh pr merge", promote)
        self.assertNotIn("--auto", promote)
        self.assertNotIn("pull_request_target", self.workflow)

    def test_candidate_data_never_enters_shell_as_executable_script(self) -> None:
        self.assertNotIn("eval ", self.workflow)
        self.assertNotIn("bash candidate", self.workflow)
        self.assertNotIn("source candidate", self.workflow)
        self.assertNotIn("python candidate", self.workflow)
        self.assertIn("candidate-issue.json", self.workflow)
        self.assertIn("candidate-result.json", self.workflow)

    def test_issue_template_requires_candidate_positive_negative_and_review_context(self) -> None:
        for label in (
            "Candidate pack ID",
            "Candidate pack title",
            "Candidate rule YAML",
            "Positive fixture YAML",
            "Negative fixture YAML",
            "Rationale",
            "False-positive expectations",
            "External provenance / source",
            "License",
        ):
            self.assertIn(f"label: {label}", self.issue)
        self.assertIn("render: yaml", self.issue)


    def test_issue_form_ids_match_deltascope_url_prefill_contract(self) -> None:
        parsed = yaml.safe_load(self.issue)
        ids = {str(row.get("id") or "") for row in parsed.get("body") or [] if isinstance(row, dict) and row.get("id")}
        self.assertEqual(set(rule_candidate.ISSUE_FORM_FIELD_IDS.values()), ids)
        self.assertEqual(self.issue, self.main_issue_reference)

    def test_reusable_workflow_checks_out_sigmascope_and_has_no_issue_event_authority_shortcut(self) -> None:
        self.assertIn("workflow_call:", self.workflow)
        self.assertIn("ref: sigmascope", self.workflow)
        self.assertNotIn("issue_comment:", self.workflow)
        self.assertNotIn("issues:\n", self.workflow.split("jobs:", 1)[0])

    def test_reference_default_branch_caller_routes_events_to_trusted_reusable_workflow(self) -> None:
        self.assertIn("issues:", self.caller)
        self.assertIn("issue_comment:", self.caller)
        self.assertIn("SigmaScope rule candidate:", self.caller)
        self.assertIn("/promote-sigmascope-rule", self.caller)
        self.assertEqual(2, self.caller.count("uses: dalagab/omega/.github/workflows/rule-candidates.yml@sigmascope"))
        self.assertIn("mode: validate", self.caller)
        self.assertIn("mode: promote", self.caller)

    def test_reference_caller_does_not_treat_comment_command_as_permission(self) -> None:
        # The caller only routes the event. The reusable workflow performs the actual
        # collaborator-permission lookup before any privileged candidate processing.
        self.assertNotIn("author_association", self.caller)
        self.assertIn("collaborators/$PROMOTION_ACTOR/permission", self.workflow)
        self.assertLess(
            self.workflow.index("Verify triggering GitHub actor has repository write authority"),
            self.workflow.index("Re-fetch candidate issue only after authorization"),
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
import unittest

import common


class SigmascopeParallelPublishWorkflowTests(unittest.TestCase):
    def text(self) -> str:
        return (common.ROOT / ".github" / "workflows" / "sigmascope-parallel-publish.yml").read_text(encoding="utf-8")

    def test_phase4c_workflow_is_manual_shared_mutex_and_defaults_to_authorization_only(self) -> None:
        text = self.text()
        self.assertIn("workflow_call:", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("schedule:", text)
        self.assertIn("confirm_publish:", text)
        self.assertIn("default: false", text)
        self.assertIn("omega-catalog-sigmascope-exclusive", text)
        self.assertIn("if: inputs.confirm_publish == true", text)

    def test_read_only_authorizer_reconstructs_exact_successful_shadow_run(self) -> None:
        text = self.text()
        self.assertIn("actions: read", text)
        self.assertIn('test "$(jq -r \'.name\' <<<"$meta")" = "Omega SigmaScope · parallel result-bundle shadow"', text)
        self.assertIn("gh run download", text)
        self.assertIn("use_current_run_artifacts", text)
        self.assertIn("current-run preflight run binding mismatch", text)
        self.assertIn("actions/download-artifact@v8", text)
        self.assertIn("sigmascope_result_merger.py", text)
        self.assertIn("sigmascope_parallel_publish_gate.py authorize", text)
        self.assertIn("baseEvidenceGitHead", text)
        self.assertIn("security-v2-authorized-candidate.tar.gz", text)

    def test_tiny_writer_rechecks_authorization_and_publishes_evidence_before_side_effects(self) -> None:
        text = self.text()
        self.assertIn("contents: write", text)
        self.assertIn("issues: write", text)
        self.assertIn("sigmascope_parallel_publish_gate.py check-current", text)
        self.assertIn("--parallel-authorization-report", text)
        self.assertIn("--expected-parent-sha", text)
        self.assertIn("--history-mode fast-forward", text)
        evidence = text.index("Publish exact authorized Security Evidence v2 child")
        deep = text.index("Publish authorized Deep Scan queue only after Evidence acceptance")
        source = text.index("Reconcile human source follow-up issues only after Evidence acceptance")
        self.assertLess(evidence, deep)
        self.assertLess(deep, source)
        self.assertNotIn("publish_catalog_state.py", text)
        self.assertNotIn("compile_marketplace_snapshot.py", text)

    def test_retry_path_never_rewrites_a_newer_evidence_head(self) -> None:
        text = self.text()
        self.assertIn("already-published-immediate-child", text)
        self.assertIn("Record already-published retry state without rewriting Evidence", text)
        self.assertIn("fetch-depth: 2", text)


if __name__ == "__main__":
    unittest.main()

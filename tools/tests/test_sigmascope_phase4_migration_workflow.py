from __future__ import annotations

import unittest

import common


class SigmascopePhase4MigrationWorkflowTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (common.ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")

    def test_one_operator_workflow_prepares_and_runs_full_phase4_migration(self) -> None:
        text = self.read("sigmascope-phase4-migration.yml")
        self.assertIn("name: Omega SigmaScope · Phase 4 automatic migration", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("confirm_migration:", text)
        self.assertNotIn("schedule:", text)
        self.assertIn("uses: ./.github/workflows/worker-images.yml", text)
        self.assertIn("uses: ./.github/workflows/catalog-freeze.yml", text)
        self.assertIn("uses: ./.github/workflows/sigmascope-phase4-cutover-core.yml", text)
        self.assertNotIn("gh workflow run", text, "migration must chain reusable stages, not launch/poll detached runs")

    def test_locked_core_owns_shadow_to_verify_under_global_writer_mutex(self) -> None:
        text = self.read("sigmascope-phase4-cutover-core.yml")
        self.assertIn("workflow_call:", text)
        self.assertIn("group: omega-catalog-sigmascope-exclusive", text)
        self.assertIn("uses: ./.github/workflows/sigmascope-parallel-shadow.yml", text)
        self.assertIn("uses: ./.github/workflows/sigmascope-parallel-publish.yml", text)
        self.assertIn("use_current_run_artifacts: true", text)
        self.assertIn("confirm_publish: true", text)

    def test_prepared_prerequisites_fail_closed_before_real_corpus_shadow(self) -> None:
        text = self.read("sigmascope-phase4-cutover-core.yml")
        self.assertIn("Require all immutable Phase-4 worker images", text)
        self.assertIn("@sha256:[0-9a-f]{64}", text)
        self.assertIn("Require newly frozen fast-forward-capable Definitions worker", text)
        self.assertIn("--parallel-authorization-report", text)
        self.assertIn("Require at least one exact real-corpus assignment", text)
        self.assertIn("sigmascope_parallel_plan.py", text)
        self.assertIn("No eligible real-corpus", text)

    def test_post_publication_verifies_authorized_evidence_and_deep_scan_state(self) -> None:
        text = self.read("sigmascope-phase4-cutover-core.yml")
        self.assertIn("sigmascope_parallel_publish_gate.py check-current", text)
        self.assertIn("already-published-immediate-child", text)
        self.assertIn("authorized-identical-tree-no-op", text)
        self.assertIn("Verify authorized Deep Scan state was published after Evidence", text)
        self.assertIn("omega.sigmascope-phase4-migration.v1", text)
        self.assertIn("retention-days: 90", text)
        self.assertNotIn("python tools/security/publish_security_evidence_v2.py", text, "locked core delegates writes to the tiny Phase-4C writer")
        self.assertNotIn("publish_catalog_state.py", text)
        self.assertNotIn("gh release upload", text)

    def test_worker_image_workflow_is_reusable_for_self_preparation(self) -> None:
        text = self.read("worker-images.yml")
        self.assertIn("workflow_call:", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("security-worker-images", text)


if __name__ == "__main__":
    unittest.main()

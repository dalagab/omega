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
        self.assertNotIn("uses: ./.github/workflows/sigmascope-phase4-cutover-core.yml", text)
        self.assertNotIn("uses: ./.github/workflows/sigmascope-parallel-shadow.yml", text)
        self.assertIn("uses: ./.github/workflows/security-reconcile.yml", text)
        self.assertIn("redispatch_active_leases: true", text)
        self.assertIn("group: omega-catalog-sigmascope-exclusive", text)
        self.assertNotIn("group: omega-sigmascope-phase4-migration", text)
        self.assertIn("gh workflow run security-orchestration-dispatch.yml", text)
        self.assertNotIn("gh workflow run security-reconcile.yml", text)
        self.assertIn("\n  freeze-current-definitions:\n", text)
        self.assertIn("\n  prerequisites:\n", text)
        self.assertIn("\n  shadow-workers:\n", text)
        self.assertIn("\n  shadow-merge:\n", text)
        self.assertIn("\n  authorize-and-publish:\n", text)
        self.assertIn("\n  verify:\n", text)
        self.assertIn("authority_lock_held: true", text)
        self.assertIn("use_current_run_artifacts: true", text)
        self.assertIn("confirm_publish: true", text)

    def test_complete_migration_owns_shadow_to_verify_under_global_writer_mutex(self) -> None:
        text = self.read("sigmascope-phase4-migration.yml")
        head = text[: text.index("\npermissions:\n")]
        self.assertIn("group: omega-catalog-sigmascope-exclusive", head)
        self.assertIn("cancel-in-progress: false", head)
        self.assertIn("queue: max", head)
        self.assertLess(text.index("\n  freeze-current-definitions:\n"), text.index("\n  prerequisites:\n"))
        self.assertLess(text.index("\n  prerequisites:\n"), text.index("\n  shadow-workers:\n"))
        self.assertLess(text.index("\n  shadow-workers:\n"), text.index("\n  shadow-merge:\n"))
        self.assertLess(text.index("\n  shadow-merge:\n"), text.index("\n  authorize-and-publish:\n"))
        self.assertLess(text.index("\n  authorize-and-publish:\n"), text.index("\n  verify:\n"))

    def test_prepared_prerequisites_fail_closed_before_real_corpus_shadow(self) -> None:
        text = self.read("sigmascope-phase4-migration.yml")
        self.assertIn("Require all immutable Phase-4 worker images", text)
        self.assertIn("@sha256:[0-9a-f]{64}", text)
        self.assertIn("Require newly frozen fast-forward-capable Definitions worker", text)
        self.assertIn("--parallel-authorization-report", text)
        self.assertIn("Require at least one exact real-corpus assignment", text)
        self.assertIn("Install pinned Python security dependencies", text)
        self.assertIn(
            "python -m pip install --disable-pip-version-check -r tools/requirements-security.txt",
            text,
        )
        self.assertIn("sigmascope_parallel_plan.py", text)
        self.assertIn("No eligible real-corpus", text)
        self.assertLess(
            text.index("Install pinned Python security dependencies"),
            text.index("Require at least one exact real-corpus assignment"),
        )

    def test_phase4b_proof_is_inlined_with_static_runner_matrix(self) -> None:
        text = self.read("sigmascope-phase4-migration.yml")
        workers = text[text.index("\n  shadow-workers:\n") : text.index("\n  shadow-merge:\n")]
        merge = text[text.index("\n  shadow-merge:\n") : text.index("\n  authorize-and-publish:\n")]
        self.assertIn("slot: [0, 1, 2, 3, 4, 5, 6, 7]", workers)
        self.assertNotIn("fromJSON(", workers)
        self.assertIn('image: ${{ needs.prerequisites.outputs.sigmascope_image }}', workers)
        self.assertIn("sigmascope_phase4b_inline_worker.py", workers)
        self.assertIn("omega-sigmascope-result-slot-${{ matrix.slot }}", workers)
        self.assertIn("sigmascope_phase4b_inline_merge.py", merge)
        self.assertIn("omega-sigmascope-merged-candidate-validation", merge)
        self.assertIn("contents: read", workers)
        self.assertIn("contents: read", merge)
        self.assertNotIn("contents: write", workers)
        self.assertNotIn("contents: write", merge)

    def test_inline_phase4b_helpers_retain_zero_publication_authority(self) -> None:
        for name in ("sigmascope_phase4b_inline_worker.py", "sigmascope_phase4b_inline_merge.py"):
            text = (common.ROOT / "tools" / "security" / name).read_text(encoding="utf-8")
            self.assertNotIn("publish_security_evidence_v2.py", text, name)
            self.assertNotIn("publish_catalog_state.py", text, name)
            self.assertNotIn("gh release", text, name)
        merge = (common.ROOT / "tools" / "security" / "sigmascope_phase4b_inline_merge.py").read_text(encoding="utf-8")
        self.assertIn("candidate-only-no-evidence-publication", merge)
        self.assertIn("preflight-only-no-evidence-publication", merge)
        self.assertIn("sigmascope_merge_equivalence.py", merge)

    def test_inline_phase4b_helpers_take_catalog_revision_from_frozen_catalog_identity(self) -> None:
        for name in ("sigmascope_phase4b_inline_worker.py", "sigmascope_phase4b_inline_merge.py"):
            helper = (common.ROOT / "tools" / "security" / name).read_text(encoding="utf-8")
            self.assertIn('catalog_index_path = args.catalog_root / "catalog" / "index.json"', helper, name)
            self.assertIn('catalog_revision = str(catalog_index.get("catalogRevision") or "")', helper, name)
            self.assertRegex(helper, r'"--catalog-revision",\s+catalog_revision,', name)
            self.assertNotIn('defs["catalogRevision"]', helper, name)

    def test_post_publication_verifies_authorized_evidence_and_deep_scan_state(self) -> None:
        text = self.read("sigmascope-phase4-migration.yml")
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

    def test_worker_image_resolvers_fail_closed_and_do_not_escape_jq_filters(self) -> None:
        single_resolvers = (
            "catalog-builder.yml",
            "catalog-discovery-worker.yml",
            "catalog-enrichment-worker.yml",
            "catalog-scrape-worker.yml",
            "threat-intelligence-worker.yml",
            "osv-worker.yml",
            "source-head-worker.yml",
            "secondary-security-worker.yml",
            "sigmascope-parallel-worker.yml",
            "sigmascope-parallel-shadow.yml",
        )
        for name in single_resolvers:
            text = self.read(name)
            self.assertIn("jq -er --arg image", text, name)
            self.assertIn("@sha256:[0-9a-f]{64}", text, name)
            self.assertNotIn(".images[\\\"", text, name)
            self.assertNotIn('run: echo "image=$(jq', text, name)
        publish = self.read("sigmascope-parallel-publish.yml")
        self.assertGreaterEqual(publish.count("jq -er --arg image"), 2)
        self.assertIn("@sha256:[0-9a-f]{64}", publish)
        self.assertNotIn(".images[\\\"", publish)


if __name__ == "__main__":
    unittest.main()

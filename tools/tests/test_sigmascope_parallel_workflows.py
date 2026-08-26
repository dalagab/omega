from __future__ import annotations

import unittest

import common


class SigmascopeParallelWorkflowTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (common.ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")

    def test_parallel_worker_is_result_only_and_digest_pinned(self) -> None:
        text = self.read("sigmascope-parallel-worker.yml")
        self.assertIn("security-worker-images", text)
        self.assertIn("sigmascope-worker", text)
        self.assertIn("--queue-key", text)
        self.assertIn("sigmascope_result_bundle.py build", text)
        self.assertIn("actions/upload-artifact", text)
        self.assertNotIn("publish_security_evidence_v2.py", text)
        self.assertNotIn("publish_catalog_state.py", text)
        self.assertNotIn("gh release upload catalog-latest", text)
        self.assertNotIn("contents: write", text)

    def test_shadow_orchestrator_has_no_schedule_or_publication_authority(self) -> None:
        text = self.read("sigmascope-parallel-shadow.yml")
        self.assertIn("workflow_call:", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("schedule:", text)
        self.assertIn("sigmascope_parallel_plan.py", text)
        self.assertIn("uses: ./.github/workflows/sigmascope-parallel-worker.yml", text)
        self.assertIn("sigmascope_result_bundle.py plan", text)
        self.assertIn("max-parallel: 8", text)
        self.assertNotIn("publish_security_evidence_v2.py", text)
        self.assertNotIn("gh release upload", text)
        self.assertIn("sigmascope_result_merger.py", text)
        self.assertIn("sigmascope_merge_equivalence.py", text)
        self.assertIn("sigmascope_parallel_preflight.py", text)
        self.assertIn("security_developer_audit.py", text)
        self.assertIn("evidence_storage_audit.py", text)
        self.assertIn("candidate-only-no-evidence-publication", text)
        self.assertIn("preflight-only-no-evidence-publication", text)
        self.assertIn("security-worker-images", text)
        self.assertIn("sigmascope_source_followups.py", text)
        self.assertIn("--deep-scan-output", text)
        self.assertNotIn("publish_security_evidence_v2.py", text)

    def test_serialized_merger_code_has_no_publication_calls(self) -> None:
        text = (common.ROOT / "tools" / "security" / "sigmascope_result_merger.py").read_text(encoding="utf-8")
        self.assertIn("candidate-only-no-evidence-publication", text)
        self.assertIn("validate_snapshot", text)
        self.assertIn("rebuild_candidate_indexes", text)
        self.assertIn("deep_scan_queue.build_queue", text)
        self.assertIn("sigmascope_source_followups.followups", text)
        self.assertNotIn("publish_security_evidence_v2", text)
        self.assertNotIn("gh release", text)

    def test_frozen_pipeline_supports_exact_queue_key_without_changing_analysis_revision_contract(self) -> None:
        pipeline = (common.ROOT / "tools" / "security" / "production_sigmascope_v2_pipeline.py").read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--queue-key"', pipeline)
        self.assertIn("scan_queue.select_key(queue_state, selected_exact_queue_key)", pipeline)
        self.assertIn("choose either --analysis-request or --queue-key", pipeline)
        self.assertIn('"requestedQueueKey": exact_queue_key', pipeline)


if __name__ == "__main__":
    unittest.main()

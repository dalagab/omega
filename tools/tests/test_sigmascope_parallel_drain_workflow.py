from __future__ import annotations

import unittest
import common


class SigmaScopeParallelDrainWorkflowTests(unittest.TestCase):
    def test_production_drain_is_parallel_bounded_and_one_writer(self) -> None:
        text = (common.ROOT / ".github" / "workflows" / "sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        for required in (
            "group: omega-catalog-sigmascope-exclusive", "queue: max", "default: 4", "default: 10",
            "sigmascope_parallel_drain_plan.py", "strategy:", "fail-fast: false", "QUEUE_KEYS_JSON",
            "sigmascope_worker_batch.py run", "--queue-keys-file catalog/slot-work/queue-keys.txt",
            "sigmascope_worker_batch.py bundles", "sigmascope_result_merger.py",
            "--queue-seed catalog/active-state/scan-queue.json", "security_developer_audit.py",
            "evidence_storage_audit.py", "publish_security_evidence_v2.py", "--expected-parent-sha",
            "publish_deep_scan_state.py", "catalog-client-publish.yml", "authority_lock_held: true",
            "gh workflow run sigmascope-parallel-drain.yml",
        ):
            self.assertIn(required, text)
        self.assertNotIn('--queue-key "$queue_key"', text)
        self.assertNotIn("while IFS= read -r queue_key; do", text)
        self.assertNotIn("sigmascope_merge_equivalence.py", text)
        self.assertNotIn("confirm_migration", text)
        self.assertNotIn("shadow_run_id", text)

    def test_parallel_workers_are_result_only_and_publication_is_serialized(self) -> None:
        text = (common.ROOT / ".github" / "workflows" / "sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        workers = text[text.index("\n  workers:"): text.index("\n  merge:")]
        publish = text[text.index("\n  publish:"): text.index("\n  publish-client:")]
        self.assertIn("permissions:\n      contents: read", workers)
        self.assertNotIn("publish_security_evidence_v2.py", workers)
        self.assertNotIn("publish_deep_scan_state.py", workers)
        self.assertIn("publish_security_evidence_v2.py", publish)
        self.assertIn("publish_deep_scan_state.py", publish)

    def test_customer_projection_is_periodic_and_terminal(self) -> None:
        text = (common.ROOT / ".github" / "workflows" / "sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        self.assertIn("publish_client_every", text)
        self.assertIn('if [ "$next_mode" != "parallel" ] ||', text)
        self.assertIn("WAVE % cadence", text)
        self.assertIn("needs.publish.outputs.publish_client == 'true'", text)


if __name__ == "__main__":
    unittest.main()

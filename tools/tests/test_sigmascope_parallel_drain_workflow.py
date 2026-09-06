from __future__ import annotations

import re
import unittest
import common


class SigmaScopeParallelDrainWorkflowTests(unittest.TestCase):
    def test_production_drain_is_parallel_bounded_and_one_writer(self) -> None:
        text = (common.ROOT / ".github" / "workflows" / "sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        for required in (
            "group: omega-sigmascope-parallel-drain-exclusive", "queue: max", "default: 8",
            "sigmascope_parallel_drain_plan.py", "strategy:", "fail-fast: false", "QUEUE_KEYS_JSON",
            "runs-on: ubuntu-latest", "container:", "image: ${{ needs.resolve-images.outputs.scan_image }}",
            "sigmascope_parallel_worker_entrypoint.sh process",
            "sigmascope_result_merger.py",
            "--queue-seed catalog/active-state/scan-queue.json", "security_developer_audit.py",
            "evidence_storage_audit.py", "publish_security_evidence_v2.py", "--expected-parent-sha",
            "publish_deep_scan_state.py", "catalog-client-publish.yml", "authority_lock_held: false",
            "gh workflow run sigmascope-parallel-drain.yml",
            "Capacity used:", "Assignments by lane:", "Eligible queue items now:",
            "Deferred by retry backoff:", "Oldest eligible enqueue:", "Highest pending attempt count:",
        ):
            self.assertIn(required, text)
        self.assertNotIn('--queue-key "$queue_key"', text)
        self.assertNotIn("while IFS= read -r queue_key; do", text)
        self.assertNotIn("sigmascope_merge_equivalence.py", text)
        self.assertNotIn("confirm_migration", text)
        self.assertNotIn("shadow_run_id", text)
        worker = (common.ROOT / "tools" / "security" / "sigmascope_parallel_worker_entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn('GIT_CONFIG_GLOBAL="${GIT_CONFIG_GLOBAL:-/tmp/sigmascope-worker-gitconfig}"', worker)
        self.assertIn('safe.directory "$PWD/catalog/security-v2-current"', worker)
        self.assertNotIn("safe.directory=*", worker)
        self.assertIn("sigmascope_worker_batch.py run", worker)
        self.assertIn("WORKER_MAX_BATCH_SECONDS:-3600", worker)
        self.assertIn("--queue-keys-file catalog/slot-work/queue-keys.txt", worker)
        self.assertIn("sigmascope_worker_batch.py bundles", worker)
        self.assertIn("--summary catalog/slot-result-bundles/slot-summary.json", worker)
        self.assertIn('run_status=0', worker)
        self.assertNotIn("default: 4", text)
        self.assertNotIn("default: 10", text)
        self.assertIn("WORKERS: ${{ inputs.workers || 8 }}", text)
        self.assertIn("ITEMS_PER_WORKER: ${{ inputs.items_per_worker || 8 }}", text)
        self.assertIn("omega.sigmascope-drain-execution-context.v1", text)
        self.assertNotIn("self-hosted", text)
        self.assertNotIn("omega-security", text)
        wake = (common.ROOT / ".github" / "workflows" / "sigmascope-drain-wake.yml").read_text(encoding="utf-8")
        self.assertNotIn("default: 4", wake)
        self.assertNotIn("default: 10", wake)
        self.assertIn("WORKERS: ${{ inputs.workers || 8 }}", wake)
        self.assertIn("ITEMS_PER_WORKER: ${{ inputs.items_per_worker || 8 }}", wake)

    def test_parallel_workers_are_result_only_and_publication_is_serialized(self) -> None:
        text = (common.ROOT / ".github" / "workflows" / "sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        workers = text[text.index("\n  workers:"): text.index("\n  merge:")]
        publish = text[text.index("\n  publish:"): text.index("\n  publish-client:")]
        for job_name in ("\n  plan:", "\n  merge:", "\n  publish:", "\n  issue-summary:"):
            if job_name in text:
                start = text.index(job_name)
                job_starts = [match.start() for match in re.finditer(r"(?m)^  [A-Za-z0-9_-]+:", text)]
                next_starts = [position for position in job_starts if position > start + len(job_name)]
                job = text[start:] if not next_starts else text[start:next_starts[0]]
                self.assertIn("runs-on: ubuntu-latest", job)
        client_publish = (common.ROOT / ".github" / "workflows" / "catalog-client-publish.yml").read_text(encoding="utf-8")
        self.assertIn("uses: ./.github/workflows/catalog-client-publish.yml", text)
        self.assertIn("runs-on: ubuntu-latest", client_publish)
        self.assertIn("runs-on: ubuntu-latest", workers)
        self.assertIn("timeout-minutes: 75", workers)
        self.assertNotIn("self-hosted", workers)
        self.assertNotIn("omega-security", workers)
        self.assertNotIn("max-parallel:", workers)
        self.assertIn("\n    container:", workers)
        self.assertIn("image: ${{ needs.resolve-images.outputs.scan_image }}", workers)
        self.assertNotIn("docker run", workers)
        self.assertIn("if: always()", workers)
        self.assertIn("if-no-files-found: warn", workers)
        self.assertNotIn("--user 0:0", workers)
        self.assertNotIn('--user "$(id -u):$(id -g)"', workers)
        self.assertIn("permissions:\n      contents: read", workers)
        self.assertNotIn("publish_security_evidence_v2.py", workers)
        self.assertNotIn("publish_deep_scan_state.py", workers)
        self.assertIn("publish_security_evidence_v2.py", publish)
        self.assertIn("publish_deep_scan_state.py", publish)
        self.assertIn("group: omega-catalog-sigmascope-exclusive", publish)
        self.assertIn("Revalidate planned authority heads after acquiring the writer lock", publish)
        self.assertIn("refs/heads/catalog-data", publish)
        self.assertIn("refs/heads/security-evidence-v2", publish)
        self.assertIn("git -C catalog/active-state ls-remote --heads origin refs/heads/catalog-data", publish)
        self.assertIn("git -C catalog/security-v2-current ls-remote --heads origin refs/heads/security-evidence-v2", publish)
        self.assertNotIn('current_catalog="$(git ls-remote', publish)
        self.assertNotIn('current_evidence="$(git ls-remote', publish)
        self.assertIn("Stale parallel candidate discarded", publish)
        self.assertIn("if: steps.authority.outputs.publish == 'true'", publish)
        merge = text[text.index("\n  merge:"): text.index("\n  publish:")]
        self.assertIn("always() &&", merge)
        self.assertIn("!cancelled() &&", merge)
        self.assertNotIn("needs.workers.result == 'success'", merge)
        self.assertIn("omega.sigmascope-drain-bundle-intake.v1", merge)
        self.assertIn("result bundles are outside the exact drain plan", merge)
        self.assertIn("no finalized SigmaScope result bundles were delivered", merge)
        self.assertIn("bundle-intake.json", merge)

    def test_customer_projection_is_periodic_and_terminal(self) -> None:
        text = (common.ROOT / ".github" / "workflows" / "sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        self.assertIn("publish_client_every", text)
        self.assertIn('if [ "$next_mode" != "parallel" ] ||', text)
        self.assertIn("WAVE % cadence", text)
        self.assertIn("needs.publish.outputs.publish_client == 'true'", text)

    def test_workers_merge_and_publication_use_exact_planned_catalog(self) -> None:
        text = (common.ROOT / ".github/workflows/sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        self.assertIn("catalog_head: ${{ steps.plan.outputs.catalog_head }}", text)
        self.assertEqual(3, text.count("ref: ${{ needs.plan.outputs.catalog_head }}"))
        self.assertIn('--wave "$WAVE"', text)
        self.assertIn("matrix.lane", text)


if __name__ == "__main__":
    unittest.main()

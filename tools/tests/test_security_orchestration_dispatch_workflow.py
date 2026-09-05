from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github" / "workflows"

WORKERS = {
    "catalog-discovery": "catalog-discovery-worker.yml",
    "catalog-enrichment": "catalog-enrichment-worker.yml",
    "catalog-scrape": "catalog-scrape-worker.yml",
    "source-head-observation": "source-head-worker.yml",
    "threat-intelligence": "threat-intelligence-worker.yml",
    "osv-advisories": "osv-worker.yml",
    "external-analysis-sources": "external-analysis-worker.yml",
    "secondary-security-definitions": "secondary-security-worker.yml",
}


class SecurityOrchestrationDispatchWorkflowTests(unittest.TestCase):
    def test_router_exists_and_routes_every_policy_worker(self):
        text = (WF / "security-orchestration-dispatch.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        top = text[: text.index("\njobs:")]
        self.assertIn("group: omega-security-dispatch-${{ inputs.mode }}-", top)
        self.assertIn("inputs.queue_id, inputs.work_id", top)
        self.assertIn("cancel-in-progress: false", top)
        self.assertNotIn("queue: max", top)
        self.assertIn("uses: ./.github/workflows/security-reconcile.yml", text)
        for queue_id, workflow in WORKERS.items():
            self.assertIn(queue_id, text)
            self.assertIn(f"uses: ./.github/workflows/{workflow}", text)

    def test_workers_are_reusable_and_wake_registered_router(self):
        for workflow in WORKERS.values():
            text = (WF / workflow).read_text(encoding="utf-8")
            self.assertIn("workflow_call:", text, workflow)
            self.assertIn("gh workflow run security-orchestration-dispatch.yml", text, workflow)
            self.assertIn("-f mode=reconcile", text, workflow)
            self.assertNotIn("gh workflow run security-reconcile.yml", text, workflow)

    def test_reconciler_dispatches_queue_identity_through_router(self):
        text = (WF / "security-reconcile.yml").read_text(encoding="utf-8")
        self.assertIn("row['queueId']", text)
        self.assertIn("gh workflow run security-orchestration-dispatch.yml", text)
        self.assertIn("-f mode=worker", text)
        self.assertIn('-f queue_id="$queue_id"', text)
        self.assertIn("redispatch_active_leases", text)
        self.assertIn("for attempt in 1 2 3", text)
        self.assertNotIn('gh workflow run "$workflow"', text)

    def test_parallel_drain_does_not_mutate_collector_leases(self):
        text = (WF / "sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        self.assertIn("group: omega-catalog-sigmascope-exclusive", text)
        self.assertIn("gh workflow run sigmascope-parallel-drain.yml", text)
        self.assertIn("--ref sigmascope", text)
        self.assertNotIn("gh workflow run security-orchestration-dispatch.yml", text)
        self.assertNotIn("gh workflow run security-reconcile.yml", text)
        self.assertNotIn("redispatch_active_leases: true", text)

    def test_release_intake_uses_existing_router_and_separate_writer_queue(self):
        router = (WF / "security-orchestration-dispatch.yml").read_text(encoding="utf-8")
        reconcile = (WF / "security-reconcile.yml").read_text(encoding="utf-8")
        intake = (WF / "catalog-release-intake.yml").read_text(encoding="utf-8")
        self.assertIn("reconcile|release-intake)", router)
        self.assertIn("uses: ./.github/workflows/catalog-release-intake.yml", router)
        self.assertIn("catalog_release_intake.py ready", reconcile)
        self.assertIn("-f mode=release-intake", reconcile)
        self.assertNotIn("uses: ./.github/workflows/catalog-release-intake.yml", reconcile)
        self.assertIn("workflow_call:", intake)
        self.assertIn("group: omega-catalog-sigmascope-exclusive", intake)
        self.assertIn("queue: max", intake)
        self.assertIn("catalog_release_intake.py build", intake)
        self.assertIn("--history-mode fast-forward --push", intake)
        self.assertIn('--expected-parent-sha "$(git -C catalog/current-state rev-parse HEAD)"', intake)
        self.assertIn("steps.intake.outputs.changed == 'true'", intake)
        self.assertIn("gh workflow run sigmascope-drain-wake.yml", intake)
        self.assertLess(intake.index("publish_catalog_state.py"), intake.index("gh workflow run sigmascope-drain-wake.yml"))
        self.assertNotIn("gh workflow run sigmascope-parallel-drain.yml", intake)
        self.assertNotIn("definitions_snapshot.py", intake)
        self.assertNotIn("catalog-client-publish.yml", intake)


if __name__ == "__main__":
    unittest.main()

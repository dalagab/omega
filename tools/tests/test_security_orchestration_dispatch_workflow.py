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
    "secondary-security-definitions": "secondary-security-worker.yml",
}


class SecurityOrchestrationDispatchWorkflowTests(unittest.TestCase):
    def test_router_exists_and_routes_every_policy_worker(self):
        text = (WF / "security-orchestration-dispatch.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
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

    def test_migration_recovery_wake_uses_router(self):
        text = (WF / "sigmascope-phase4-migration.yml").read_text(encoding="utf-8")
        self.assertIn("gh workflow run security-orchestration-dispatch.yml", text)
        self.assertIn("-f mode=reconcile", text)
        self.assertIn("redispatch_active_leases: true", text)
        self.assertIn("group: omega-sigmascope-phase4-migration", text)
        self.assertNotIn("gh workflow run security-reconcile.yml", text)


if __name__ == "__main__":
    unittest.main()

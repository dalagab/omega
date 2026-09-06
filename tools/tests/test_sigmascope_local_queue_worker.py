from __future__ import annotations

import unittest
import common


class SigmaScopeLocalQueueWorkerContractTests(unittest.TestCase):
    def test_local_worker_uses_fast_forward_expected_parent_publication(self) -> None:
        text = (common.ROOT / "tools" / "security" / "sigmascope_local_queue_worker.py").read_text(encoding="utf-8")
        self.assertIn("omega.sigmascope-local-queue-worker.v1", text)
        self.assertIn("export_branch(repo, \"catalog-data\"", text)
        self.assertIn("export_branch(repo, \"security-evidence-v2\"", text)
        self.assertIn("production_sigmascope_v2_pipeline.py", text)
        self.assertIn("security_developer_audit.py", text)
        self.assertIn("evidence_storage_audit.py", text)
        self.assertIn("publish_security_evidence_v2.py", text)
        self.assertIn("\"--history-mode\", \"fast-forward\"", text)
        self.assertIn("\"--expected-parent-sha\", evidence_head", text)
        self.assertIn("if args.push:", text)
        self.assertIn("--preflight-only", text)
        self.assertIn("--sparse-evidence", text)
        self.assertIn("sigmascope_sparse_evidence.py", text)
        self.assertIn("git_snapshot_history.py", text)
        self.assertIn("default_work_dir", text)
        self.assertIn("C:/osl", text)
        self.assertIn("validate_windows_work_dir", text)
        self.assertIn("--allow-long-windows-work-dir", text)
        self.assertIn("core.longpaths=true", text)
        self.assertIn("core.autocrlf=false", text)
        self.assertIn("warning: source follow-up issue reconciliation failed", text)
        self.assertIn("--reconcile-source-followups requires --push", text)
        self.assertGreater(
            text.index("maybe_run_source_followups(args, work, env)"),
            text.index('report["publication"] = json.loads(publication)'),
        )
        self.assertIn("verify_frozen_worker_matches_checkout(repo, catalog)", text)
        self.assertIn("Frozen SigmaScope worker is stale relative to this checkout", text)
        self.assertIn("definitions\" / \"worker\" / \"manifest.json", text)
        self.assertIn("refresh frozen scanner worker", text)
        self.assertNotIn("legacy-orphan", text)
        self.assertNotIn("force-with-lease", text)

    def test_local_worker_does_not_publish_catalog_or_issue_side_effects_by_default(self) -> None:
        text = (common.ROOT / "tools" / "security" / "sigmascope_local_queue_worker.py").read_text(encoding="utf-8")
        self.assertIn("parser.add_argument(\"--push\", action=\"store_true\"", text)
        self.assertIn("parser.add_argument(\"--reconcile-source-followups\", action=\"store_true\"", text)
        self.assertNotIn("publish_catalog_state.py", text)
        self.assertNotIn("catalog-client-publish.yml", text)
        self.assertNotIn("gh workflow run", text)

    def test_local_queue_powershell_wrapper_reports_summary(self) -> None:
        text = (common.ROOT / "tools" / "security" / "run_sigmascope_local_queue.ps1").read_text(encoding="utf-8")
        self.assertIn("sigmascope_local_queue_worker.py", text)
        self.assertIn("local-sigmascope-queue-worker-report.json", text)
        self.assertIn("sigmascope-report-*.json", text)
        self.assertIn("Batch summary", text)
        self.assertIn("previousHead", text)
        self.assertIn("newHead", text)
        self.assertIn("SkipSourceFollowupReconcile", text)
        self.assertIn("MaxNewFollowups = 0", text)
        self.assertIn("MaxCloseFollowups = 100", text)
        self.assertIn("--reconcile-source-followups", text)


if __name__ == "__main__":
    unittest.main()

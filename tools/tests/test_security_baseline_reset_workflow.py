from __future__ import annotations

from pathlib import Path
import unittest

import common


class SecurityBaselineResetWorkflowTests(unittest.TestCase):
    def test_reset_workflow_preserves_contracts_and_retires_phase4_workloads(self) -> None:
        workflow = (
            common.ROOT / ".github" / "workflows" / "security-baseline-reset.yml"
        ).read_text(encoding="utf-8")

        for required in (
            "confirm_reset:",
            "group: omega-catalog-sigmascope-exclusive",
            "queue: max",
            "reset_security_baseline.py",
            "catalog_json_store.py materialize",
            "scan_queue.py build-seed",
            "catalog_state.py assemble",
            "publish_security_evidence_v2.py",
            "--history-mode fast-forward",
            "--expected-parent-sha",
            "publish_deep_scan_state.py",
            "publish_catalog_state.py",
            "catalog-client-publish.yml",
            "authority_lock_held: true",
            "gh workflow run sigmascope-parallel-drain.yml",
            "-f workers=4",
            "-f items_per_worker=10",
        ):
            self.assertIn(required, workflow)

        self.assertIn(
            "cmp catalog/active-state/catalog/index.json "
            "catalog/security-reset/catalog-state/catalog/index.json",
            workflow,
        )
        self.assertIn(
            "cmp catalog/active-state/definitions/index.json "
            "catalog/security-reset/catalog-state/definitions/index.json",
            workflow,
        )

        retired = (
            "sigmascope-phase4-migration.yml",
            "sigmascope-phase4-cutover-core.yml",
            "sigmascope-parallel-shadow.yml",
            "sigmascope-parallel-publish.yml",
        )
        self.assertTrue(
            (common.ROOT / ".github" / "workflows" / "sigmascope-parallel-worker.yml").is_file(),
            "exact result worker remains available for the production parallel refill path",
        )
        for name in retired:
            self.assertFalse(
                (common.ROOT / ".github" / "workflows" / name).exists(),
                f"{name} must no longer be an executable GitHub Actions workload",
            )
            self.assertTrue(
                (common.ROOT / ".github" / "retired-workflows" / "phase4" / name).is_file(),
                f"{name} should remain archived for forensic/history reference",
            )


if __name__ == "__main__":
    unittest.main()

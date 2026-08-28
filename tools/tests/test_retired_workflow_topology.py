from __future__ import annotations

from pathlib import Path
import unittest

import common


class RetiredWorkflowTopologyTests(unittest.TestCase):
    def test_obsolete_workflows_are_archived_not_executable(self) -> None:
        active = common.ROOT / ".github" / "workflows"
        retired = common.ROOT / ".github" / "retired-workflows"
        expected = {
            "catalog-compaction.yml": retired / "legacy" / "catalog-compaction.yml",
            "security-baseline-reset.yml": retired / "recovery" / "security-baseline-reset.yml",
            "srl-cutover-readiness.yml": retired / "cutover" / "srl-cutover-readiness.yml",
            "sigmascope-parallel-worker.yml": retired / "phase4" / "sigmascope-parallel-worker.yml",
        }
        for name, archive in expected.items():
            self.assertFalse((active / name).exists(), name)
            self.assertTrue(archive.is_file(), str(archive))

    def test_current_production_entrypoints_remain_active(self) -> None:
        active = common.ROOT / ".github" / "workflows"
        for name in (
            "catalog-builder.yml",
            "catalog-client-publish.yml",
            "security-orchestration-dispatch.yml",
            "security-reconcile.yml",
            "sigmascope.yml",
            "sigmascope-parallel-drain.yml",
            "deep-scan.yml",
            "rift-evidence-ingest.yml",
            "worker-images.yml",
        ):
            self.assertTrue((active / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()

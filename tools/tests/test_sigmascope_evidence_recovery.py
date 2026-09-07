from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import common

SECURITY = common.ROOT / "tools" / "security"
CATALOG = common.ROOT / "tools" / "catalog"
for root in (SECURITY, CATALOG):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

import sigmascope_evidence_recovery as recovery  # noqa: E402


class SigmaScopeEvidenceRecoveryTests(unittest.TestCase):
    def _json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def _variant(self, variant_id: int, artifact: str, scan_id: int) -> dict[str, object]:
        return {
            "schema": "omega.security-evidence.variant.v2",
            "variantId": variant_id,
            "analysis": {
                "analysisId": f"analysis-{scan_id}",
                "artifactSha256": artifact * 64,
                "path": f"artifacts/{artifact * 2}/{artifact * 64}/analyses/analysis-{scan_id}",
            },
            "current": {
                "scan_id": scan_id,
                "artifact_sha256": artifact * 64,
                "artifact_url": f"https://example.invalid/{artifact}.zip",
                "assembly_version": f"1.0.{scan_id}.0",
                "status": "complete",
            },
            "lifecycle": {"schema": "omega.security-evidence.variant-lifecycle.v1", "state": "active"},
        }

    def test_stage_retained_union_keeps_missing_variant_and_archives_replaced_current(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-evidence-recovery-") as td:
            root = Path(td)
            retained = root / "retained"
            current = root / "current"
            candidate = root / "candidate"
            self._json(retained / "index.json", {"schema": "omega.security-evidence.v2", "formatVersion": 2, "revisions": {"catalogIdentityEpoch": "epoch"}})
            self._json(current / "index.json", {"schema": "omega.security-evidence.v2", "formatVersion": 2, "revisions": {"catalogIdentityEpoch": "epoch"}})
            self._json(retained / "variants/0000/7.json", self._variant(7, "a", 1))
            self._json(retained / "variants/0000/8.json", self._variant(8, "c", 3))
            self._json(current / "variants/0000/7.json", self._variant(7, "b", 2))
            self._json(current / recovery.SPARSE_MARKER, {"schema": "omega.sigmascope.sparse-evidence.v1"})

            fake_plugins = {"path": "indexes/plugins.json", "sha256": "1" * 64}
            fake_artifacts = {"path": "indexes/artifacts.json", "sha256": "2" * 64}
            with patch.object(
                recovery,
                "_build_plugins_artifacts_indexes",
                return_value=(fake_plugins, fake_artifacts, 2, 0, 1, 3, 3),
            ):
                staged = recovery.stage_retained_union(current, retained, candidate)

            current_seven = json.loads((candidate / "variants/0000/7.json").read_text(encoding="utf-8"))
            retained_eight = json.loads((candidate / "variants/0000/8.json").read_text(encoding="utf-8"))
            self.assertEqual("b" * 64, current_seven["current"]["artifact_sha256"])
            self.assertEqual("c" * 64, retained_eight["current"]["artifact_sha256"])
            history = list((candidate / "history/variants/0000/7").glob("*.json"))
            self.assertEqual(1, len(history))
            archived = json.loads(history[0].read_text(encoding="utf-8"))
            self.assertEqual("a" * 64, archived["current"]["artifact_sha256"])
            self.assertEqual("superseded", archived["lifecycle"]["state"])
            self.assertFalse((candidate / recovery.SPARSE_MARKER).exists())
            self.assertTrue(staged["sparseAuthorityMarkerRemoved"])
            self.assertEqual(1, staged["currentMerge"]["historicalSnapshotsArchived"])

    def test_stage_retained_union_archives_replaced_terminal_before_current_wins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-evidence-terminal-recovery-") as td:
            root = Path(td)
            retained = root / "retained"
            current = root / "current"
            candidate = root / "candidate"
            self._json(retained / "index.json", {"schema": "omega.security-evidence.v2", "formatVersion": 2, "revisions": {"catalogIdentityEpoch": "epoch"}})
            self._json(current / "index.json", {"schema": "omega.security-evidence.v2", "formatVersion": 2, "revisions": {"catalogIdentityEpoch": "epoch"}})
            retained_terminal = self._variant(1130, "a", 10)
            retained_terminal["lifecycle"] = {"schema": "omega.security-evidence.variant-lifecycle.v1", "state": "retired"}
            current_terminal = self._variant(1130, "a", 20)
            current_terminal["lifecycle"] = {"schema": "omega.security-evidence.variant-lifecycle.v1", "state": "retired"}
            self._json(retained / "terminal/variants/0001/1130.json", retained_terminal)
            self._json(current / "terminal/variants/0001/1130.json", current_terminal)

            fake_plugins = {"path": "indexes/plugins.json", "sha256": "1" * 64}
            fake_artifacts = {"path": "indexes/artifacts.json", "sha256": "2" * 64}
            with patch.object(
                recovery,
                "_build_plugins_artifacts_indexes",
                return_value=(fake_plugins, fake_artifacts, 0, 1, 1, 2, 1),
            ):
                staged = recovery.stage_retained_union(current, retained, candidate)

            terminal = json.loads((candidate / "terminal/variants/0001/1130.json").read_text(encoding="utf-8"))
            self.assertEqual(20, terminal["current"]["scan_id"])
            history = list((candidate / "history/variants/0001/1130").glob("*.json"))
            self.assertEqual(1, len(history))
            archived = json.loads(history[0].read_text(encoding="utf-8"))
            self.assertEqual(10, archived["current"]["scan_id"])
            self.assertEqual("superseded", archived["lifecycle"]["state"])
            self.assertEqual("recovery_current_terminal_wins", archived["lifecycle"]["reason"])
            self.assertEqual(1, staged["currentTerminalOverlay"]["terminalSnapshotsArchived"])

    def test_recovery_contract_uses_only_current_queue_progress(self) -> None:
        text = (common.ROOT / "tools" / "security" / "sigmascope_evidence_recovery.py").read_text(encoding="utf-8")
        self.assertIn('previous_queue = scan_queue.load_state(current_evidence / "scanner-queue.json")', text)
        self.assertIn("queue_state = scan_queue.sync_state(queue_seed, previous_queue)", text)
        self.assertNotIn('scan_queue.load_state(retained_evidence / "scanner-queue.json")', text)
        self.assertIn('"newScans": 0', text)
        self.assertIn("_merge_successful_subset(candidate, current_evidence)", text)
        self.assertIn("validate_snapshot(candidate, require_no_orphans=True)", text)
        self.assertIn("SPARSE_MARKER", text)
        self.assertIn("_snapshot_identity_keys(retained_evidence)", text)
        self.assertIn("missingRetainedSnapshotIdentities", text)

    def test_recovery_workflow_is_callable_serialized_and_fast_forward_only(self) -> None:
        workflow = (common.ROOT / ".github" / "workflows" / "sigmascope-evidence-recovery.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_call:", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("omega-catalog-sigmascope-exclusive", workflow)
        self.assertIn("4011b37068c83821c5633f33e885230f50f4de37", workflow)
        self.assertIn("sigmascope_evidence_recovery.py", workflow)
        self.assertIn("verify_frozen_worker_matches_checkout", workflow)
        self.assertIn("--history-mode fast-forward", workflow)
        self.assertIn("--expected-parent-sha", workflow)
        self.assertNotIn("force-with-lease", workflow)
        self.assertNotIn("publish_deep_scan_state.py", workflow)
        self.assertIn("publish:", workflow)
        self.assertIn("default: false", workflow)


if __name__ == "__main__":
    unittest.main()

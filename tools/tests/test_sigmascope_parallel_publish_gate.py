from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

import common

SECURITY = common.ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import sigmascope_parallel_preflight as preflight  # noqa: E402
import sigmascope_parallel_publish_gate as gate  # noqa: E402


class SigmascopeParallelPublishGateTests(unittest.TestCase):
    def write(self, path: Path, value: object) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return path

    def fixture(self, root: Path) -> dict[str, Path | str]:
        current = root / "current"
        candidate = root / "candidate"
        current.mkdir(); candidate.mkdir()
        self.write(current / "index.json", {"schema": "omega.security-evidence.v2", "value": "base"})
        self.write(candidate / "index.json", {"schema": "omega.security-evidence.v2", "value": "candidate"})
        self.write(candidate / "validation-report.json", {"schema": "omega.security-evidence.snapshot-validation.v2", "ok": True, "errors": []})
        base_index = gate.sha256_file(current / "index.json")
        candidate_index = gate.sha256_file(candidate / "index.json")
        merge = self.write(root / "shadow-merge.json", {
            "schema": "omega.sigmascope-result-merge.v1",
            "authority": "candidate-only-no-evidence-publication",
            "mergeRevision": "merge-fixture",
            "baseIndexSha256": base_index,
            "candidateIndexSha256": candidate_index,
            "bundleRevisions": ["bundle-b", "bundle-a"],
            "variantIds": [2, 1],
            "validation": {"ok": True},
            "deferredSideEffects": ["Evidence-v2-publication"],
        })
        equivalence = self.write(root / "equivalence.json", {
            "schema": "omega.sigmascope-merge-equivalence.v1", "equivalent": True,
            "mismatches": [], "equivalenceRevision": "eq-fixture",
        })
        validation = self.write(root / "shadow-validation.json", {"schema": "omega.security-evidence.snapshot-validation.v2", "ok": True, "errors": []})
        audit = self.write(root / "audit.json", {"schema": "omega.security-developer-audit.v1", "counts": {"fail": 0, "warn": 0, "pass": 4}})
        storage = self.write(root / "storage.json", {"schema": "omega.security-evidence.storage-audit.v1", "files": 5, "bytes": 50})
        preflight_path = root / "preflight.json"
        base_head = "a" * 40
        preflight.build(
            merge_report=merge,
            equivalence_report=equivalence,
            candidate_validation=validation,
            developer_audit=audit,
            storage_audit=storage,
            base_evidence_git_head=base_head,
            source_run_id="1234",
            source_run_attempt="2",
            output=preflight_path,
        )
        reconstructed = self.write(root / "reconstructed-merge.json", {
            "schema": "omega.sigmascope-result-merge.v1",
            "authority": "candidate-only-no-evidence-publication",
            "mergeRevision": "merge-reconstructed",
            "baseIndexSha256": base_index,
            "candidateIndexSha256": candidate_index,
            "bundleRevisions": ["bundle-a", "bundle-b"],
            "variantIds": [1, 2],
        })
        deep = self.write(root / "deep.json", {"schema": "omega.deep-scan-queue.v1", "items": {}})
        follow = self.write(root / "followups.json", {"schema": "omega.sigmascope.source-followups.v1", "items": []})
        return {
            "current": current, "candidate": candidate, "merge": merge, "equivalence": equivalence,
            "validation": validation, "audit": audit, "storage": storage, "preflight": preflight_path,
            "reconstructed": reconstructed, "deep": deep, "follow": follow, "base_head": base_head,
        }

    def test_authorization_binds_shadow_hashes_candidate_and_exact_git_parent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = self.fixture(Path(td))
            output = Path(td) / "authorization.json"
            auth = gate.authorize(
                preflight_path=f["preflight"],
                shadow_reports={
                    "merge": f["merge"], "equivalence": f["equivalence"],
                    "candidateValidation": f["validation"], "developerAudit": f["audit"],
                    "storageAudit": f["storage"],
                },
                current_evidence=f["current"], current_evidence_git_head=f["base_head"],
                candidate=f["candidate"], reconstructed_merge_report=f["reconstructed"],
                deep_scan_index=f["deep"], source_followups=f["follow"], output=output,
            )
            self.assertTrue(auth["authorized"])
            self.assertEqual(gate.AUTHORITY, auth["authority"])
            self.assertEqual(f["base_head"], auth["expectedParentHead"])
            gate.verify_authorization(auth)

            state = gate.check_current(
                authorization_path=output, candidate=f["candidate"], current_evidence=f["current"],
                current_head=f["base_head"], current_parent="", output=Path(td) / "state.json",
            )
            self.assertEqual("ready-to-publish", state["state"])

    def test_retry_accepts_only_immediate_child_with_exact_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = self.fixture(Path(td))
            auth_path = Path(td) / "authorization.json"
            gate.authorize(
                preflight_path=f["preflight"],
                shadow_reports={
                    "merge": f["merge"], "equivalence": f["equivalence"],
                    "candidateValidation": f["validation"], "developerAudit": f["audit"],
                    "storageAudit": f["storage"],
                },
                current_evidence=f["current"], current_evidence_git_head=f["base_head"],
                candidate=f["candidate"], reconstructed_merge_report=f["reconstructed"],
                deep_scan_index=f["deep"], source_followups=f["follow"], output=auth_path,
            )
            published = Path(td) / "published"
            published.mkdir()
            (published / "index.json").write_bytes((f["candidate"] / "index.json").read_bytes())
            state = gate.check_current(
                authorization_path=auth_path, candidate=f["candidate"], current_evidence=published,
                current_head="d" * 40, current_parent=f["base_head"], output=Path(td) / "retry-state.json",
            )
            self.assertEqual("already-published-immediate-child", state["state"])
            with self.assertRaisesRegex(ValueError, "stale"):
                gate.check_current(
                    authorization_path=auth_path, candidate=f["candidate"], current_evidence=published,
                    current_head="e" * 40, current_parent="d" * 40, output=Path(td) / "stale.json",
                )

    def test_tampered_shadow_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            f = self.fixture(Path(td))
            Path(f["equivalence"]).write_text('{"equivalent":false}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                gate.authorize(
                    preflight_path=f["preflight"],
                    shadow_reports={
                        "merge": f["merge"], "equivalence": f["equivalence"],
                        "candidateValidation": f["validation"], "developerAudit": f["audit"],
                        "storageAudit": f["storage"],
                    },
                    current_evidence=f["current"], current_evidence_git_head=f["base_head"],
                    candidate=f["candidate"], reconstructed_merge_report=f["reconstructed"],
                    deep_scan_index=f["deep"], source_followups=f["follow"], output=Path(td) / "authorization.json",
                )


if __name__ == "__main__":
    unittest.main()

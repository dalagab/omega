from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

import common

SECURITY = common.ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import sigmascope_parallel_preflight  # noqa: E402


class SigmascopeParallelPreflightTests(unittest.TestCase):
    def _json(self, path: Path, value: object) -> None:
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def test_preflight_requires_all_shadow_gates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._json(root / "merge.json", {
                "schema": "omega.sigmascope-result-merge.v1",
                "authority": "candidate-only-no-evidence-publication", "mergeRevision": "merge-1",
                "baseIndexSha256": "b" * 64, "candidateIndexSha256": "a" * 64, "bundleRevisions": ["b1"], "variantIds": [1],
                "validation": {"ok": True}, "deferredSideEffects": ["Evidence-v2-publication"],
            })
            self._json(root / "equivalence.json", {"equivalent": True, "mismatches": [], "equivalenceRevision": "eq-1"})
            self._json(root / "validation.json", {"ok": True, "errors": []})
            self._json(root / "audit.json", {"counts": {"fail": 0, "warn": 1, "pass": 10}})
            self._json(root / "storage.json", {"schema": "omega.security-evidence.storage-audit.v1", "files": 10, "bytes": 1000})
            result = sigmascope_parallel_preflight.build(
                merge_report=root / "merge.json", equivalence_report=root / "equivalence.json",
                candidate_validation=root / "validation.json", developer_audit=root / "audit.json",
                storage_audit=root / "storage.json", base_evidence_git_head="c" * 40,
                source_run_id="123", source_run_attempt="1", output=root / "preflight.json",
            )
            self.assertTrue(result["publishable"])
            self.assertEqual("preflight-only-no-evidence-publication", result["authority"])
            self.assertTrue(all(gate["passed"] for gate in result["gates"]))
            self.assertEqual("c" * 40, result["baseEvidenceGitHead"])
            self.assertEqual("b" * 64, result["baseIndexSha256"])
            self.assertEqual("123", result["sourceRun"]["id"])
            self.assertEqual(5, len(result["inputReports"]))

            self._json(root / "equivalence.json", {"equivalent": False, "mismatches": [{"area": "scanner-queue"}], "equivalenceRevision": "eq-2"})
            failed = sigmascope_parallel_preflight.build(
                merge_report=root / "merge.json", equivalence_report=root / "equivalence.json",
                candidate_validation=root / "validation.json", developer_audit=root / "audit.json",
                storage_audit=root / "storage.json", base_evidence_git_head="c" * 40,
                source_run_id="123", source_run_attempt="1", output=root / "preflight-failed.json",
            )
            self.assertFalse(failed["publishable"])
            gate = next(item for item in failed["gates"] if item["id"] == "serialized.equivalence")
            self.assertFalse(gate["passed"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import common


def remove_readonly(func, path, _exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)

SECURITY = common.ROOT / "tools" / "security"
if str(SECURITY) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(SECURITY))

import sigmascope_sparse_evidence
from security_evidence_v2 import validate_snapshot


class SparseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temp_parent = Path(os.environ.get("OMEGA_TEST_TMP") or (r"C:\tmp" if os.name == "nt" and Path(r"C:\tmp").is_dir() else tempfile.gettempdir()))
        self.root = Path(tempfile.mkdtemp(prefix="omega-sparse-evidence-test-", dir=temp_parent))
        self.repo = self.root / "repo"
        self.repo.mkdir(parents=True)
        subprocess.run(["git", "init"], cwd=self.repo, check=True, stdout=subprocess.PIPE)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=self.repo, check=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True, onexc=remove_readonly)

    def write_json(self, relpath: str, value: dict) -> None:
        path = self.repo / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def test_builds_valid_filtered_view_for_selected_queue_key(self) -> None:
        variant = {
            "schema": "omega.security-evidence.variant.v2",
            "variantId": 7,
            "analysis": {"analysisId": "analysis-7", "artifactSha256": "a" * 64, "path": "artifacts/aa/" + "a" * 64 + "/analyses/analysis-7"},
            "current": {"scan_id": 7, "status": "failed", "artifact_sha256": "a" * 64, "report_json": {}},
            "lifecycle": {"schema": "omega.security-evidence.variant-lifecycle.v1", "state": "active", "terminal": False, "rescanEligible": True},
        }
        self.write_json("variants/0000/7.json", variant)
        self.write_json("artifacts/aa/" + "a" * 64 + "/analyses/analysis-7/manifest.json", {"artifactSha256": "a" * 64})
        self.write_json("indexes/plugins.json", {
            "schema": "omega.security-evidence.plugins-index.v2",
            "lifecycleContractVersion": 1,
            "currentVariants": [{"variantId": 7, "variantPath": "variants/0000/7.json", "artifactSha256": "a" * 64, "analysisId": "analysis-7", "summary": None}],
            "terminalVariants": [],
            "historicalSnapshots": [],
        })
        self.write_json("indexes/artifacts.json", {"schema": "omega.security-evidence.artifacts-index.v2", "artifacts": [{"artifactSha256": "a" * 64, "variants": [7], "currentVariants": [7], "historicalSnapshots": [], "analyses": ["analysis-7"]}]})
        self.write_json("scanner-queue.json", {"schema": "omega.sigmascope.queue-state.v2", "catalogIdentityEpoch": "epoch", "items": {"variant-7": {"queueKey": "variant-7", "variantId": 7, "workType": "artifact"}}})
        self.write_json("index.json", {"schema": "omega.security-evidence.v2", "formatVersion": 2, "counts": {"analyses": 0, "artifactGroups": 1, "currentVariants": 1, "terminalVariants": 0, "historicalSnapshots": 0}, "indexes": {"plugins": {"path": "indexes/plugins.json"}, "artifacts": {"path": "indexes/artifacts.json"}}, "revisions": {"evidenceRevision": "ev-test", "catalogIdentityEpoch": "epoch"}, "scannerQueue": {"path": "scanner-queue.json"}})
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "fixture"], cwd=self.repo, check=True, stdout=subprocess.PIPE)

        out = self.root / "sparse"
        report = sigmascope_sparse_evidence.build_sparse_view(self.repo, "HEAD", ["variant-7"], out)

        self.assertEqual([7], report["variantIds"])
        self.assertTrue((out / ".sigmascope-sparse-evidence.json").exists() is False)
        validation = validate_snapshot(out, require_no_orphans=False)
        self.assertTrue(validation.get("ok"), validation.get("errors"))


if __name__ == "__main__":
    unittest.main()

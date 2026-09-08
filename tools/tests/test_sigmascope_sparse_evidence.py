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

        source_index_sha256 = sigmascope_sparse_evidence.sha256_bytes((self.repo / "index.json").read_bytes())
        out = self.root / "sparse"
        report = sigmascope_sparse_evidence.build_sparse_view(self.repo, "HEAD", ["variant-7"], out)

        self.assertEqual([7], report["variantIds"])
        self.assertEqual(source_index_sha256, report["sourceIndexSha256"])
        self.assertTrue((out / ".sigmascope-sparse-evidence.json").exists() is False)
        sparse_index = json.loads((out / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(source_index_sha256, sparse_index["sparseEvidenceView"]["sourceIndexSha256"])
        self.assertNotEqual(source_index_sha256, sigmascope_sparse_evidence.sha256_bytes((out / "index.json").read_bytes()))
        validation = validate_snapshot(out, require_no_orphans=False)
        self.assertTrue(validation.get("ok"), validation.get("errors"))

    def test_shared_completed_analysis_is_counted_once(self) -> None:
        artifact_sha = "b" * 64
        analysis_id = "analysis-shared"
        analysis_path = f"artifacts/{artifact_sha[:2]}/{artifact_sha}/analyses/{analysis_id}"
        current_rows = []
        queue_items = {}
        for variant_id in (7, 8):
            variant_path = f"variants/0000/{variant_id}.json"
            self.write_json(variant_path, {
                "schema": "omega.security-evidence.variant.v2",
                "variantId": variant_id,
                "analysis": {
                    "analysisId": analysis_id,
                    "artifactSha256": artifact_sha,
                    "path": analysis_path,
                },
                "current": {
                    "scan_id": variant_id,
                    "status": "complete",
                    "artifact_sha256": artifact_sha,
                    "report_json": {},
                },
                "lifecycle": {
                    "schema": "omega.security-evidence.variant-lifecycle.v1",
                    "state": "active",
                    "terminal": False,
                    "rescanEligible": True,
                },
            })
            current_rows.append({
                "variantId": variant_id,
                "variantPath": variant_path,
                "artifactSha256": artifact_sha,
                "analysisId": analysis_id,
                "summary": None,
            })
            queue_items[f"variant-{variant_id}"] = {
                "queueKey": f"variant-{variant_id}",
                "variantId": variant_id,
                "workType": "artifact",
            }

        self.write_json(f"{analysis_path}/manifest.json", {
            "analysisId": analysis_id,
            "artifactSha256": artifact_sha,
            "datasets": {},
        })
        self.write_json("indexes/plugins.json", {
            "schema": "omega.security-evidence.plugins-index.v2",
            "lifecycleContractVersion": 1,
            "currentVariants": current_rows,
            "terminalVariants": [],
            "historicalSnapshots": [],
        })
        self.write_json("indexes/artifacts.json", {
            "schema": "omega.security-evidence.artifacts-index.v2",
            "artifacts": [{
                "artifactSha256": artifact_sha,
                "variants": [7, 8],
                "currentVariants": [7, 8],
                "terminalSnapshots": [],
                "historicalSnapshots": [],
                "analyses": [{"analysisId": analysis_id}],
            }],
        })
        self.write_json("scanner-queue.json", {
            "schema": "omega.sigmascope.queue-state.v2",
            "catalogIdentityEpoch": "epoch",
            "items": queue_items,
        })
        self.write_json("index.json", {
            "schema": "omega.security-evidence.v2",
            "formatVersion": 2,
            "counts": {
                "analyses": 1,
                "artifactGroups": 1,
                "currentVariants": 2,
                "terminalVariants": 0,
                "historicalSnapshots": 0,
            },
            "indexes": {
                "plugins": {"path": "indexes/plugins.json"},
                "artifacts": {"path": "indexes/artifacts.json"},
            },
            "revisions": {"evidenceRevision": "ev-shared", "catalogIdentityEpoch": "epoch"},
            "scannerQueue": {"path": "scanner-queue.json"},
        })
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "shared-analysis-fixture"], cwd=self.repo, check=True, stdout=subprocess.PIPE)

        out = self.root / "sparse-shared"
        sigmascope_sparse_evidence.build_sparse_view(
            self.repo, "HEAD", ["variant-7", "variant-8"], out
        )
        sparse_index = json.loads((out / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(2, sparse_index["counts"]["currentVariants"])
        self.assertEqual(1, sparse_index["counts"]["analyses"])


if __name__ == "__main__":
    unittest.main()

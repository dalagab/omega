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
from plugin_index_transport import (
    PLUGIN_INDEX_LEGACY_SCHEMA,
    PLUGIN_INDEX_SCHEMA,
    write_plugin_index,
)
from security_evidence_v2 import validate_snapshot


class SparseEvidenceV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        temp_parent = Path(
            os.environ.get("OMEGA_TEST_TMP")
            or (
                r"C:\tmp"
                if os.name == "nt" and Path(r"C:\tmp").is_dir()
                else tempfile.gettempdir()
            )
        )
        self.root = Path(tempfile.mkdtemp(prefix="omega-sparse-evidence-v3-test-", dir=temp_parent))
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
        path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_v3_authority_materializes_valid_inline_sparse_view(self) -> None:
        rows = []
        artifacts = []
        queue_items = {}
        for variant_id, digest_char in ((7, "a"), (8, "b")):
            artifact_sha = digest_char * 64
            analysis_id = f"analysis-{variant_id}"
            variant_path = f"variants/0000/{variant_id}.json"
            analysis_path = f"artifacts/{artifact_sha[:2]}/{artifact_sha}/analyses/{analysis_id}"
            self.write_json(
                variant_path,
                {
                    "schema": "omega.security-evidence.variant.v2",
                    "variantId": variant_id,
                    "analysis": {
                        "analysisId": analysis_id,
                        "artifactSha256": artifact_sha,
                        "path": analysis_path,
                    },
                    "current": {
                        "scan_id": variant_id,
                        "status": "failed",
                        "artifact_sha256": artifact_sha,
                        "report_json": {},
                    },
                    "lifecycle": {
                        "schema": "omega.security-evidence.variant-lifecycle.v1",
                        "state": "active",
                        "terminal": False,
                        "rescanEligible": True,
                    },
                },
            )
            self.write_json(
                f"{analysis_path}/manifest.json",
                {"analysisId": analysis_id, "artifactSha256": artifact_sha, "datasets": {}},
            )
            rows.append(
                {
                    "variantId": variant_id,
                    "variantPath": variant_path,
                    "artifactSha256": artifact_sha,
                    "analysisId": analysis_id,
                    "summary": None,
                }
            )
            artifacts.append(
                {
                    "artifactSha256": artifact_sha,
                    "variants": [variant_id],
                    "currentVariants": [variant_id],
                    "historicalSnapshots": [],
                    "analyses": [analysis_id],
                }
            )
            queue_items[f"variant-{variant_id}"] = {
                "queueKey": f"variant-{variant_id}",
                "variantId": variant_id,
                "workType": "artifact",
            }

        plugin_entry = write_plugin_index(
            self.repo,
            current_variants=rows,
            terminal_variants=[],
            historical_snapshots=[],
            lifecycle_contract_version=1,
            chunk_bytes=256,
        )
        source_manifest = json.loads(
            (self.repo / "indexes" / "plugins.json").read_text(encoding="utf-8")
        )
        self.assertEqual(PLUGIN_INDEX_SCHEMA, source_manifest["schema"])
        self.assertTrue(source_manifest["datasets"]["currentVariants"]["files"])

        self.write_json(
            "indexes/artifacts.json",
            {"schema": "omega.security-evidence.artifacts-index.v2", "artifacts": artifacts},
        )
        self.write_json(
            "scanner-queue.json",
            {
                "schema": "omega.sigmascope.queue-state.v2",
                "catalogIdentityEpoch": "epoch",
                "items": queue_items,
            },
        )
        self.write_json(
            "index.json",
            {
                "schema": "omega.security-evidence.v2",
                "formatVersion": 2,
                "counts": {
                    "analyses": 0,
                    "artifactGroups": 2,
                    "currentVariants": 2,
                    "terminalVariants": 0,
                    "historicalSnapshots": 0,
                },
                "indexes": {
                    "plugins": plugin_entry,
                    "artifacts": {"path": "indexes/artifacts.json"},
                },
                "revisions": {
                    "evidenceRevision": "ev-v3-test",
                    "catalogIdentityEpoch": "epoch",
                },
                "scannerQueue": {"path": "scanner-queue.json"},
            },
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "commit", "-m", "v3-fixture"],
            cwd=self.repo,
            check=True,
            stdout=subprocess.PIPE,
        )

        out = self.root / "sparse"
        report = sigmascope_sparse_evidence.build_sparse_view(
            self.repo,
            "HEAD",
            ["variant-7"],
            out,
        )

        self.assertEqual([7], report["variantIds"])
        self.assertEqual(1, report["currentVariants"])
        sparse_plugins = json.loads(
            (out / "indexes" / "plugins.json").read_text(encoding="utf-8")
        )
        self.assertEqual(PLUGIN_INDEX_LEGACY_SCHEMA, sparse_plugins["schema"])
        self.assertEqual([7], [row["variantId"] for row in sparse_plugins["currentVariants"]])
        self.assertNotIn("datasets", sparse_plugins)
        self.assertNotIn("storage", sparse_plugins)
        self.assertFalse((out / ".sigmascope-plugin-index-source").exists())
        validation = validate_snapshot(out, require_no_orphans=False)
        self.assertTrue(validation.get("ok"), validation.get("errors"))


if __name__ == "__main__":
    unittest.main()

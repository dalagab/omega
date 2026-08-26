from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import common

import sys
for root in (common.ROOT / "tools" / "security", common.ROOT / "tools" / "catalog"):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

import scan_queue  # noqa: E402
import sigmascope  # noqa: E402
import sigmascope_result_bundle  # noqa: E402
import sigmascope_result_merger  # noqa: E402
import test_production_sigmascope_v2_pipeline as production_tests  # noqa: E402
from migrate_security_evidence_v2 import migrate  # noqa: E402
from production_sigmascope_v2_pipeline import _copy_evidence_tree, _merge_successful_subset, synchronize_candidate  # noqa: E402
from security_evidence_v2 import validate_snapshot  # noqa: E402


class SigmascopeResultMergerTests(unittest.TestCase):
    def _json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def _queue_context(self) -> dict[str, object]:
        return {
            "schema": scan_queue.STATE_SCHEMA,
            "queueSeedRevision": "seed-merge-1",
            "catalogRevision": "catalog-merge-1",
            "catalogIdentityEpoch": "epoch-merge-1",
            "baselineSecurityRebuild": False,
            "definitionsRevision": "defs-merge-1",
            "scannerRevision": "scanner-merge-1",
            "scannerBundleSha256": "3" * 64,
            "artifactAnalysisRevision": "artifact-merge-1",
            "sourceAnalysisRevision": "source-merge-1",
            "sourceObservationRevision": "source-observations-merge-1",
            "ruleSetRevision": "rules-merge-1",
            "srlRuleSetRevision": "srl-rules-merge-1",
            "advisoryRevision": "osv-merge-1",
            "selectionPolicy": "coverage-first",
            "reasonContracts": {},
            "srlReprojection": {},
        }

    def test_serialized_merger_reconstructs_valid_candidate_without_publication(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-parallel-merger-") as td:
            root = Path(td)
            helper = production_tests.ProductionSecurityV2PipelineTests(methodName="test_bounded_batch_report_aggregates_multiple_queue_invocations")
            database, variant_id, _plugin_id = helper.make_catalog_with_security(root)
            current = root / "current"
            migrate(database, current, reset=True)
            self.assertTrue(validate_snapshot(current)["ok"])

            # Bind the fixture to the same identity/revision tuple used by the result bundle.
            current_index = json.loads((current / "index.json").read_text(encoding="utf-8"))
            current_index.setdefault("revisions", {}).update({
                "catalogIdentityEpoch": "epoch-merge-1",
                "catalogRevision": "catalog-merge-1",
                "catalogDataRevision": "catalog-merge-1",
            })
            self._json(current / "index.json", current_index)
            before = {
                "queueKey": f"source-variant-{variant_id}", "workType": "source", "variantId": variant_id,
                "targetFingerprint": "target-source-merge", "state": "pending", "attemptCount": 0,
                "priority": 300, "recentAttempts": [], "internalName": "ExamplePlugin", "primaryReason": "source_revision_changed",
            }
            context = self._queue_context()
            self._json(current / "scanner-queue.json", {**context, "updatedAtUtc": "2026-08-26T05:00:00Z", "items": {before["queueKey"]: before}, "recentCompleted": []})

            worker_db = root / "worker.sqlite"
            shutil.copy2(database, worker_db)
            with closing(sqlite3.connect(worker_db)) as db:
                db.row_factory = sqlite3.Row
                scan = dict(db.execute("SELECT * FROM plugin_security_scans WHERE scan_id=9001").fetchone())
                scan["scan_id"] = 9002
                scan["scanned_at_utc"] = "2026-08-26T05:10:00Z"
                columns = list(scan)
                db.execute(
                    f"INSERT INTO plugin_security_scans({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
                    tuple(scan[col] for col in columns),
                )
                for table, pk in (("plugin_security_findings", "finding_id"), ("plugin_security_dependencies", "dependency_id")):
                    rows = [dict(row) for row in db.execute(f"SELECT * FROM {table} WHERE scan_id=9001")]
                    for row in rows:
                        row.pop(pk, None); row["scan_id"] = 9002
                        cols = list(row)
                        db.execute(f"INSERT INTO {table}({','.join(cols)}) VALUES({','.join('?' for _ in cols)})", tuple(row[c] for c in cols))
                db.execute("UPDATE plugin_security_current SET scan_id=9002,scanned_at_utc='2026-08-26T05:10:00Z' WHERE variant_id=?", (variant_id,))
                db.commit()

            subset = root / "worker-subset"
            migrate(worker_db, subset, reset=True, variant_ids={variant_id})
            worker_candidate = root / "worker-candidate"
            _copy_evidence_tree(current, worker_candidate)
            _merge_successful_subset(worker_candidate, subset)
            synchronize_candidate(worker_candidate, worker_db, {variant_id})
            # The result-bundle builder only requires a valid v2 root identity and the exact queue settlement.
            candidate_index = json.loads((worker_candidate / "index.json").read_text(encoding="utf-8"))
            candidate_index.setdefault("revisions", {})["catalogIdentityEpoch"] = "epoch-merge-1"
            self._json(worker_candidate / "index.json", candidate_index)
            after = {
                **before, "state": "complete", "attemptCount": 1, "lastAttemptStatus": "complete",
                "completedAtUtc": "2026-08-26T05:10:00Z",
                "recentAttempts": [{
                    "schema": "omega.sigmascope.queue-attempt.v2", "attemptId": "attempt-merge-1", "attemptNumber": 1,
                    "selectedAtUtc": "2026-08-26T05:09:00Z", "status": "complete", "completedAtUtc": "2026-08-26T05:10:00Z",
                    "error": "", "artifactSha256": "a" * 64, "scanId": 9002,
                }],
            }
            self._json(worker_candidate / "scanner-queue.json", {**context, "updatedAtUtc": after["completedAtUtc"], "items": {before["queueKey"]: after}, "recentCompleted": []})
            work = root / "worker-work"
            self._json(work / "production-sigmascope-v2-report.json", {
                "generatedAtUtc": after["completedAtUtc"], "materialized": {"baselineSecurityRebuild": False},
                "successfulVariantIds": [variant_id], "failedRetainedVariantIds": [],
                "queue": {"selectedItems": [{"queueKey": before["queueKey"], "variantId": variant_id, "workType": "source"}]},
            })
            definitions = root / "definitions"
            self._json(definitions / "index.json", {
                "schema": "omega.definitions.v1", "definitionsRevision": context["definitionsRevision"],
                "scannerRevision": context["scannerRevision"], "scannerBundle": {"sha256": context["scannerBundleSha256"]},
                "artifactAnalysisRevision": context["artifactAnalysisRevision"], "sourceAnalysisRevision": context["sourceAnalysisRevision"],
                "ruleSetRevision": context["ruleSetRevision"], "advisoryRevision": context["advisoryRevision"],
                "osv": {"path": "osv-advisories.json"},
            })
            self._json(definitions / "osv-advisories.json", {
                "schema": "omega.public-advisories.v1", "generatedAtUtc": "2026-08-26T04:00:00Z",
                "source": "OSV", "ecosystem": "NuGet", "queriedPackages": 1, "matchedPackages": 0,
                "queriedPackageVersionPairs": [{"name": "Example.Package", "version": "1.2.3"}], "advisories": [],
            })
            bundle = root / "bundle"
            sigmascope_result_bundle.build(
                current=current, candidate=worker_candidate, work_dir=work, definitions=definitions,
                queue_key=before["queueKey"], worker_image="ghcr.io/dalagab/omega-sigmascope-worker@sha256:" + "c" * 64,
                output=bundle,
            )

            merged_candidate = root / "merged-candidate"
            with patch("sigmascope_result_merger.materialize_definition_provenance_index", return_value={}), \
                 patch("sigmascope_result_merger.materialize_threat_intelligence_index", return_value={}), \
                 patch("sigmascope_result_merger.materialize_srl_reprojection_sidecar", return_value={"enabled": False}):
                result = sigmascope_result_merger.merge(
                    current_evidence=current, base_database=database, definitions=definitions, bundle_roots=[bundle],
                    candidate=merged_candidate, work_dir=root / "merge-work", report=root / "merge-report.json",
                )
            self.assertEqual("candidate-only-no-evidence-publication", result["authority"])
            self.assertTrue(result["validation"]["ok"])
            self.assertEqual([variant_id], result["successfulVariantIds"])
            merged_variant = json.loads(next((merged_candidate / "variants").rglob(f"{variant_id}.json")).read_text(encoding="utf-8"))
            self.assertEqual(9002, int(merged_variant["current"]["scan_id"]))
            queue = json.loads((merged_candidate / "scanner-queue.json").read_text(encoding="utf-8"))
            self.assertEqual("complete", queue["items"][before["queueKey"]]["state"])
            self.assertEqual(9002, int(queue["items"][before["queueKey"]]["recentAttempts"][-1]["scanId"]))
            self.assertTrue(validate_snapshot(merged_candidate)["ok"])

    def test_central_queue_merge_reproduces_artifact_source_followup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-parallel-source-followup-") as td:
            root = Path(td)
            context = self._queue_context()
            self._json(root / "scanner-queue.json", {**context, "items": {}, "recentCompleted": []})
            after = {
                "queueKey": "variant-77", "workType": "artifact", "variantId": 77, "pluginId": 7, "sourceId": 3,
                "internalName": "Example", "name": "Example", "sourceName": "Feed", "assemblyVersion": "1.0.0.0",
                "artifactChannel": "stable", "artifactUrl": "https://example.invalid/plugin.zip",
                "repositoryUrl": "https://github.com/example/plugin", "sourceRepositoryUrl": "",
                "priority": 500, "targetFingerprint": "artifact-target", "state": "complete",
                "completedAtUtc": "2026-08-26T05:10:00Z",
            }
            doc = {"work": {"queueKey": "variant-77", "after": after, "queueContextAfter": context}, "outcome": {"status": "complete"}}
            current_rows = {77: {
                "status": "complete", "scan_id": 9901, "artifact_sha256": "a" * 64,
                "source_repository": "", "source_commit": "", "source_available": 0, "source_to_binary_verified": 0,
            }}
            queue, keys = sigmascope_result_merger._merge_queue(root, [doc], current_rows)
            self.assertEqual(["source-variant-77"], keys)
            followup = queue["items"]["source-variant-77"]
            self.assertEqual("source", followup["workType"])
            self.assertEqual("pending", followup["state"])
            self.assertEqual("source_followup", followup["primaryReason"])
            self.assertEqual(9901, followup["currentScanId"])
            self.assertTrue(followup["dynamic"])



if __name__ == "__main__":
    unittest.main()

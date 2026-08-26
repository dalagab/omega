from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

import common

SECURITY = common.ROOT / "tools" / "security"
CATALOG = common.ROOT / "tools" / "catalog"
for root in (SECURITY, CATALOG):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

import sigmascope_parallel_plan  # noqa: E402
import sigmascope_result_bundle  # noqa: E402


class SigmascopeResultBundleTests(unittest.TestCase):
    def _json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def _fixture(self, root: Path, *, variant_id: int, queue_key: str) -> tuple[Path, Path, Path, Path]:
        current = root / "current"
        candidate = root / "candidate"
        work = root / "work"
        definitions = root / "definitions"
        revisions = {
            "evidenceRevision": "ev-v2-base",
            "securityRevision": "sec-base",
            "catalogRevision": "catalog-base",
            "catalogIdentityEpoch": "epoch-1",
        }
        self._json(current / "index.json", {"schema": "omega.security-evidence.v2", "revisions": revisions})
        self._json(candidate / "index.json", {"schema": "omega.security-evidence.v2", "revisions": {**revisions, "evidenceRevision": "ev-v2-candidate"}})
        before = {
            "queueKey": queue_key, "workType": "artifact", "variantId": variant_id,
            "targetFingerprint": f"target-{variant_id}", "state": "pending", "attemptCount": 0,
            "priority": 500, "recentAttempts": [],
        }
        after = {
            **before, "state": "complete", "attemptCount": 1, "lastAttemptStatus": "complete",
            "recentAttempts": [{"attemptId": f"attempt-{variant_id}", "status": "complete"}],
        }
        queue_context = {
            "schema": "omega.sigmascope.queue-state.v2", "queueSeedRevision": "seed-1",
            "catalogRevision": "catalog-base", "catalogIdentityEpoch": "epoch-1",
            "baselineSecurityRebuild": False, "definitionsRevision": "defs-1",
            "scannerRevision": "scanner-1", "scannerBundleSha256": "3" * 64,
            "artifactAnalysisRevision": "artifact-1", "sourceAnalysisRevision": "source-1",
            "sourceObservationRevision": "source-observations-1", "ruleSetRevision": "rules-1",
            "srlRuleSetRevision": "srl-rules-1", "advisoryRevision": "osv-1",
            "selectionPolicy": "coverage-first",
        }
        self._json(current / "scanner-queue.json", {**queue_context, "queueRevision": "queue-base", "items": {queue_key: before}})
        self._json(candidate / "scanner-queue.json", {**queue_context, "queueRevision": "queue-candidate", "items": {queue_key: after}})
        bucket = f"{variant_id // 1000:04d}"
        old_variant = {
            "schema": "omega.security-evidence.variant.v2", "variantId": variant_id,
            "analysis": {"analysisId": "old", "path": "artifacts/old", "artifactSha256": "1" * 64},
            "current": {"artifact_sha256": "1" * 64}, "derivedEvidence": {},
        }
        new_variant = {
            "schema": "omega.security-evidence.variant.v2", "variantId": variant_id,
            "analysis": {"analysisId": f"new-{variant_id}", "path": f"artifacts/new-{variant_id}", "artifactSha256": "2" * 64},
            "current": {"artifact_sha256": "2" * 64},
            "derivedEvidence": {"urls": {"files": [{"path": f"derived/variants/{bucket}/{variant_id}/urls.jsonl", "sha256": "ignored"}]}},
        }
        self._json(current / "variants" / bucket / f"{variant_id}.json", old_variant)
        self._json(candidate / "variants" / bucket / f"{variant_id}.json", new_variant)
        (candidate / "artifacts" / f"new-{variant_id}").mkdir(parents=True, exist_ok=True)
        (candidate / "artifacts" / f"new-{variant_id}" / "manifest.json").write_text('{"records":1}\n', encoding="utf-8")
        (candidate / "derived" / "variants" / bucket / str(variant_id)).mkdir(parents=True, exist_ok=True)
        (candidate / "derived" / "variants" / bucket / str(variant_id) / "urls.jsonl").write_text('{"url":"https://example.test"}\n', encoding="utf-8")
        self._json(definitions / "index.json", {
            "definitionsRevision": "defs-1", "scannerRevision": "scanner-1",
            "scannerBundle": {"sha256": "3" * 64}, "artifactAnalysisRevision": "artifact-1",
            "sourceAnalysisRevision": "source-1", "ruleSetRevision": "rules-1", "advisoryRevision": "osv-1",
        })
        self._json(work / "production-sigmascope-v2-report.json", {
            "generatedAtUtc": "2026-08-26T06:00:00Z",
            "materialized": {"baselineSecurityRebuild": False},
            "successfulVariantIds": [variant_id], "failedRetainedVariantIds": [],
            "queue": {"selectedItems": [{"queueKey": queue_key, "variantId": variant_id, "workType": "artifact"}]},
        })
        return current, candidate, work, definitions

    def test_bundle_is_content_addressed_bounded_and_tamper_detecting(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            current, candidate, work, definitions = self._fixture(root, variant_id=42, queue_key="variant-42")
            out = root / "bundle"
            doc = sigmascope_result_bundle.build(
                current=current, candidate=candidate, work_dir=work, definitions=definitions,
                queue_key="variant-42", worker_image="ghcr.io/dalagab/omega-sigmascope-worker@sha256:" + "a" * 64,
                output=out,
            )
            self.assertEqual(sigmascope_result_bundle.SCHEMA, doc["schema"])
            self.assertEqual("result-only-no-evidence-publication", doc["authority"])
            self.assertEqual(42, doc["work"]["variantId"])
            self.assertTrue(doc["outcome"]["archivePreviousVariant"])
            paths = [row["path"] for row in doc["payload"]["files"]]
            self.assertIn("variants/0000/42.json", paths)
            self.assertIn("artifacts/new-42/manifest.json", paths)
            self.assertIn("derived/variants/0000/42/urls.jsonl", paths)
            self.assertTrue(all(not path.startswith("indexes/") for path in paths))
            target = out / "payload" / "variants" / "0000" / "42.json"
            target.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                sigmascope_result_bundle.validate(out, current_evidence=current)

    def test_merge_plan_rejects_same_variant_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            current, candidate, work, definitions = self._fixture(root / "a", variant_id=7, queue_key="variant-7")
            one = root / "bundle-a"
            sigmascope_result_bundle.build(current=current, candidate=candidate, work_dir=work, definitions=definitions,
                queue_key="variant-7", worker_image="ghcr.io/x@sha256:" + "b" * 64, output=one)
            # Second bundle deliberately mutates the same variant under a different queue key.
            current2, candidate2, work2, definitions2 = self._fixture(root / "b", variant_id=7, queue_key="source-variant-7")
            # Bind both fixtures to the exact same starting Evidence index bytes.
            (current2 / "index.json").write_bytes((current / "index.json").read_bytes())
            two = root / "bundle-b"
            sigmascope_result_bundle.build(current=current2, candidate=candidate2, work_dir=work2, definitions=definitions2,
                queue_key="source-variant-7", worker_image="ghcr.io/x@sha256:" + "c" * 64, output=two)
            with self.assertRaisesRegex(ValueError, "multiple bundles mutate variant 7"):
                sigmascope_result_bundle.build_plan([one, two], current_evidence=current, output=root / "plan.json")


    def test_merge_plan_rejects_different_frozen_identities(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            current, candidate, work, definitions = self._fixture(root / "a", variant_id=7, queue_key="variant-7")
            one = root / "bundle-a"
            sigmascope_result_bundle.build(current=current, candidate=candidate, work_dir=work, definitions=definitions,
                queue_key="variant-7", worker_image="ghcr.io/x@sha256:" + "b" * 64, output=one)
            current2, candidate2, work2, definitions2 = self._fixture(root / "b", variant_id=8, queue_key="variant-8")
            (current2 / "index.json").write_bytes((current / "index.json").read_bytes())
            defs = json.loads((definitions2 / "index.json").read_text(encoding="utf-8"))
            defs["scannerRevision"] = "scanner-different"
            self._json(definitions2 / "index.json", defs)
            two = root / "bundle-b"
            sigmascope_result_bundle.build(current=current2, candidate=candidate2, work_dir=work2, definitions=definitions2,
                queue_key="variant-8", worker_image="ghcr.io/x@sha256:" + "c" * 64, output=two)
            with self.assertRaisesRegex(ValueError, "different frozen Definitions"):
                sigmascope_result_bundle.build_plan([one, two], current_evidence=current, output=root / "plan.json")

    def test_parallel_plan_selects_disjoint_exact_variant_work_and_blocks_baselines(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "evidence"
            self._json(evidence / "index.json", {"schema": "omega.security-evidence.v2", "revisions": {"evidenceRevision": "ev", "catalogIdentityEpoch": "epoch-1"}})
            items = [
                {"queueKey": "variant-1", "workType": "artifact", "variantId": 1, "targetFingerprint": "a", "priority": 500, "internalName": "A", "sourceName": "S", "reasons": ["baseline_scan"]},
                {"queueKey": "source-variant-2", "workType": "source", "variantId": 2, "targetFingerprint": "b", "priority": 300, "internalName": "B", "sourceName": "S", "reasons": ["source_revision_changed"]},
            ]
            seed = {"schema": "omega.sigmascope.queue-seed.v2", "queueSeedRevision": "seed-1", "catalogIdentityEpoch": "epoch-1", "baselineSecurityRebuild": False, "items": items}
            seed_path = root / "seed.json"; self._json(seed_path, seed)
            plan = sigmascope_parallel_plan.build(seed_path, evidence, max_assignments=4, output=root / "plan.json", now=dt.datetime(2026, 8, 26, 6, tzinfo=dt.timezone.utc))
            self.assertEqual(2, plan["assignmentCount"])
            self.assertEqual({"variant-1", "source-variant-2"}, {row["queueKey"] for row in plan["assignments"]})
            seed["baselineSecurityRebuild"] = True; self._json(seed_path, seed)
            blocked = sigmascope_parallel_plan.build(seed_path, evidence, max_assignments=4, output=root / "blocked.json")
            self.assertEqual(0, blocked["assignmentCount"])
            self.assertEqual("baseline-security-rebuild-requires-serialized-worker", blocked["blockedReason"])


if __name__ == "__main__":
    unittest.main()

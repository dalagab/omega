from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

import common
import test_sqlite_catalog
import catalog_json_store
import scan_queue


NOW = dt.datetime(2026, 8, 19, 10, 0, tzinfo=dt.timezone.utc)


class ScanQueueTests(unittest.TestCase):
    def _catalog(self, root: Path) -> tuple[Path, dict]:
        curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
        built = root / "built"
        test_sqlite_catalog.run_builder(common.ROOT, built, curated, raw, enriched, websites)
        catalog = root / "catalog"
        catalog_json_store.export_snapshot(built / "omega-catalog.sqlite", catalog, source_commit="fixture")
        variants = scan_queue.catalog_variants(catalog)
        self.assertTrue(variants)
        return catalog, variants[0]

    def _definitions(
        self, root: Path, *, defs: str = "defs-v1-fixture", rules: str = "rules-v1-fixture",
        advisory: str = "osv-v1-fixture", artifact_analysis: str = "artifact-analysis-v1-fixture",
        source_analysis: str = "source-analysis-v1-fixture", source_observations: list[dict] | None = None,
        scanner_revision: str = "scanner-v1-fixture",
    ) -> Path:
        target = root / f"definitions-{defs[-7:]}-{rules[-7:]}-{advisory[-7:]}-{scanner_revision[-7:]}"
        target.mkdir(parents=True, exist_ok=True)
        observations = {
            "schema": "omega.source-revision-observations.v1",
            "revision": "source-observations-v1-fixture",
            "repositories": source_observations or [],
        }
        (target / "source-revisions.json").write_text(json.dumps(observations), encoding="utf-8")
        (target / "index.json").write_text(json.dumps({
            "schema": "omega.definitions.v1",
            "definitionsRevision": defs,
            "scannerRevision": scanner_revision,
            "scannerBundle": {"sha256": "b" * 64},
            "artifactAnalysisRevision": artifact_analysis,
            "sourceAnalysisRevision": source_analysis,
            "sourceObservationRevision": "source-observations-v1-fixture",
            "sourceObservations": {"path": "source-revisions.json"},
            "ruleSetRevision": rules,
            "advisoryRevision": advisory,
        }), encoding="utf-8")
        return target

    def _evidence(
        self, root: Path, current: dict | None = None, *, variant_id: int = 0,
        identity_epoch: str | None = None, advisory_revision: str = "osv-v1-fixture",
    ) -> Path:
        target = root / "evidence"
        (target / "indexes").mkdir(parents=True, exist_ok=True)
        entries = []
        if current is not None:
            variant_path = f"plugins/{variant_id}.json"
            (target / "plugins").mkdir(exist_ok=True)
            (target / variant_path).write_text(json.dumps({"variantId": variant_id, "current": current}), encoding="utf-8")
            entries.append({"variantId": variant_id, "variantPath": variant_path})
        (target / "indexes" / "plugins.json").write_text(json.dumps({"currentVariants": entries}), encoding="utf-8")
        if identity_epoch is None:
            identity_epoch = catalog_json_store.IDENTITY_EPOCH
        (target / "index.json").write_text(json.dumps({
            "schema": "omega.security-evidence.v2",
            "revisions": {"catalogIdentityEpoch": identity_epoch, "advisoryRevision": advisory_revision},
            "indexes": {"plugins": {"path": "indexes/plugins.json"}},
        }), encoding="utf-8")
        return target

    def test_seed_explicitly_queues_new_variants(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-queue-") as td:
            root = Path(td)
            catalog, _variant = self._catalog(root)
            definitions = self._definitions(root)
            evidence = self._evidence(root)
            seed = scan_queue.build_seed(
                catalog_root=catalog,
                definitions_root=definitions,
                evidence_root=evidence,
                output=root / "queue.json",
                now=NOW,
            )
            self.assertGreater(seed["counts"]["queued"], 0)
            self.assertTrue(all("new_variant" in item["reasons"] for item in seed["items"]))
            self.assertTrue(all(item["targetFingerprint"].startswith("artifact-target-v2-") for item in seed["items"]))
            self.assertTrue(all(item["workType"] == "artifact" for item in seed["items"]))
            self.assertEqual("scanner-v1-fixture", seed["scannerRevision"])
            self.assertEqual("b" * 64, seed["scannerBundleSha256"])
            self.assertEqual("artifact", seed["reasonContracts"]["new_variant"]["workType"])
            self.assertEqual("advisory", seed["reasonContracts"]["advisory_changed"]["workType"])
            self.assertEqual("source", seed["reasonContracts"]["source_observation_changed"]["workType"])


    def test_identity_epoch_mismatch_creates_clean_baseline_queue(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-queue-baseline-") as td:
            root = Path(td)
            catalog, variant = self._catalog(root)
            current = {
                "scan_id": 9, "status": "complete", "scanned_at_utc": "2026-08-19T09:00:00Z",
                "artifact_url": "https://wrong.invalid/old-id-collision.zip",
                "assembly_version": "99.0.0", "artifact_sha256": "a" * 64,
                "source_available": 1, "report_json": {"artifactAnalysisRevision": "artifact-analysis-v1-fixture", "scanProvenance": {"scannerRevision": "scanner-v1-fixture", "ruleSetRevision": "rules-v1-fixture"}},
            }
            evidence = self._evidence(root, current, variant_id=variant["variantId"], identity_epoch="legacy-sqlite-identities")
            seed = scan_queue.build_seed(
                catalog_root=catalog, definitions_root=self._definitions(root), evidence_root=evidence,
                output=root / "queue.json", now=NOW,
            )
            self.assertTrue(seed["baselineSecurityRebuild"])
            self.assertEqual("legacy-sqlite-identities", seed["previousEvidenceIdentityEpoch"])
            self.assertEqual(seed["counts"]["queued"], seed["counts"]["baseline_scan"])
            self.assertTrue(all(item["primaryReason"] == "baseline_scan" for item in seed["items"]))
            self.assertTrue(all("artifact_changed" not in item["reasons"] for item in seed["items"]))

    def test_definitions_or_legacy_rule_change_does_not_force_artifact_rescan_but_artifact_analysis_change_does(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-queue-rules-") as td:
            root = Path(td)
            catalog, variant = self._catalog(root)
            current = {
                "scan_id": 9,
                "status": "complete",
                "scanned_at_utc": "2026-08-19T09:00:00Z",
                "scanner_version": "2.8.0",
                "artifact_url": variant["artifactUrl"],
                "assembly_version": variant["assemblyVersion"],
                "artifact_sha256": "a" * 64,
                "source_available": 1,
                "source_repository": "https://github.com/example/source",
                "report_json": {"artifactAnalysisRevision": "artifact-analysis-v1-fixture", "scanProvenance": {"scannerRevision": "scanner-v1-fixture", "ruleSetRevision": "rules-v1-same"}},
            }
            evidence = self._evidence(root, current, variant_id=variant["variantId"])

            same_rules = scan_queue.build_seed(
                catalog_root=catalog,
                definitions_root=self._definitions(
                    root, defs="defs-v1-new-osv", rules="rules-v1-same", advisory="osv-v1-new",
                ),
                evidence_root=evidence,
                output=root / "same.json",
                now=NOW,
            )
            artifact_ids = {item["variantId"] for item in same_rules["items"] if item.get("workType") == "artifact"}
            self.assertNotIn(variant["variantId"], artifact_ids)
            advisory_item = next(item for item in same_rules["items"] if item.get("workType") == "advisory")
            self.assertEqual("advisory_changed", advisory_item["primaryReason"])
            self.assertEqual(0, advisory_item["variantId"])
            self.assertTrue(advisory_item["targetFingerprint"].startswith("advisory-target-v1-"))

            changed_rules_only = scan_queue.build_seed(
                catalog_root=catalog,
                definitions_root=self._definitions(
                    root, defs="defs-v1-new-rules", rules="rules-v1-changed", advisory="osv-v1-fixture",
                ),
                evidence_root=evidence,
                output=root / "changed-rules-only.json",
                now=NOW,
            )
            artifact_ids = {item["variantId"] for item in changed_rules_only["items"] if item.get("workType") == "artifact"}
            self.assertNotIn(variant["variantId"], artifact_ids, "legacy combined rule/bundle metadata is not an artifact-analysis invalidator")

            changed_analysis = scan_queue.build_seed(
                catalog_root=catalog,
                definitions_root=self._definitions(
                    root, defs="defs-v1-new-analysis", rules="rules-v1-changed",
                    artifact_analysis="artifact-analysis-v1-changed", advisory="osv-v1-fixture",
                ),
                evidence_root=evidence,
                output=root / "changed-analysis.json",
                now=NOW,
            )
            item = next(item for item in changed_analysis["items"] if item["variantId"] == variant["variantId"] and item.get("workType") == "artifact")
            self.assertIn("artifact_analysis_changed", item["reasons"])
            self.assertEqual("artifact_analysis_changed", item["primaryReason"])

    def test_scanner_bundle_change_alone_does_not_requeue_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-queue-scanner-change-") as td:
            root = Path(td)
            catalog, variant = self._catalog(root)
            current = {
                "scan_id": 9,
                "status": "complete",
                "scanned_at_utc": "2026-08-19T09:00:00Z",
                "artifact_url": variant["artifactUrl"],
                "assembly_version": variant["assemblyVersion"],
                "artifact_sha256": "a" * 64,
                "source_available": 0,
                "report_json": {"artifactAnalysisRevision": "artifact-analysis-v1-fixture", "scanProvenance": {"scannerRevision": "scanner-v1-old", "ruleSetRevision": "rules-v1-same"}},
            }
            evidence = self._evidence(root, current, variant_id=variant["variantId"])
            seed = scan_queue.build_seed(
                catalog_root=catalog,
                definitions_root=self._definitions(root, rules="rules-v1-same", scanner_revision="scanner-v1-new-worker"),
                evidence_root=evidence,
                output=root / "queue.json",
                now=NOW,
            )
            artifact_ids = {item["variantId"] for item in seed["items"] if item.get("workType") == "artifact"}
            self.assertNotIn(variant["variantId"], artifact_ids, "worker transport/scheduler changes must not invalidate artifact analysis")

    def test_source_review_never_requeues_artifact_work(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-queue-source-") as td:
            root = Path(td)
            catalog, variant = self._catalog(root)
            current = {
                "scan_id": 9,
                "status": "complete",
                "scanned_at_utc": "2026-08-19T09:00:00Z",
                "artifact_url": variant["artifactUrl"],
                "assembly_version": variant["assemblyVersion"],
                "artifact_sha256": "a" * 64,
                "source_available": 0,
                "source_repository": "https://github.com/example/source",
                "report_json": {"artifactAnalysisRevision": "artifact-analysis-v1-fixture", "scanProvenance": {"scannerRevision": "scanner-v1-fixture", "ruleSetRevision": "rules-v1-same"}},
            }
            evidence = self._evidence(root, current, variant_id=variant["variantId"])
            seed = scan_queue.build_seed(
                catalog_root=catalog,
                definitions_root=self._definitions(root, rules="rules-v1-same"),
                evidence_root=evidence,
                output=root / "queue.json",
                now=NOW,
            )
            artifact_ids = {item["variantId"] for item in seed["items"] if item.get("workType") == "artifact"}
            self.assertNotIn(variant["variantId"], artifact_ids)
            source_item = next(item for item in seed["items"] if item["variantId"] == variant["variantId"] and item.get("workType") == "source")
            self.assertIn("source_unresolved", source_item["reasons"])
            self.assertTrue(source_item["targetFingerprint"].startswith("source-target-v2-"))

    def test_default_branch_observation_change_enqueues_source_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-queue-source-head-") as td:
            root = Path(td)
            catalog, variant = self._catalog(root)
            repository = "https://github.com/example/source"
            variant["repositoryUrl"] = repository
            current = {
                "scan_id": 9, "status": "complete", "scanned_at_utc": "2026-08-19T09:00:00Z",
                "artifact_url": variant["artifactUrl"], "assembly_version": variant["assemblyVersion"],
                "artifact_sha256": "a" * 64, "source_available": 1, "source_repository": repository,
                "report_json": {
                    "workType": "source",
                    "artifactAnalysisRevision": "artifact-analysis-v1-fixture",
                    "sourceAnalysisRevision": "source-analysis-v1-fixture",
                    "source": {
                        "available": True, "repository": repository, "commit": "1" * 40,
                        "attribution": {"confidence": 40, "basis": ["default_branch"]},
                    },
                },
            }
            evidence = self._evidence(root, current, variant_id=variant["variantId"])
            definitions = self._definitions(root, source_observations=[{
                "repository": repository, "status": "observed", "defaultRef": "refs/heads/main", "commitSha": "2" * 40,
            }])
            # The fixture catalog itself has its original repo URL; pass the changed repository through
            # sourceRepositoryUrl by rewriting the canonical source file used by the queue fixture.
            plugin_index = json.loads((catalog / "plugins" / "index.json").read_text())
            payload_path = catalog / plugin_index["plugins"][0]["path"]
            payload = json.loads(payload_path.read_text())
            target = next(group["variant"] for group in payload["variants"] if int(group["variant"]["variant_id"]) == variant["variantId"])
            target["repo_url"] = repository
            payload_path.write_text(json.dumps(payload), encoding="utf-8")
            seed = scan_queue.build_seed(catalog_root=catalog, definitions_root=definitions, evidence_root=evidence, output=root / "queue.json", now=NOW)
            artifact_ids = {item["variantId"] for item in seed["items"] if item.get("workType") == "artifact"}
            self.assertNotIn(variant["variantId"], artifact_ids)
            source_item = next(item for item in seed["items"] if item.get("workType") == "source" and item["variantId"] == variant["variantId"])
            self.assertIn("source_observation_changed", source_item["reasons"])
            self.assertEqual("2" * 40, source_item["observedSourceCommit"])
            self.assertTrue(source_item["targetFingerprint"].startswith("source-target-v2-"))

    def test_completed_artifact_enqueues_independent_source_followup(self) -> None:
        state = {
            "schema": scan_queue.STATE_SCHEMA, "catalogRevision": "cat", "catalogIdentityEpoch": "epoch",
            "definitionsRevision": "defs", "scannerRevision": "scanner", "artifactAnalysisRevision": "artifact-analysis",
            "sourceAnalysisRevision": "source-analysis", "ruleSetRevision": "rules",
            "items": {}, "recentCompleted": [],
        }
        artifact = {
            "queueKey": "variant-7", "workType": "artifact", "variantId": 7, "pluginId": 3, "sourceId": 2,
            "internalName": "Fixture", "name": "Fixture", "sourceName": "Repo", "assemblyVersion": "1.0.0",
            "artifactChannel": "stable", "artifactUrl": "https://example.test/plugin.zip",
            "repositoryUrl": "https://github.com/example/plugin", "sourceRepositoryUrl": "", "priority": 900,
        }
        current = {"scan_id": 44, "status": "complete", "artifact_sha256": "a" * 64, "scanned_at_utc": "2026-08-19T10:00:00Z"}
        item = scan_queue.enqueue_source_followup(state, artifact, current, now=NOW)
        self.assertIsNotNone(item)
        self.assertEqual("source", item["workType"])
        self.assertEqual("source-variant-7", item["queueKey"])
        self.assertGreater(item["priority"], artifact["priority"])
        seed = {
            "schema": scan_queue.SEED_SCHEMA, "queueSeedRevision": "seed", "catalogRevision": "cat",
            "catalogIdentityEpoch": "epoch", "definitionsRevision": "defs", "scannerRevision": "scanner",
            "scannerBundleSha256": "", "artifactAnalysisRevision": "artifact-analysis", "sourceAnalysisRevision": "source-analysis",
            "ruleSetRevision": "rules", "items": [],
        }
        state["queueSeedRevision"] = "seed"
        synced = scan_queue.sync_state(seed, state, now=NOW + dt.timedelta(minutes=15))
        self.assertIn("source-variant-7", synced["items"], "dynamic source follow-up must survive the next worker sync for the same daily seed")
        selected = scan_queue.select_next(synced, now=NOW + dt.timedelta(minutes=15))
        self.assertEqual("source", selected["workType"])
        self.assertEqual("attempted", synced["items"]["source-variant-7"]["state"])

    def test_coverage_first_selection_prefers_never_scanned_before_source_followup_or_rescan(self) -> None:
        state = {
            "schema": scan_queue.STATE_SCHEMA, "selectionPolicy": scan_queue.SELECTION_POLICY,
            "items": {
                "source-variant-1": {
                    "queueKey": "source-variant-1", "workType": "source", "variantId": 1,
                    "internalName": "AlreadyCovered", "sourceName": "Repo", "priority": 1001,
                    "currentScanId": 10, "currentScannedAtUtc": "2026-08-19T10:00:00Z",
                    "attemptCount": 0, "state": "pending", "targetFingerprint": "source-1",
                },
                "variant-2": {
                    "queueKey": "variant-2", "workType": "artifact", "variantId": 2,
                    "internalName": "NeverScanned", "sourceName": "Repo", "priority": 900,
                    "currentScanId": 0, "currentScannedAtUtc": "",
                    "attemptCount": 0, "state": "pending", "targetFingerprint": "artifact-2",
                },
                "variant-3": {
                    "queueKey": "variant-3", "workType": "artifact", "variantId": 3,
                    "internalName": "UncoveredRetry", "sourceName": "Repo", "priority": 950,
                    "currentScanId": 0, "currentScannedAtUtc": "",
                    "attemptCount": 2, "state": "pending", "targetFingerprint": "artifact-3",
                },
            },
        }
        first = scan_queue.select_next(state, now=NOW)
        self.assertEqual(2, first["variantId"], "untouched uncovered artifact must beat a higher-priority revisit")
        scan_queue.finish_attempt(state, first, status="complete", artifact_sha256="a" * 64, scan_id=20, now=NOW)
        second = scan_queue.select_next(state, now=NOW + dt.timedelta(seconds=1))
        self.assertEqual(3, second["variantId"], "retry of an uncovered artifact must still beat already-covered work")
        summary = scan_queue.state_summary(state)
        self.assertEqual(scan_queue.SELECTION_POLICY, summary["selectionPolicy"])
        self.assertEqual(1, summary["unscannedVariantsPending"])
        self.assertEqual(1, summary["unscannedRetryVariants"])
        self.assertEqual(1, summary["coveredWorkPending"])

    def test_failed_attempts_back_off_instead_of_releasing_every_fifteen_minutes(self) -> None:
        seed = {
            "schema": scan_queue.SEED_SCHEMA,
            "queueSeedRevision": "queue-seed-v1-fixture",
            "catalogRevision": "cat",
            "definitionsRevision": "defs",
            "ruleSetRevision": "rules",
            "items": [{
                "queueKey": "variant-1",
                "targetFingerprint": "target",
                "variantId": 1,
                "internalName": "Fixture",
                "sourceName": "Repo",
                "primaryReason": "new_variant",
                "reasons": ["new_variant"],
                "priority": 900,
                "currentScannedAtUtc": "",
            }],
        }
        state = scan_queue.sync_state(seed, {}, now=NOW)
        selected = scan_queue.select_next(state, now=NOW)
        self.assertIsNotNone(selected)
        self.assertEqual("attempted", state["items"]["variant-1"]["state"])
        scan_queue.finish_attempt(state, selected, status="failed", error="network timeout", now=NOW)
        item = state["items"]["variant-1"]
        self.assertEqual("retry", item["state"])
        self.assertEqual("2026-08-19T11:00:00Z", item["nextEligibleAtUtc"])
        self.assertIsNone(scan_queue.select_next(state, now=NOW + dt.timedelta(minutes=15)))
        retried = scan_queue.select_next(state, now=NOW + dt.timedelta(hours=1))
        self.assertIsNotNone(retried)
        self.assertEqual(2, retried["attemptCount"])

    def test_completed_target_is_not_released_again_within_same_daily_seed(self) -> None:
        seed = {
            "schema": scan_queue.SEED_SCHEMA,
            "queueSeedRevision": "queue-seed-v1-fixture",
            "catalogRevision": "cat",
            "definitionsRevision": "defs",
            "ruleSetRevision": "rules",
            "items": [{
                "queueKey": "variant-1", "targetFingerprint": "target", "variantId": 1,
                "internalName": "Fixture", "sourceName": "Repo", "primaryReason": "source_review_due",
                "reasons": ["source_review_due"], "priority": 800, "currentScannedAtUtc": "",
            }],
        }
        state = scan_queue.sync_state(seed, {}, now=NOW)
        selected = scan_queue.select_next(state, now=NOW)
        scan_queue.finish_attempt(state, selected, status="complete", artifact_sha256="b" * 64, scan_id=42, now=NOW)
        self.assertEqual("complete", state["items"]["variant-1"]["state"])
        self.assertIsNone(scan_queue.select_next(state, now=NOW + dt.timedelta(minutes=15)))
        synced = scan_queue.sync_state(seed, state, now=NOW + dt.timedelta(hours=2))
        self.assertEqual("complete", synced["items"]["variant-1"]["state"])

    def test_unchanged_old_scan_is_not_requeued_by_age(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-queue-no-ttl-") as td:
            root = Path(td)
            catalog, variant = self._catalog(root)
            current = {
                "scan_id": 9,
                "status": "complete",
                "scanned_at_utc": "2020-01-01T00:00:00Z",
                "artifact_url": variant["artifactUrl"],
                "assembly_version": variant["assemblyVersion"],
                "artifact_sha256": "a" * 64,
                "source_available": 1,
                "source_repository": "https://github.com/example/source",
                "report_json": {
                    "workType": "source",
                    "artifactAnalysisRevision": "artifact-analysis-v1-fixture",
                    "sourceAnalysisRevision": "source-analysis-v1-fixture",
                    "source": {"available": True, "attribution": {"confidence": 70}},
                    "scanProvenance": {"scannerRevision": "scanner-v1-fixture", "ruleSetRevision": "rules-v1-fixture"},
                },
            }
            evidence = self._evidence(root, current, variant_id=variant["variantId"])
            seed = scan_queue.build_seed(
                catalog_root=catalog,
                definitions_root=self._definitions(root),
                evidence_root=evidence,
                output=root / "queue.json",
                now=NOW,
            )
            queued_ids = {
                item["variantId"]
                for item in seed["items"]
                if item.get("workType") in {"artifact", "source"} and int(item.get("variantId") or 0) > 0
            }
            self.assertNotIn(variant["variantId"], queued_ids)
            self.assertNotIn("periodic_revalidation", scan_queue.REASON_PRIORITIES)

    def test_changed_target_resets_completed_state_without_time_ttl(self) -> None:
        old_seed = {
            "schema": scan_queue.SEED_SCHEMA, "queueSeedRevision": "seed-old",
            "catalogRevision": "cat", "definitionsRevision": "defs", "ruleSetRevision": "rules",
            "advisoryRevision": "osv", "items": [{
                "queueKey": "variant-1", "targetFingerprint": "artifact-target-v2-old", "variantId": 1,
                "workType": "artifact", "internalName": "Fixture", "sourceName": "Repo",
                "primaryReason": "artifact_changed", "reasons": ["artifact_changed"], "priority": 850,
                "currentScannedAtUtc": "",
            }],
        }
        state = scan_queue.sync_state(old_seed, {}, now=NOW)
        selected = scan_queue.select_next(state, now=NOW)
        scan_queue.finish_attempt(state, selected, status="complete", scan_id=11, now=NOW)
        new_seed = {
            **old_seed,
            "queueSeedRevision": "seed-new",
            "items": [{**old_seed["items"][0], "targetFingerprint": "artifact-target-v2-new"}],
        }
        next_state = scan_queue.sync_state(new_seed, state, now=NOW + dt.timedelta(days=30))
        self.assertEqual("pending", next_state["items"]["variant-1"]["state"])
        self.assertEqual(0, next_state["items"]["variant-1"]["attemptCount"])

    def test_inactive_catalog_variant_is_not_a_queue_candidate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-queue-retired-") as td:
            root = Path(td)
            catalog, variant = self._catalog(root)
            plugin_index = json.loads((catalog / "plugins" / "index.json").read_text(encoding="utf-8"))
            payload_path = catalog / plugin_index["plugins"][0]["path"]
            payload = json.loads(payload_path.read_text(encoding="utf-8"))
            target = next(group["variant"] for group in payload["variants"] if int(group["variant"]["variant_id"]) == variant["variantId"])
            target["active"] = 0
            payload_path.write_text(json.dumps(payload), encoding="utf-8")
            current = {
                "scan_id": 9, "status": "complete", "scanned_at_utc": "2026-08-19T09:00:00Z",
                "artifact_url": variant["artifactUrl"], "assembly_version": variant["assemblyVersion"],
                "artifact_sha256": "a" * 64, "report_json": {"artifactAnalysisRevision": "artifact-analysis-v1-fixture"},
            }
            seed = scan_queue.build_seed(
                catalog_root=catalog, definitions_root=self._definitions(root),
                evidence_root=self._evidence(root, current, variant_id=variant["variantId"]),
                output=root / "queue.json", now=NOW,
            )
            self.assertFalse(any(int(item.get("variantId") or 0) == variant["variantId"] for item in seed["items"]))

    def test_artifact_identity_changes_have_precise_reasons(self) -> None:
        variant = {"artifactUrl": "https://example.test/new.zip", "assemblyVersion": "2.0.0"}
        current = {
            "status": "complete", "artifact_url": "https://example.test/old.zip", "assembly_version": "1.0.0",
            "report_json": {"artifactAnalysisRevision": "analysis-same"},
        }
        reasons = scan_queue.due_reasons(variant, current, artifact_analysis_revision="analysis-same")
        self.assertEqual(["artifact_url_changed", "artifact_version_changed"], reasons)
        self.assertNotIn("artifact_changed", scan_queue.REASON_PRIORITIES)
        self.assertEqual("artifact", scan_queue.REASON_CONTRACTS["artifact_url_changed"]["workType"])
        self.assertEqual(["artifact", "source-followup"], scan_queue.REASON_CONTRACTS["artifact_version_changed"]["invalidates"])

    def test_queue_state_contains_no_lease_fields(self) -> None:
        seed = {
            "schema": scan_queue.SEED_SCHEMA, "queueSeedRevision": "seed",
            "catalogRevision": "cat", "definitionsRevision": "defs", "ruleSetRevision": "rules",
            "advisoryRevision": "osv", "items": [{
                "queueKey": "variant-1", "targetFingerprint": "target", "variantId": 1,
                "workType": "artifact", "internalName": "Fixture", "sourceName": "Repo",
                "primaryReason": "new_variant", "reasons": ["new_variant"], "priority": 900,
                "currentScannedAtUtc": "",
            }],
        }
        state = scan_queue.sync_state(seed, {}, now=NOW)
        selected = scan_queue.select_next(state, now=NOW)
        self.assertIsNotNone(selected)
        serialized = json.dumps(state)
        self.assertNotIn("leaseId", serialized)
        self.assertNotIn("leaseExpiresAtUtc", serialized)
        self.assertNotIn('"leased"', serialized)




if __name__ == "__main__":
    unittest.main()

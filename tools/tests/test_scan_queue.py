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

    def _definitions(self, root: Path, *, defs: str = "defs-v1-fixture", rules: str = "rules-v1-fixture") -> Path:
        target = root / f"definitions-{defs[-7:]}-{rules[-7:]}"
        target.mkdir(parents=True, exist_ok=True)
        (target / "index.json").write_text(json.dumps({
            "schema": "omega.definitions.v1",
            "definitionsRevision": defs,
            "ruleSetRevision": rules,
        }), encoding="utf-8")
        return target

    def _evidence(self, root: Path, current: dict | None = None, *, variant_id: int = 0) -> Path:
        target = root / "evidence"
        (target / "indexes").mkdir(parents=True, exist_ok=True)
        entries = []
        if current is not None:
            variant_path = f"plugins/{variant_id}.json"
            (target / "plugins").mkdir(exist_ok=True)
            (target / variant_path).write_text(json.dumps({"variantId": variant_id, "current": current}), encoding="utf-8")
            entries.append({"variantId": variant_id, "variantPath": variant_path})
        (target / "indexes" / "plugins.json").write_text(json.dumps({"currentVariants": entries}), encoding="utf-8")
        (target / "index.json").write_text(json.dumps({
            "schema": "omega.security-evidence.v2",
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
            self.assertTrue(all(item["targetFingerprint"].startswith("scan-target-v1-") for item in seed["items"]))

    def test_osv_only_definitions_change_does_not_force_artifact_rescan_but_rule_change_does(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-queue-rules-") as td:
            root = Path(td)
            catalog, variant = self._catalog(root)
            current = {
                "scan_id": 9,
                "status": "complete",
                "scanned_at_utc": "2026-08-19T09:00:00Z",
                "scanner_version": "2.6.0",
                "artifact_url": variant["artifactUrl"],
                "assembly_version": variant["assemblyVersion"],
                "artifact_sha256": "a" * 64,
                "source_available": 1,
                "source_repository": "https://github.com/example/source",
                "report_json": {"scanProvenance": {"ruleSetRevision": "rules-v1-same"}},
            }
            evidence = self._evidence(root, current, variant_id=variant["variantId"])

            same_rules = scan_queue.build_seed(
                catalog_root=catalog,
                definitions_root=self._definitions(root, defs="defs-v1-new-osv", rules="rules-v1-same"),
                evidence_root=evidence,
                output=root / "same.json",
                now=NOW,
            )
            queued_ids = {item["variantId"] for item in same_rules["items"]}
            self.assertNotIn(variant["variantId"], queued_ids)

            changed_rules = scan_queue.build_seed(
                catalog_root=catalog,
                definitions_root=self._definitions(root, defs="defs-v1-new-rules", rules="rules-v1-changed"),
                evidence_root=evidence,
                output=root / "changed.json",
                now=NOW,
            )
            item = next(item for item in changed_rules["items"] if item["variantId"] == variant["variantId"])
            self.assertIn("rule_set_changed", item["reasons"])
            self.assertEqual("rule_set_changed", item["primaryReason"])

    def test_source_review_is_an_explicit_queue_reason(self) -> None:
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
                "report_json": {"scanProvenance": {"ruleSetRevision": "rules-v1-same"}},
            }
            evidence = self._evidence(root, current, variant_id=variant["variantId"])
            seed = scan_queue.build_seed(
                catalog_root=catalog,
                definitions_root=self._definitions(root, rules="rules-v1-same"),
                evidence_root=evidence,
                output=root / "queue.json",
                now=NOW,
            )
            item = next(item for item in seed["items"] if item["variantId"] == variant["variantId"])
            self.assertIn("source_review_due", item["reasons"])
            self.assertEqual("source_review_due", item["primaryReason"])

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
        leased = scan_queue.lease_next(state, now=NOW)
        self.assertIsNotNone(leased)
        scan_queue.finish_lease(state, leased, status="failed", error="network timeout", now=NOW)
        item = state["items"]["variant-1"]
        self.assertEqual("retry_wait", item["state"])
        self.assertEqual("2026-08-19T11:00:00Z", item["nextEligibleAtUtc"])
        self.assertIsNone(scan_queue.lease_next(state, now=NOW + dt.timedelta(minutes=15)))
        retried = scan_queue.lease_next(state, now=NOW + dt.timedelta(hours=1))
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
        leased = scan_queue.lease_next(state, now=NOW)
        scan_queue.finish_lease(state, leased, status="complete", artifact_sha256="b" * 64, scan_id=42, now=NOW)
        self.assertEqual("complete", state["items"]["variant-1"]["state"])
        self.assertIsNone(scan_queue.lease_next(state, now=NOW + dt.timedelta(minutes=15)))
        synced = scan_queue.sync_state(seed, state, now=NOW + dt.timedelta(hours=2))
        self.assertEqual("complete", synced["items"]["variant-1"]["state"])

    def test_new_daily_due_entry_resets_completion_after_current_scan_advances(self) -> None:
        old_seed = {
            "schema": scan_queue.SEED_SCHEMA, "queueSeedRevision": "seed-old",
            "catalogRevision": "cat", "definitionsRevision": "defs", "ruleSetRevision": "rules",
            "items": [{
                "queueKey": "variant-1", "targetFingerprint": "target-scan-10", "variantId": 1,
                "internalName": "Fixture", "sourceName": "Repo", "primaryReason": "periodic_revalidation",
                "reasons": ["periodic_revalidation"], "priority": 100, "currentScannedAtUtc": "2026-08-01T00:00:00Z",
            }],
        }
        state = scan_queue.sync_state(old_seed, {}, now=NOW)
        leased = scan_queue.lease_next(state, now=NOW)
        scan_queue.finish_lease(state, leased, status="complete", scan_id=11, now=NOW)
        new_seed = {**old_seed, "queueSeedRevision": "seed-new", "items": [{**old_seed["items"][0], "targetFingerprint": "target-scan-11"}]}
        next_state = scan_queue.sync_state(new_seed, state, now=NOW + dt.timedelta(days=8))
        self.assertEqual("pending", next_state["items"]["variant-1"]["state"])
        self.assertEqual(0, next_state["items"]["variant-1"]["attemptCount"])



if __name__ == "__main__":
    unittest.main()

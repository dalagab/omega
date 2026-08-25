from __future__ import annotations
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import common
import test_sqlite_catalog
import sigmascope
import sigmascope_request_adapter as adapter


class SigmaScopeRequestAdapterTests(unittest.TestCase):
    def make_database(self, root: Path, *, with_current: bool = True) -> tuple[Path, int, int, str]:
        curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(root)
        built = root / "built"
        test_sqlite_catalog.run_builder(common.ROOT, built, curated, raw, enriched, websites)
        database = built / "omega-catalog.sqlite"
        artifact = "a" * 64
        with closing(sqlite3.connect(database)) as db:
            db.row_factory = sqlite3.Row
            sigmascope.ensure_schema(db)
            variant = db.execute(
                """SELECT v.variant_id,v.plugin_id,v.source_id,v.assembly_version
                     FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id
                    WHERE v.active=1 AND p.active=1 ORDER BY v.variant_id LIMIT 1"""
            ).fetchone()
            self.assertIsNotNone(variant)
            variant_id = int(variant["variant_id"])
            plugin_id = int(variant["plugin_id"])
            source_id = int(variant["source_id"])
            if with_current:
                db.execute(
                    """INSERT INTO plugin_security_scans(
                         scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,
                         artifact_sha256,scanner_version,status,scanned_at_utc,highest_severity,
                         informational_count,caution_count,high_count,critical_count,capabilities_json,
                         source_available,source_repository,source_commit,source_to_binary_verified,report_json,error)
                         VALUES(?,?,?,?,?,'stable','https://example.invalid/plugin.zip',?,?,'complete',
                         '2026-08-24T20:00:00Z','none',0,0,0,0,'[]',1,'https://example.invalid/repo',
                         'abc',0,'{}','')""",
                    (9001, plugin_id, variant_id, source_id, str(variant["assembly_version"] or "1.0.0"), artifact, sigmascope.SCANNER_VERSION),
                )
                db.execute(
                    """INSERT INTO plugin_security_current(
                         variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,
                         scanner_version,status,scanned_at_utc,highest_severity,informational_count,caution_count,
                         high_count,critical_count,capabilities_json,automation_level,automation_capabilities_json,
                         findings_json,source_available,source_repository,source_commit,source_to_binary_verified,
                         report_json,error)
                         VALUES(?,9001,?,'stable','https://example.invalid/plugin.zip',?,?,'complete',
                         '2026-08-24T20:00:00Z','none',0,0,0,0,'[]','none','[]','[]',1,
                         'https://example.invalid/repo','abc',0,'{}','')""",
                    (variant_id, str(variant["assembly_version"] or "1.0.0"), artifact, sigmascope.SCANNER_VERSION),
                )
            db.commit()
        return database, variant_id, plugin_id, artifact

    def state(self) -> dict:
        return {
            "catalogRevision": "catalog-v1-fixture",
            "catalogIdentityEpoch": "catalog-identity-v1-fixture",
            "definitionsRevision": "defs-v1-fixture",
            "scannerRevision": "scanner-v1-fixture",
            "artifactAnalysisRevision": "artifact-analysis-v1-fixture",
            "sourceAnalysisRevision": "source-analysis-v1-fixture",
            "ruleSetRevision": "rules-v1-fixture",
            "srlRuleSetRevision": "srl-v1-fixture",
            "items": {},
        }

    def request(self, observation: str, variant_id: int, **subject_extra) -> dict:
        subject = {"type": "variant", "variantId": variant_id, **subject_extra}
        return {
            "requestId": f"req-{observation}",
            "observation": observation,
            "subject": subject,
            "reason": f"Need {observation}",
            "priority": 730,
            "requestedBy": {"componentId": "omega.stigma-1", "ruleId": "fixture.rule"},
            "requestedAtUtc": "2026-08-24T20:00:00Z",
        }

    def test_artifact_observation_merges_into_canonical_variant_queue_item(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-sigma-request-") as td:
            root = Path(td)
            database, variant_id, _plugin_id, _artifact = self.make_database(root)
            state = self.state()
            with closing(sqlite3.connect(database)) as db:
                db.row_factory = sqlite3.Row
                target = adapter.enqueue_request(state, db, self.request("managedCallSites", variant_id), work_item_id="work-1")
            self.assertEqual("artifact", target["workType"])
            self.assertEqual(f"variant-{variant_id}", target["queueKey"])
            item = state["items"][target["queueKey"]]
            self.assertEqual("pending", item["state"])
            self.assertIn("managedCallSites", item["requiredObservationCollections"])
            self.assertEqual("work-1", item["analysisRequests"][0]["workItemId"])
            self.assertIn("analysis_observation_requested", item["reasons"])

    def test_existing_seeded_item_is_reused_not_duplicated(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-sigma-request-merge-") as td:
            root = Path(td)
            database, variant_id, _plugin_id, _artifact = self.make_database(root)
            state = self.state()
            with closing(sqlite3.connect(database)) as db:
                db.row_factory = sqlite3.Row
                first = adapter.enqueue_request(state, db, self.request("managedCallSites", variant_id), work_item_id="work-1")
                item = state["items"][first["queueKey"]]
                fingerprint = item["targetFingerprint"]
                item["state"] = "complete"
                item["attemptCount"] = 2
                second_request = self.request("nativeImports", variant_id)
                second_request["requestId"] = "req-native"
                second = adapter.enqueue_request(state, db, second_request, work_item_id="work-2")
            self.assertEqual(first["queueKey"], second["queueKey"])
            item = state["items"][first["queueKey"]]
            self.assertEqual(fingerprint, item["targetFingerprint"])
            self.assertEqual(2, item["attemptCount"])
            self.assertEqual("pending", item["state"])
            self.assertEqual({"managedCallSites", "nativeImports"}, set(item["requiredObservationCollections"]))
            self.assertEqual(2, len(item["analysisRequests"]))

    def test_source_observation_uses_source_queue_when_artifact_prerequisite_exists(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-sigma-source-request-") as td:
            root = Path(td)
            database, variant_id, _plugin_id, _artifact = self.make_database(root)
            state = self.state()
            with closing(sqlite3.connect(database)) as db:
                db.row_factory = sqlite3.Row
                target = adapter.enqueue_request(state, db, self.request("sourceAttribution", variant_id), work_item_id="work-source")
            self.assertEqual("source", target["workType"])
            self.assertEqual(f"source-variant-{variant_id}", target["queueKey"])
            self.assertIn("sourceAttribution", state["items"][target["queueKey"]]["requiredObservationCollections"])

    def test_source_observation_requires_completed_artifact_prerequisite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-sigma-source-prereq-") as td:
            root = Path(td)
            database, variant_id, _plugin_id, _artifact = self.make_database(root, with_current=False)
            with closing(sqlite3.connect(database)) as db:
                db.row_factory = sqlite3.Row
                with self.assertRaisesRegex(ValueError, "artifact scan prerequisite"):
                    adapter.enqueue_request(self.state(), db, self.request("sourceAttribution", variant_id), work_item_id="work-source")

    def test_exact_artifact_subject_must_match_retained_variant_hash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-sigma-artifact-request-") as td:
            root = Path(td)
            database, variant_id, _plugin_id, artifact = self.make_database(root)
            request = self.request("managedCallSites", variant_id, artifactSha256=artifact)
            with closing(sqlite3.connect(database)) as db:
                db.row_factory = sqlite3.Row
                target = adapter.enqueue_request(self.state(), db, request, work_item_id="work-hash")
            self.assertEqual(artifact, target["artifactSha256"])
            bad = self.request("managedCallSites", variant_id, artifactSha256="b" * 64)
            with closing(sqlite3.connect(database)) as db:
                db.row_factory = sqlite3.Row
                with self.assertRaisesRegex(ValueError, "does not match"):
                    adapter.enqueue_request(self.state(), db, bad, work_item_id="work-bad")

    def test_planned_authenticode_provider_is_not_dispatchable_through_adapter_yet(self) -> None:
        with self.assertRaisesRegex(ValueError, "no active SigmaScope provider"):
            adapter.compile_sigmascope_request({
                "observation": "binarySignatureTrust",
                "subject": {"type": "variant", "variantId": 1},
                "reason": "Need signature trust",
            })

    def test_verification_requires_requested_collection_in_candidate_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-sigma-verify-") as td:
            root = Path(td)
            variant_id = 42
            path = root / "variants" / "0000" / "42.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({
                "variantId": variant_id,
                "observations": {
                    "schema": "omega.sigmascope.observation-contract.v1",
                    "contractRevision": "observations-v1-fixture",
                    "collections": {
                        "managedCallSites": {"records": 0, "recordDigest": "abc", "completeness": "retained"},
                    },
                },
            }), encoding="utf-8")
            target = {"schema": adapter.TARGET_SCHEMA, "requestId": "req", "workItemId": "work", "variantId": 42, "observation": "managedCallSites"}
            verified = adapter.verify_target(root, target)
            self.assertTrue(verified["ok"])
            self.assertEqual(0, verified["records"])
            target["observation"] = "nativeImports"
            with self.assertRaisesRegex(ValueError, "absent"):
                adapter.verify_target(root, target)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import common
import catalog_release_intake as intake
import catalog_json_store
import catalog_state
import definitions_snapshot
import publish_catalog_state
import reconcile_work
import scan_queue
import test_sqlite_catalog
import work_queue
import work_result

NOW = "2026-09-01T10:00:00Z"


class CatalogReleaseIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        curated, raw, enriched, websites = test_sqlite_catalog.fixture_documents(self.root)
        self.enriched = enriched
        self.raw = raw
        self.repo = self.root / "repo"
        (self.repo / "sources").mkdir(parents=True)
        shutil.copy2(curated, self.repo / "sources/curated-sources.json")
        intake.write(self.repo / "sources/community-sources.json", [])
        test_sqlite_catalog.run_builder(common.ROOT, self.root / "built", curated, raw, enriched, websites)
        catalog_json_store.export_snapshot(self.root / "built/omega-catalog.sqlite", self.root / "catalog")
        self.evidence = self.root / "evidence"
        intake.write(self.evidence / "indexes/nuget.json", {"schema": "omega.security-evidence.nuget-index.v2", "packages": []})
        intake.write(self.evidence / "indexes/plugins.json", {"currentVariants": []})
        intake.write(self.evidence / "index.json", {
            "schema": "omega.security-evidence.v2",
            "revisions": {"evidenceRevision": "ev-fixture", "catalogIdentityEpoch": catalog_json_store.IDENTITY_EPOCH},
            "indexes": {"nuget": {"path": "indexes/nuget.json"}, "plugins": {"path": "indexes/plugins.json"}},
        })
        advisories = self.root / "advisories.json"
        intake.write(advisories, {"schema": "omega.public-advisories.v1", "source": "OSV", "ecosystem": "NuGet",
                                  "queriedPackages": 0, "matchedPackages": 0, "advisories": []})
        empty = self.root / "empty-secondary"
        empty.mkdir()
        definitions_snapshot.build_snapshot(repo_root=common.ROOT, evidence_root=self.evidence,
            output=self.root / "definitions", advisories_input=advisories, secondary_security_input=empty)
        queue = self.root / "queue.json"
        scan_queue.build_seed(catalog_root=self.root / "catalog", definitions_root=self.root / "definitions",
                              evidence_root=self.evidence, output=queue)
        self.state = self.root / "state"
        catalog_state.assemble(catalog=self.root / "catalog", definitions=self.root / "definitions",
                               output=self.state, queue_seed=queue)
        self.lane = self.root / "lane"
        self.lane.mkdir()
        self.work = self.root / "work"

    def settle(self, *, version="2.0.0.0", settled=True, stale=False):
        document = intake.read(self.enriched)
        document["sources"][0]["plugins"][0]["assemblyVersion"] = version
        intake.write(self.lane / "enriched-sources.json", document)
        shutil.copy2(self.raw, self.lane / "raw-sources.json")
        revision = intake.read(self.state / "catalog/index.json")["catalogRevision"]
        intake.write(self.lane / "provenance.json", {"baseCatalogRevision": "stale" if stale else revision})
        queue = work_queue.new_queue("catalog-enrichment", "omega.catalog", now=NOW)
        queue, _, _ = work_queue.enqueue(queue, kind="refresh", subject={"type": "catalog"}, reason=["release"],
                                         priority=500, required_revision="req-fixture", now=NOW)
        queue, claim = work_queue.claim(queue, owner="omega.worker.catalog-enrichment", now=NOW)
        result = work_result.build_result(queue_id="catalog-enrichment", item=claim, root=self.lane,
            files=["raw-sources.json", "enriched-sources.json", "provenance.json"])
        intake.write(self.lane / "result.json", result)
        if settled:
            queue, _ = work_queue.settle(queue, work_id=claim["workId"], claim_token=claim["lease"]["claimToken"],
                outcome="complete", result_revision=result["resultRevision"],
                result_sha256=work_result.sha256_file(self.lane / "result.json"), now=NOW)
        intake.write(self.work / "queues/catalog-enrichment.json", queue)
        semantic = {"schema": reconcile_work.INDEX_SCHEMA, "policyVersion": 5, "queues": [
            {"queueId": "catalog-enrichment", "queueRevision": queue["queueRevision"], "path": "queues/catalog-enrichment.json"}]}
        intake.write(self.work / "index.json", {**semantic,
            "workStateRevision": "work-state-v1-" + reconcile_work._sha(semantic)[:20],
            "securityAuthority": False, "clientDatabaseBuildRequested": False})

    def build(self):
        return intake.build(state=self.state, work_state=self.work, enrichment=self.lane,
                            evidence=self.evidence, repo=self.repo, output=self.root / "candidate")

    def test_release_is_admitted_with_exact_definitions_and_known_plugin_identity(self):
        self.settle()
        result = self.build()
        self.assertTrue(result["changed"])
        self.assertEqual(1, result["releaseUpdates"])
        candidate = self.root / "candidate"
        self.assertTrue(catalog_state.validate(candidate)["ok"])
        self.assertEqual((self.state / "definitions/index.json").read_bytes(), (candidate / "definitions/index.json").read_bytes())
        self.assertEqual((self.state / "definitions/worker/manifest.json").read_bytes(), (candidate / "definitions/worker/manifest.json").read_bytes())
        old_plugins = {item["pluginId"] for item in scan_queue.catalog_variants(self.state / "catalog")}
        seed = intake.read(candidate / "scan-queue.json")
        updates = [item for item in seed["items"] if item.get("releaseUpdate")]
        self.assertEqual(1, len(updates))
        self.assertEqual("2.0.0.0", updates[0]["assemblyVersion"])
        self.assertIn(updates[0]["pluginId"], old_plugins)
        self.assertFalse(seed["baselineSecurityRebuild"])

    def test_unchanged_release_is_a_noop(self):
        self.settle(version="1.0.0.0")
        self.assertFalse(self.build()["changed"])
        self.assertFalse((self.root / "candidate").exists())

    def test_unsettled_and_stale_results_never_create_a_candidate(self):
        self.settle(settled=False)
        self.assertFalse(self.build()["ready"])
        self.settle(stale=True)
        self.assertEqual("enrichment-base-is-stale", self.build()["reason"])
        self.assertFalse((self.root / "candidate").exists())

    def test_changed_payload_is_rejected_before_catalog_mutation(self):
        self.settle()
        with (self.lane / "enriched-sources.json").open("a", encoding="utf-8") as handle:
            handle.write(" ")
        with self.assertRaisesRegex(ValueError, "does not reproduce"):
            self.build()
        self.assertFalse((self.root / "candidate").exists())

    def test_catalog_publication_binds_the_candidate_base_head(self):
        with mock.patch.object(publish_catalog_state, "publish_snapshot_tree") as publish:
            publish.return_value.as_dict.return_value = {"pushed": False}
            publish_catalog_state.publish(self.state, self.repo, "catalog-data", "origin", False,
                                          expected_parent_sha="a" * 40)
            self.assertEqual("a" * 40, publish.call_args.kwargs["expected_previous_head"])

    def test_new_release_of_retired_scanned_variant_retains_plugin_coverage(self):
        self.settle()
        variant = scan_queue.catalog_variants(self.state / "catalog")[0]
        intake.write(self.evidence / "plugins/old.json", {"variantId": variant["variantId"], "pluginId": variant["pluginId"],
            "current": {"status": "complete", "scan_id": 10, "scanned_at_utc": NOW, "artifact_sha256": "a" * 64}})
        intake.write(self.evidence / "indexes/plugins.json", {"currentVariants": [
            {"variantId": variant["variantId"], "variantPath": "plugins/old.json"}]})
        self.build()
        seed = intake.read(self.root / "candidate/scan-queue.json")
        update = next(item for item in seed["items"] if item.get("releaseUpdate"))
        self.assertTrue(update["pluginHasCurrentScan"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest
from pathlib import Path

import common


class OrchestrationContractTests(unittest.TestCase):
    def read_workflow(self, name: str) -> str:
        return (common.ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")

    def test_reconciler_is_orchestration_only_and_cannot_publish_client_database(self) -> None:
        text = self.read_workflow("security-reconcile.yml")
        self.assertIn("reconcile_work.py", text)
        self.assertIn("security-work-state", text)
        self.assertIn("publish_work_state.py", text)
        self.assertIn("No semantic orchestration-state change; skipping branch publication.", text)
        self.assertIn("if: steps.change.outputs.changed == 'true'", text)
        self.assertIn("clientDatabaseBuildRequested", text)
        for forbidden in (
            "compile_marketplace_snapshot.py",
            "omega-marketplace.sqlite.zip",
            "gh release upload catalog-latest",
            "publish_catalog_state.py",
            "definitions_snapshot.py build",
        ):
            self.assertNotIn(forbidden, text)

    def test_catalog_freeze_is_explicit_release_boundary(self) -> None:
        text = self.read_workflow("catalog-freeze.yml")
        self.assertIn("name: Omega catalog · freeze and publish", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("uses: ./.github/workflows/catalog-builder.yml", text)
        self.assertNotIn("schedule:", text)
        reconciler = self.read_workflow("security-reconcile.yml")
        self.assertNotIn("catalog-freeze.yml", reconciler)
        self.assertNotIn("catalog-builder.yml", reconciler)

    def test_worker_images_are_toolchain_only(self) -> None:
        expected = {
            "catalog-worker": ("git", "curl"),
            "sigmascope-worker": ("yara", "clamav"),
            "intelligence-worker": ("dnsutils", "openssl"),
            "publisher-worker": ("gh", "git"),
        }
        for name, tools in expected.items():
            text = (common.ROOT / "containers" / name / "Dockerfile").read_text(encoding="utf-8")
            self.assertIn("python:3.13.15-slim-bookworm", text)
            self.assertIn("PyYAML==6.0.3", text)
            for tool in tools:
                self.assertIn(tool, text)
            self.assertNotIn("COPY security-definitions", text)
            self.assertNotIn("COPY catalog", text)
            self.assertNotIn("COPY definitions", text)
            self.assertNotIn("COPY tools", text, "first worker images are reusable toolchains, not mutable code/data snapshots")

    def test_image_workflow_publishes_ghcr_digest_artifacts(self) -> None:
        text = self.read_workflow("worker-images.yml")
        self.assertIn("packages: write", text)
        self.assertIn("ghcr.io/${{ github.repository_owner }}/omega-${{ matrix.image }}", text)
        self.assertIn("sed -nE 's/^.*digest: (sha256:[0-9a-f]{64})", text)
        self.assertIn('[[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]', text)
        self.assertIn('digest_ref="$IMAGE@$digest"', text)
        self.assertIn('[[ ! "$digest_ref" =~ @sha256:[0-9a-f]{64}$ ]]', text)
        self.assertIn("image_ref_re=re.compile(r'^ghcr\\.io/[^@\\s]+@sha256:[0-9a-f]{64}$')", text)
        self.assertIn("worker-image-digest-${{ matrix.image }}", text)
        for name in ("catalog-worker", "sigmascope-worker", "intelligence-worker", "publisher-worker"):
            self.assertIn(name, text)

    def test_ascii_doc_records_remaining_platform_work_and_freeze_invariant(self) -> None:
        text = (common.ROOT / "docs" / "SIGMASCOPE-DATA-COLLECTION-ORCHESTRATION.adoc").read_text(encoding="utf-8")
        self.assertIn("Collector activity MUST NOT directly rebuild or publish the Omega client database", text)
        self.assertIn("Phase 4 - parallel scanner/result merger", text)
        self.assertIn("Build Provenance/Rebuilder", text)
        self.assertIn("Threat Intelligence expansion", text)
        self.assertIn("provider activation reconciliation", text)
        self.assertIn("broker prerequisite chaining", text)
        self.assertIn("Evidence-v2 content reuse/deduplication", text)
        self.assertIn("Rift runtime execution remains a separate branch/workstream", text)

    def test_collection_lanes_are_separate_and_freeze_is_network_quiet(self) -> None:
        policy = (common.ROOT / "security-definitions" / "orchestration" / "work-policy.json").read_text(encoding="utf-8")
        self.assertIn('"queueId": "catalog-discovery"', policy)
        self.assertIn('"queueId": "catalog-enrichment"', policy)
        self.assertIn('"queueId": "catalog-scrape"', policy)
        self.assertIn('"queueId": "source-head-observation"', policy)
        self.assertIn('"queueId": "threat-intelligence"', policy)
        self.assertIn('"queueId": "osv-advisories"', policy)
        self.assertIn('"queueId": "secondary-security-definitions"', policy)
        self.assertIn('"prerequisites": [\n        "catalog-discovery"', policy)
        self.assertIn('"prerequisites": [\n        "catalog-enrichment"', policy)
        freeze = self.read_workflow("catalog-builder.yml")
        self.assertIn("freeze_inputs.py", freeze)
        self.assertIn("catalog_freeze_identity.py", freeze)
        self.assertIn("publisher-worker", freeze)
        for forbidden in (
            "collect_reputation_intelligence.py", "collect_public_advisories.py", "freshclam",
            "source_revision_observer.py", "enrich_metadata.py", "scrape_websites_incremental.py",
            "actions/setup-python", "apt-get install", "pip install",
        ):
            self.assertNotIn(forbidden, freeze)

    def test_all_linux_collectors_use_digest_manifest_and_lease_bound_results(self) -> None:
        workflows = {
            "catalog-discovery-worker.yml": "catalog-discovery",
            "catalog-enrichment-worker.yml": "catalog-enrichment",
            "catalog-scrape-worker.yml": "catalog-scrape",
            "source-head-worker.yml": "source-head-observation",
            "threat-intelligence-worker.yml": "threat-intelligence",
            "osv-worker.yml": "osv-advisories",
            "secondary-security-worker.yml": "secondary-security-definitions",
        }
        for name, queue in workflows.items():
            text=self.read_workflow(name)
            self.assertIn("security-worker-images", text)
            self.assertIn("worker_claim.py", text)
            self.assertIn(queue, text)
            self.assertIn("work_result.py build", text)
            self.assertIn("--worker-image", text)
            self.assertIn("needs.resolve-image.outputs.image", text)
            self.assertIn("publish_lane_state.py", text)
            self.assertIn("@sha256", (common.ROOT / "docs" / "SIGMASCOPE-DATA-COLLECTION-ORCHESTRATION.adoc").read_text(encoding="utf-8"))

    def test_workers_wake_only_reconciler_after_publishing_results(self) -> None:
        workflows = (
            "catalog-discovery-worker.yml", "catalog-enrichment-worker.yml", "catalog-scrape-worker.yml",
            "source-head-worker.yml", "threat-intelligence-worker.yml", "osv-worker.yml",
            "secondary-security-worker.yml",
        )
        for name in workflows:
            text = self.read_workflow(name)
            self.assertIn("actions: write", text)
            self.assertIn("Wake the reconciler after result publication", text)
            self.assertIn("gh workflow run security-orchestration-dispatch.yml", text)
            self.assertIn("-f mode=reconcile", text)
            self.assertNotIn("gh workflow run security-reconcile.yml", text)
            self.assertNotIn("gh workflow run catalog-freeze.yml", text)
            self.assertNotIn("gh workflow run catalog-builder.yml", text)

    def test_reconciler_dispatches_only_after_publishing_durable_leases(self) -> None:
        text=self.read_workflow("security-reconcile.yml")
        self.assertIn("Publish queue state before dispatch", text)
        self.assertIn("Dispatch newly leased or explicitly recovered exact work items", text)
        self.assertLess(text.index("Publish queue state before dispatch"), text.index("Dispatch newly leased or explicitly recovered exact work items"))
        self.assertIn("gh workflow run security-orchestration-dispatch.yml", text)
        self.assertIn("-f mode=worker", text)
        self.assertIn("row['queueId']", text)
        self.assertIn("actions: write", text)

    def test_worker_image_manifest_is_persisted_not_only_an_actions_artifact(self) -> None:
        text=self.read_workflow("worker-images.yml")
        self.assertIn("security-worker-images", text)
        self.assertIn("omega.worker-images.v1", text)
        self.assertIn("publish_worker_images.py", text)


if __name__ == "__main__":
    unittest.main()

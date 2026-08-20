from __future__ import annotations

import re
import unittest

import common


class WorkflowContractTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (common.ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")

    def assert_has(self, text: str, *snippets: str) -> None:
        for snippet in snippets:
            self.assertIn(snippet, text, f"workflow contract missing: {snippet}")

    def test_catalog_builder_is_daily_or_manual_json_authority_and_client_compiler(self) -> None:
        text = self.read("catalog-builder.yml")
        self.assert_has(
            text,
            "name: Omega catalog snapshot and client database",
            "workflow_call:",
            "workflow_dispatch:",
            "name: Freeze JSON state and compile the Omega client DB",
            "needs: [collect, enrich, scrape]",
            "ref: security-evidence-v2",
            "ref: catalog-data",
            "catalog_json_store.py",
            "catalog_json_store.py export",
            "identity-compatible",
            "legacy/incompatible identity epoch",
            "source_inventory_guard.py",
            "--aliases sources/source-url-aliases.json",
            "--report catalog/source-inventory.json",
            "Observe public source HEAD revisions without fetching source bodies",
            "source_revision_observer.py",
            "--source-observations catalog/source-revision-observations.json",
            "Freeze optional ClamAV feed into a content-addressed release asset",
            "secondary_security_assets.py build-clamav",
            "releases/download/sigmascope-definitions",
            "--secondary-security-asset-manifest",
            "definitions_snapshot.py build",
            "scan_queue.py build-seed",
            "--output catalog/state-scan-queue.json",
            "catalog_state.py assemble",
            "--queue-seed catalog/state-scan-queue.json",
            "--source-inventory catalog/source-inventory.json",
            "catalog_state.py validate",
            "publish_catalog_state.py",
            "--branch catalog-data",
            "compile_marketplace_snapshot.py",
            "validate_marketplace_catalog.py --root catalog/client-dist",
            "Publish the once-daily client database",
            "gh release upload catalog-latest",
            "omega-marketplace.sqlite.zip",
            "database-build.json",
        )
        self.assertLess(
            text.index("Validate exact client publication"),
            text.index("Publish canonical JSON state atomically"),
            "catalog-data must not advance until the exact daily client DB has compiled and validated locally",
        )
        self.assertLess(
            text.index("Publish canonical JSON state atomically"),
            text.index("Publish the once-daily client database"),
            "publish frozen online inputs immediately before the matching client DB",
        )
        self.assertNotIn("  schedule:", text, "schedule is owned by the thin default-branch launcher")
        self.assertNotIn("--allow-legacy-identity", text, "legacy catalog snapshots may be skipped as seeds but must never be materialized by weakening validation")
        self.assertNotIn("security-evidence-latest", text)
        self.assertNotIn("omega-security-evidence.sqlite.zip", text)

    def test_catalog_json_is_authoritative_public_state_not_a_main_branch_generated_commit(self) -> None:
        builder = self.read("catalog-builder.yml")
        publisher = (common.ROOT / "tools" / "catalog" / "publish_catalog_state.py").read_text(encoding="utf-8")
        self.assertIn("catalog-data", builder)
        self.assertIn("omega.catalog-state.v1", (common.ROOT / "tools" / "catalog" / "catalog_state.py").read_text(encoding="utf-8"))
        self.assertIn("omega.catalog-json.v1", (common.ROOT / "tools" / "catalog" / "catalog_json_store.py").read_text(encoding="utf-8"))
        self.assertIn("force-with-lease", publisher)
        self.assertNotIn("git add catalog/catalog-endpoint.json", builder)
        self.assertNotIn("git push\n", builder, "daily generated catalog state belongs on catalog-data, not main")

    def test_sigmascope_is_a_15_minute_single_item_evidence_worker(self) -> None:
        text = self.read("sigmascope.yml")
        self.assert_has(
            text,
            "name: Omega Sigmascope continuous worker",
            "workflow_call:",
            "workflow_dispatch:",
            "ref: catalog-data",
            "path: catalog/active-state",
            "ref: security-evidence-v2",
            "path: catalog/security-v2-current",
            "definitions_snapshot.py",
            "catalog_json_store.py",
            "production_sigmascope_v2_pipeline.py",
            "--skip-marketplace",
            "--frozen-advisories catalog/active-state/definitions/osv-advisories.json",
            '--catalog-revision "${{ steps.frozen.outputs.catalog_revision }}"',
            '--definitions-revision "${{ steps.frozen.outputs.definitions_revision }}"',
            '--scanner-revision "${{ steps.frozen.outputs.scanner_revision }}"',
            '--scanner-bundle-sha256 "${{ steps.frozen.outputs.scanner_bundle_sha256 }}"',
            '--artifact-analysis-revision "${{ steps.frozen.outputs.artifact_analysis_revision }}"',
            '--source-analysis-revision "${{ steps.frozen.outputs.source_analysis_revision }}"',
            '--rule-set-revision "${{ steps.frozen.outputs.rule_set_revision }}"',
            '--advisory-revision "${{ steps.frozen.outputs.advisory_revision }}"',
            "--queue-seed catalog/active-state/scan-queue.json",
            "--max-scans 1",
            "publish_security_evidence_v2.py",
            "--branch security-evidence-v2",
            "developer_view.py",
            "sigmascope-source-followups.json",
            "continue-on-error: true",
        )
        self.assertNotIn("schedule:", text, "schedule is owned by the thin default-branch launcher")
        self.assertNotIn("--rescan-after-hours", text, "production scheduling is event-driven, not age/TTL driven")
        self.assertNotIn("gh release upload catalog-latest", text, "continuous scanner must never publish the client DB")
        self.assertNotIn("validate_marketplace_catalog.py", text, "continuous scanner no longer builds a client projection")
        self.assertNotIn("omega-marketplace.sqlite.zip", text)

    def test_sigmascope_executes_frozen_worker_bundle_without_historical_dev_checkout(self) -> None:
        text = self.read("sigmascope.yml")
        self.assertIn("OMEGA_FROZEN_WORKER: catalog/active-state/definitions/worker", text)
        self.assertIn("OMEGA_SECONDARY_SECURITY_ROOT: catalog/active-state/definitions/secondary-security", text)
        self.assertIn("OMEGA_SECONDARY_SECURITY_CACHE: catalog/secondary-security-runtime", text)
        self.assertIn("Materialize exact frozen ClamAV definitions", text)
        self.assertIn("secondary_security_assets.py\" materialize-clamav", text)
        self.assertIn("--no-install-recommends clamav yara", text)
        self.assertIn("scanner_revision=", text)
        self.assertIn("scanner_bundle_sha256=", text)
        self.assertIn("Verify frozen worker bundle before execution", text)
        self.assertIn('$OMEGA_FROZEN_WORKER/tools/security/production_sigmascope_v2_pipeline.py', text)
        self.assertIn('$OMEGA_FROZEN_WORKER/tools/security/publish_security_evidence_v2.py', text)
        self.assertIn('$OMEGA_FROZEN_WORKER/sources/source-overrides.json', text)
        self.assertIn('--advisories catalog/active-state/definitions/osv-advisories.json', text)
        self.assertNotIn("git checkout --detach", text)
        self.assertNotIn("source_commit=", text)
        self.assertNotIn("definitions-source-commit", text)
        self.assertLess(text.index("Verify frozen worker bundle before execution"), text.index("Examine one due variant"))

    def test_definitions_freeze_rules_and_exact_osv_query_universe(self) -> None:
        definitions = (common.ROOT / "tools" / "catalog" / "definitions_snapshot.py").read_text(encoding="utf-8")
        pipeline = (common.ROOT / "tools" / "security" / "production_sigmascope_v2_pipeline.py").read_text(encoding="utf-8")
        self.assertIn("ruleFiles", definitions)
        self.assertIn("RULE_SET_FILES", definitions)
        self.assertIn("ruleSetRevision", definitions)
        self.assertIn("WORKER_BUNDLE_SCHEMA", definitions)
        self.assertIn("scannerRevision", definitions)
        self.assertIn("artifactAnalysisRevision", definitions)
        self.assertIn("sourceAnalysisRevision", definitions)
        self.assertIn("sourceObservationRevision", definitions)
        self.assertIn("source-revisions.json", definitions)
        self.assertIn("analysis_revision.compute", definitions)
        self.assertIn("scannerBundle", definitions)
        self.assertIn("builtFromDevCommit", definitions)
        self.assertNotIn('"sourceCommit": source_commit', definitions)
        self.assertIn("queriedPackageVersionPairs", definitions)
        self.assertIn("definitionsRevision", definitions)
        self.assertIn("SECONDARY_SECURITY_SCHEMA", definitions)
        self.assertIn("YARA_POLICY_SCHEMA", definitions)
        self.assertIn("secondary_security_assets.validate_asset_manifest", definitions)
        self.assertIn("secondarySecurity", definitions)
        self.assertIn("bind_artifact_analysis_revision", definitions)
        self.assertIn("notCoveredByFrozenDefinitions", pipeline)
        self.assertIn("frozen-definitions", pipeline)
        self.assertIn("--skip-marketplace", pipeline)
        self.assertIn("queueSeedRevision", pipeline)
        self.assertIn("primaryReason", pipeline)

    def test_source_submission_persists_now_but_waits_for_daily_or_manual_publication(self) -> None:
        text = self.read("source-submissions.yml")
        self.assert_has(
            text,
            "name: Omega source submissions",
            "workflow_call:",
            "workflow_dispatch:",
            "tools/catalog/process_source_submission.py",
            "sources/community-sources.json",
            "sources/source-overrides.json",
            "persist-credentials: false",
            "needs: validate",
            "needs.validate.outputs.status == 'accepted'",
            "contents: write",
            "Record daily processing boundary",
            "next daily catalog/Definitions snapshot",
            'gh issue close "$ISSUE_NUMBER"',
            "persisted it disabled-by-default",
        )
        self.assertNotIn("gh workflow run catalog-builder.yml", text)
        self.assertNotIn("gh workflow run sigmascope.yml", text)
        validate_start = text.index("  validate:")
        persist_start = text.index("\n  persist:\n")
        validate_block = text[validate_start:persist_start]
        persist_block = text[persist_start:]
        self.assertIn("contents: read", validate_block)
        self.assertNotIn("contents: write", validate_block)
        self.assertIn("contents: write", persist_block)
        self.assertIn("Revalidate and materialize the accepted source change", persist_block)

    def test_catalog_builder_ingests_community_source_metadata_explicitly(self) -> None:
        text = self.read("catalog-builder.yml")
        self.assertIn("--community sources/community-sources.json", text)
        self.assertGreaterEqual(text.count("--community sources/community-sources.json"), 2)

    def test_legacy_compactor_is_manual_and_never_publishes(self) -> None:
        text = self.read("catalog-compaction.yml")
        self.assert_has(
            text,
            "name: Omega legacy SQLite catalog compactor (disabled)",
            "workflow_dispatch:",
            "Legacy compactor compatibility self-tests only",
            "python tools/catalog/compact_sqlite_catalog.py --self-test",
            "python tools/catalog/project_marketplace_catalog.py --self-test",
            "The v1 SQLite evidence release is archival only.",
        )
        self.assertNotIn("schedule:", text, "schedule is owned by the thin default-branch launcher")
        self.assertNotIn("gh release upload", text)
        self.assertNotIn("contents: write", text)

    def test_revision_and_v2_publication_tools_are_separated_by_workflow(self) -> None:
        builder = self.read("catalog-builder.yml")
        security = self.read("sigmascope.yml")
        self.assertIn("publish_catalog_state.py", builder)
        self.assertIn("compile_marketplace_snapshot.py", builder)
        self.assertIn("validate_marketplace_catalog.py", builder)
        self.assertIn("production_sigmascope_v2_pipeline.py", security)
        self.assertIn("publish_security_evidence_v2.py", security)
        self.assertNotIn("compile_marketplace_snapshot.py", security)

    def test_catalog_and_sigmascope_are_mutually_exclusive(self) -> None:
        catalog = self.read("catalog-builder.yml")
        security = self.read("sigmascope.yml")
        shared_group = "group: omega-catalog-sigmascope-exclusive"
        self.assertIn(shared_group, catalog)
        self.assertIn(shared_group, security)
        self.assertIn("cancel-in-progress: false", catalog)
        self.assertIn("cancel-in-progress: false", security)
        self.assertNotIn("group: omega-daily-catalog-publication", catalog)
        self.assertNotIn("group: omega-sigmascope", security)

    def test_workflows_do_not_embed_large_python_heredocs(self) -> None:
        for name in ("catalog-builder.yml", "sigmascope.yml", "catalog-compaction.yml"):
            self.assertNotIn("python - <<'PY'", self.read(name), f"{name} should call tested Python modules instead of inline Python")


if __name__ == "__main__":
    unittest.main()

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
            "name: Omega daily catalog snapshot and client database",
            'cron: "17 2 * * *"',
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
        self.assertNotRegex(text, r"(?m)^  push:\s*$", "ordinary source pushes must not create client-visible catalog churn")
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
            'cron: "*/15 * * * *"',
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
        self.assertNotIn("workflow_run:", text)
        self.assertNotIn("--rescan-after-hours", text, "production scheduling is event-driven, not age/TTL driven")
        self.assertNotIn("gh release upload catalog-latest", text, "continuous scanner must never publish the client DB")
        self.assertNotIn("validate_marketplace_catalog.py", text, "continuous scanner no longer builds a client projection")
        self.assertNotIn("omega-marketplace.sqlite.zip", text)

    def test_sigmascope_executes_frozen_worker_bundle_without_historical_dev_checkout(self) -> None:
        text = self.read("sigmascope.yml")
        self.assertIn("OMEGA_FROZEN_WORKER: catalog/active-state/definitions/worker", text)
        self.assertIn("scanner_revision=", text)
        self.assertIn("scanner_bundle_sha256=", text)
        self.assertIn("Verify frozen worker bundle before execution", text)
        self.assertIn('$OMEGA_FROZEN_WORKER/tools/security/production_sigmascope_v2_pipeline.py', text)
        self.assertIn('$OMEGA_FROZEN_WORKER/tools/security/publish_security_evidence_v2.py', text)
        self.assertIn('$OMEGA_FROZEN_WORKER/sources/source-overrides.json', text)
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
            "issues:",
            "issue_comment:",
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
        self.assertNotIn("workflow_run:", text)
        self.assertNotIn("gh release upload", text)
        self.assertNotIn("contents: write", text)

    def test_catalog_bootstrap_prefers_exact_published_client_db_with_legacy_fallback(self) -> None:
        helper = (common.ROOT / "tools" / "catalog" / "stage_catalog_bootstrap.py").read_text(encoding="utf-8")
        regression = self.read("regression-tests.yml")
        release = self.read("release.yml")
        self.assertIn('MARKETPLACE_BUNDLE_NAME = "omega-marketplace.sqlite.zip"', helper)
        self.assertIn('validate_marketplace_catalog.validate_bytes', helper)
        self.assertIn('BUILDER_WORKFLOW = "catalog-builder.yml"', helper)
        self.assertIn('ARTIFACT_NAME = "omega-sqlite-catalog"', helper)
        self.assertIn('validate_base_catalog.validate_local', helper)
        self.assertIn('"gh", "release", "download", "catalog-latest"', helper)
        self.assertIn('"gh", "run", "list"', helper)
        self.assertIn("tools/catalog/stage_catalog_bootstrap.py", regression)
        self.assertIn("tools/catalog/stage_catalog_bootstrap.py", release)

    def test_client_code_has_no_full_security_evidence_endpoint(self) -> None:
        omega_root = common.ROOT / "Omega"
        combined = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in omega_root.rglob("*.cs"))
        self.assertNotIn("security-evidence-latest", combined)
        self.assertNotIn("omega-security-evidence.sqlite.zip", combined)
        self.assertIn("EvidenceRevision", combined)

    def test_repository_regression_workflow_covers_python_and_dotnet(self) -> None:
        text = self.read("regression-tests.yml")
        self.assertIn('- "sources/**"', text)
        self.assert_has(
            text,
            "name: Omega repository regression tests",
            "pull_request:",
            "workflow_dispatch:",
            "actions: read",
            "python -m unittest discover -s tools/tests -p 'test_*.py' -v",
            "python tools/catalog/sigmascope.py --self-test",
            "python tools/catalog/sigmascope.py --hardening-self-test",
            "python tools/catalog/compact_sqlite_catalog.py --self-test",
            "python tools/catalog/project_marketplace_catalog.py --self-test",
            "Stage validated current catalog bootstrap",
            "tools/catalog/stage_catalog_bootstrap.py",
            "--output catalog/bootstrap/omega-catalog.sqlite.zip",
            "dotnet build .\\Omega.sln -c Release",
        )
        self.assertLess(text.index("Stage validated current catalog bootstrap"), text.index("dotnet build .\\Omega.sln -c Release"))

    def test_revision_and_v2_publication_tools_are_separated_by_workflow(self) -> None:
        builder = self.read("catalog-builder.yml")
        security = self.read("sigmascope.yml")
        self.assertIn("publish_catalog_state.py", builder)
        self.assertIn("compile_marketplace_snapshot.py", builder)
        self.assertIn("validate_marketplace_catalog.py", builder)
        self.assertIn("production_sigmascope_v2_pipeline.py", security)
        self.assertIn("publish_security_evidence_v2.py", security)
        self.assertNotIn("compile_marketplace_snapshot.py", security)

    def test_release_workflow_runs_python_and_dotnet_regressions_before_publish(self) -> None:
        text = self.read("release.yml")
        self.assert_has(
            text,
            "Run repository Python regression suite",
            "python -m unittest discover -s tools/tests -p 'test_*.py' -v",
            "Stage validated current catalog bootstrap",
            "tools/catalog/stage_catalog_bootstrap.py",
            "--output catalog/bootstrap/omega-catalog.sqlite.zip",
            "Build and run regression suite",
            "dotnet build .\\Omega.sln -c Release",
            "Publish immutable versioned release",
        )
        self.assertLess(text.index("Run repository Python regression suite"), text.index("Publish immutable versioned release"))
        self.assertLess(text.index("Build and run regression suite"), text.index("Publish immutable versioned release"))

    def test_release_queues_one_deliberate_out_of_cycle_daily_snapshot(self) -> None:
        text = self.read("release.yml")
        self.assertIn("Queue Definitions rebuild for published Omega feed", text)
        self.assertIn("gh workflow run catalog-builder.yml", text)
        self.assertNotIn("gh workflow run sigmascope.yml", text)

    def test_release_workflow_uses_three_part_versions_for_ziprunner(self) -> None:
        text = self.read("release.yml")
        self.assertIn('      - "v*.*.*"', text)
        self.assertNotIn('      - "v*.*.*.*"', text)
        self.assertIn(r"^v(?<version>\d+\.\d+\.\d+)$", text)
        self.assertIn("Distributed plugin version $distributedVersion does not match release tag assembly version $expectedAssemblyVersion", text)
        self.assertIn("generate_pluginmaster.py", text)
        self.assertIn("repository/pluginmaster.template.json", text)
        self.assertIn("Verify immutable versioned release asset", text)
        self.assertIn("gh release upload omega-latest pluginmaster.json Omega.zip Omega.zip.sha256 --clobber", text)
        self.assertIn("Publish legacy raw-main PluginMaster compatibility mirror", text)

    def test_release_feed_is_generated_from_built_package_before_stable_publication(self) -> None:
        text = self.read("release.yml")
        ordered = [
            "Assemble Dalamud package",
            "Generate PluginMaster from packaged Omega.zip",
            "Publish immutable versioned release",
            "Verify immutable versioned release asset",
            "Publish stable generated Dalamud feed",
            "Verify stable generated Dalamud feed",
            "Publish legacy raw-main PluginMaster compatibility mirror",
        ]
        positions = [text.index(item) for item in ordered]
        self.assertEqual(sorted(positions), positions)
        self.assertIn("--package Omega.zip", text)
        self.assertIn("--tag '${{ steps.release.outputs.tag }}'", text)
        self.assertNotIn("Get-Content 'repository/pluginmaster.json'", text)
        self.assertIn("group: omega-release-stable", text)
        self.assertIn("actions: write", text)
        versioned = text[text.index("Publish immutable versioned release"):text.index("Verify immutable versioned release asset")]
        self.assertNotIn("--clobber", versioned)
        self.assertIn("Refusing to clobber the tagged release", versioned)

    def test_release_package_contains_private_sqlite_runtime(self) -> None:
        text = self.read("release.yml")
        self.assertIn("e_sqlite3.dll", text)
        self.assertIn("SQLitePCLRaw.provider.e_sqlite3.dll", text)
        self.assertIn("Build output is missing the bundled e_sqlite3.dll runtime.", text)
        self.assertIn("Compress-Archive -Path (Join-Path $extract '*')", text)
        self.assertNotIn("SQLitePCLRaw.provider.winsqlite3", text)

    def test_workflows_do_not_embed_large_python_heredocs(self) -> None:
        for name in ("catalog-builder.yml", "sigmascope.yml", "catalog-compaction.yml"):
            self.assertNotIn("python - <<'PY'", self.read(name), f"{name} should call tested Python modules instead of inline Python")

    def test_release_uses_project_changelog(self):
        release = self.read("release.yml")
        changelog = (common.ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        extractor = (common.ROOT / "tools" / "release" / "extract_changelog.py").read_text(encoding="utf-8")
        self.assertIn("extract_changelog.py", release)
        self.assertIn("--notes-file release-notes.md", release)
        self.assertIn("## [0.8.56]", changelog)
        self.assertIn("CHANGELOG.md has no release section", extractor)


if __name__ == "__main__":
    unittest.main()

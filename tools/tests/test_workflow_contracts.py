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

    def test_catalog_publish_installs_security_dependencies_before_definitions_freeze(self) -> None:
        text = self.read("catalog-builder.yml")
        publish_start = text.index("\n  publish:\n")
        publish_block = text[publish_start:]
        install = "Install pinned Python security dependencies"
        verify = "Verify Definitions freezer Python dependencies"
        freeze = "Freeze daily Definitions and OSV data"
        self.assertIn(install, publish_block)
        self.assertIn("-r tools/requirements-security.txt", publish_block)
        self.assertIn(verify, publish_block)
        self.assertIn("import yaml", publish_block)
        self.assertLess(publish_block.index(install), publish_block.index(verify))
        self.assertLess(publish_block.index(verify), publish_block.index(freeze))
        yara_install = "Install YARA compile-check dependency for Definitions freezer"
        self.assertIn(yara_install, publish_block)
        self.assertIn("apt-get install -y --no-install-recommends yara", publish_block)
        self.assertLess(publish_block.index(yara_install), publish_block.index(freeze))


    def test_optional_clamav_freeze_is_atomic_and_never_blocks_definitions(self) -> None:
        text = self.read("catalog-builder.yml")
        start = text.index("Freeze optional ClamAV feed into a content-addressed release asset")
        end = text.index("Freeze daily Definitions and OSV data", start)
        block = text[start:end]
        self.assertIn('pending_manifest="catalog/secondary-security-asset-manifest.pending.json"', block)
        self.assertIn('--manifest-output "$pending_manifest"', block)
        self.assertIn('gh release upload sigmascope-definitions', block)
        self.assertIn('mv "$pending_manifest" "$final_manifest"', block)
        self.assertLess(block.index('gh release upload sigmascope-definitions'), block.index('mv "$pending_manifest" "$final_manifest"'))
        self.assertIn("retain-previous-clamav", block)
        self.assertIn("continuing this Definitions revision without ClamAV", block)
        self.assertIn("if ! sudo apt-get install -y --no-install-recommends clamav clamav-freshclam", block)
        self.assertIn("if gh release upload", block)
        build_start = block.index('secondary_security_assets.py build-clamav')
        build_end = block.index('release_ready=true', build_start)
        self.assertNotIn('--manifest-output "$final_manifest"', block[build_start:build_end])
        self.assertNotIn("python - <<", block)

    def test_catalog_json_is_authoritative_public_state_not_a_main_branch_generated_commit(self) -> None:
        builder = self.read("catalog-builder.yml")
        publisher = (common.ROOT / "tools" / "catalog" / "publish_catalog_state.py").read_text(encoding="utf-8")
        self.assertIn("catalog-data", builder)
        self.assertIn("omega.catalog-state.v1", (common.ROOT / "tools" / "catalog" / "catalog_state.py").read_text(encoding="utf-8"))
        self.assertIn("omega.catalog-json.v1", (common.ROOT / "tools" / "catalog" / "catalog_json_store.py").read_text(encoding="utf-8"))
        self.assertIn("force-with-lease", publisher)
        self.assertNotIn("git add catalog/catalog-endpoint.json", builder)
        self.assertNotIn("git push\n", builder, "daily generated catalog state belongs on catalog-data, not main")

    def test_sigmascope_is_a_15_minute_bounded_batch_evidence_worker(self) -> None:
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
            "--frozen-definitions catalog/active-state/definitions",
            '--catalog-revision "${{ steps.frozen.outputs.catalog_revision }}"',
            '--definitions-revision "${{ steps.frozen.outputs.definitions_revision }}"',
            '--scanner-revision "${{ steps.frozen.outputs.scanner_revision }}"',
            '--scanner-bundle-sha256 "${{ steps.frozen.outputs.scanner_bundle_sha256 }}"',
            '--artifact-analysis-revision "${{ steps.frozen.outputs.artifact_analysis_revision }}"',
            '--source-analysis-revision "${{ steps.frozen.outputs.source_analysis_revision }}"',
            '--rule-set-revision "${{ steps.frozen.outputs.rule_set_revision }}"',
            '--advisory-revision "${{ steps.frozen.outputs.advisory_revision }}"',
            "--queue-seed catalog/active-state/scan-queue.json",
            "--max-scans 20",
            "analysis_request_json",
            "--analysis-request catalog/security-v2-work/analysis-request.json",
            "sigmascope_request_adapter.py\" verify",
            "publish_security_evidence_v2.py",
            "--branch security-evidence-v2",
            "security_developer_audit.py",
            "sigmascope-source-followups.json",
            "continue-on-error: true",
        )
        self.assertNotIn("schedule:", text, "schedule is owned by the thin default-branch launcher")
        self.assertNotIn("--rescan-after-hours", text, "production scheduling is event-driven, not age/TTL driven")
        self.assertNotIn("gh release upload catalog-latest", text, "continuous scanner must never publish the client DB")
        self.assertNotIn("validate_marketplace_catalog.py", text, "continuous scanner no longer builds a client projection")
        self.assertNotIn("omega-marketplace.sqlite.zip", text)

    def test_authenticode_is_a_dedicated_nonexecuting_windows_collector_lane(self) -> None:
        text = self.read("sigmascope.yml")
        probe = (common.ROOT / "tools" / "security" / "authenticode_probe.ps1").read_text(encoding="utf-8")
        collector = (common.ROOT / "tools" / "security" / "authenticode_collector.py").read_text(encoding="utf-8")
        registry = (common.ROOT / "tools" / "security" / "collector_contracts.py").read_text(encoding="utf-8")
        self.assertIn('if [ "$observation" = "binarySignatureTrust" ]; then lane="authenticode"; fi', text)
        auth = text[text.index("  authenticode:"):text.index("  notify-discord:")]
        self.assertIn("runs-on: windows-latest", auth)
        self.assertIn("ref: security-evidence-v2", auth)
        self.assertIn('definitions_snapshot.py" verify-worker', auth)
        self.assertIn("authenticode_collector.py", auth)
        self.assertIn("authenticode_probe.ps1", auth)
        self.assertIn("collector_results.py", auth)
        self.assertIn("collector_evidence_adapter.py", auth)
        self.assertIn("collector_evidence_audit.py", auth)
        self.assertIn("gh auth setup-git", auth)
        self.assertIn("publish_security_evidence_v2.py", auth)
        self.assertNotIn("actions: read", auth)
        self.assertNotIn('--github-token "$GITHUB_TOKEN"', auth)
        self.assertIn("Get-AuthenticodeSignature", probe)
        self.assertNotIn("Start-Process", probe)
        self.assertNotIn("Invoke-Expression", probe)
        self.assertNotIn("Invoke-Command", probe)
        self.assertIn("subprocess.run", collector)
        self.assertNotIn("shell=True", collector)
        self.assertIn('"network": True, "status": "active"', registry)
        regression = self.read("regression-tests.yml")
        self.assertIn("authenticode-windows:", regression)
        self.assertIn("runs-on: windows-latest", regression)
        self.assertIn("authenticode_probe.ps1", regression)
        self.assertIn("omega.authenticode.windows-probe.v1", regression)

    def test_native_structure_is_a_dedicated_nonexecuting_collector_lane(self) -> None:
        text = self.read("sigmascope.yml")
        collector = (common.ROOT / "tools" / "security" / "native_structure_collector.py").read_text(encoding="utf-8")
        registry = (common.ROOT / "tools" / "security" / "collector_contracts.py").read_text(encoding="utf-8")
        self.assertIn('if [ "$observation" = "elfBinaryStructure" ] || [ "$observation" = "machOBinaryStructure" ]; then lane="native-structure"; fi', text)
        native = text[text.index("  native-structure:"):text.index("  authenticode:")]
        self.assertIn("runs-on: ubuntu-latest", native)
        self.assertIn("native_structure_collector.py", native)
        self.assertIn("collector_evidence_adapter.py", native)
        self.assertIn("collector_evidence_audit.py", native)
        self.assertIn("publish_security_evidence_v2.py", native)
        self.assertIn("gh auth setup-git", native)
        self.assertNotIn("subprocess.run", collector)
        self.assertNotIn("os.system", collector)
        self.assertIn('"elfBinaryStructure"', registry)
        self.assertIn('"machOBinaryStructure"', registry)

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
        self.assertLess(text.index("Verify frozen worker bundle before execution"), text.index("Examine bounded due-variant batch"))



    def test_analysis_broker_is_non_executing_durable_control_plane_state(self) -> None:
        broker = self.read("analysis-broker.yml")
        caller = (common.ROOT / "docs" / "workflow-callers" / "analysis-broker-main.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_call:", broker)
        self.assertIn("workflow_dispatch:", broker)
        self.assertIn("analysis-broker-state", broker)
        self.assertIn("Reconcile neutral collector coverage goals", broker)
        self.assertIn("collector_coverage.py", broker)
        self.assertIn("collector-coverage-report.json", broker)
        self.assertIn("analysis_broker.py enqueue", broker)
        self.assertIn("publish_analysis_broker_state.py", broker)
        self.assertIn("Materialize current reusable observation inventory", broker)
        self.assertIn("Reconcile retained Stigma-1 hard dependencies", broker)
        self.assertIn("observation_inventory.py", broker)
        self.assertIn("stigma_broker_bridge.py", broker)
        self.assertNotIn("uses: dalagab/omega/.github/workflows/sigmascope.yml", broker)
        self.assertNotIn("uses: dalagab/omega/.github/workflows/catalog-discovery.yml", broker)
        self.assertNotIn("@rift", broker)
        self.assertNotIn("schedule:", broker)
        self.assertIn("uses: dalagab/omega/.github/workflows/analysis-broker.yml@sigmascope", caller)
        self.assertIn("workflow_dispatch:", caller)

    def test_analysis_dispatcher_is_a_leased_parallel_runner_with_static_main_routes(self) -> None:
        claim = self.read("analysis-dispatcher-claim.yml")
        batch = self.read("analysis-dispatcher-batch-claim.yml")
        self.assertEqual(batch.count("      allowed_components:"), 2)  # workflow_call + workflow_dispatch; duplicate keys are forbidden
        settle = self.read("analysis-dispatcher-settle.yml")
        caller = (common.ROOT / "docs" / "workflow-callers" / "analysis-dispatcher-main.yml").read_text(encoding="utf-8")
        discovery_worker = (common.ROOT / "docs" / "workflow-callers" / "analysis-dispatch-discovery-main.yml").read_text(encoding="utf-8")
        sigmascope_worker = (common.ROOT / "docs" / "workflow-callers" / "analysis-dispatch-sigmascope-main.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_call:", claim)
        self.assertIn("analysis_dispatcher.py claim", claim)
        self.assertIn("analysis_dispatcher.py claim-batch", batch)
        self.assertIn("max_in_flight", batch)
        self.assertIn("allowed_components", batch)
        self.assertIn("default: omega.discovery", batch)
        self.assertIn("omega-analysis-broker-state", batch)
        self.assertIn("Publish all leases atomically before any worker launch", batch)
        self.assertIn("analysis_dispatcher.py settle", settle)
        self.assertIn("omega-analysis-broker-state", settle)
        self.assertIn("claim_token", settle)
        self.assertIn("cron: '*/5 * * * *'", caller)
        self.assertIn("analysis-dispatcher-batch-claim.yml@sigmascope", caller)
        self.assertIn("max_claims: 4", caller)
        self.assertIn("max_in_flight: 4", caller)
        self.assertIn("allowed_components: omega.discovery,omega.sigmascope", caller)
        self.assertIn('case "$component" in', caller)
        self.assertIn("gh workflow run analysis-dispatch-discovery.yml", caller)
        self.assertIn("gh workflow run analysis-dispatch-sigmascope.yml", caller)
        self.assertNotIn("needs.reserve.outputs.workflow", caller, "queue data must never select a workflow path dynamically")
        self.assertIn("uses: dalagab/omega/.github/workflows/catalog-discovery.yml@sigmascope", discovery_worker)
        self.assertIn("uses: dalagab/omega/.github/workflows/analysis-dispatcher-settle.yml@sigmascope", discovery_worker)
        self.assertIn("uses: dalagab/omega/.github/workflows/sigmascope.yml@sigmascope", sigmascope_worker)
        self.assertIn("analysis_request_json: ${{ inputs.request_json }}", sigmascope_worker)
        self.assertIn("uses: dalagab/omega/.github/workflows/analysis-dispatcher-settle.yml@sigmascope", sigmascope_worker)
        self.assertNotIn("@rift", caller + discovery_worker + sigmascope_worker)

    def test_stigma_deep_scan_is_a_separate_frozen_worker_queue(self) -> None:
        sigmascope = self.read("sigmascope.yml")
        deep = self.read("deep-scan.yml")
        caller = (common.ROOT / "docs" / "workflow-callers" / "deep-scan-main.yml").read_text(encoding="utf-8")
        self.assertIn("--deep-scan-output", sigmascope)
        self.assertIn("deep_scan_pending", sigmascope)
        self.assertIn("Frozen worker predates Stigma-1 deep-scan queue support", sigmascope)
        self.assertIn("gh workflow run deep-scan.yml --ref sigmascope", sigmascope)
        self.assertIn("continue-on-error: true", sigmascope[sigmascope.index("Publish durable Stigma-1 deep-scan queue"):sigmascope.index("Project public-source coverage follow-ups")])
        self.assertIn("workflow_call:", deep)
        self.assertIn("workflow_dispatch:", deep)
        self.assertNotIn("schedule:", deep)
        self.assertIn("$OMEGA_FROZEN_WORKER/tools/security/deep_scan_worker.py", deep)
        self.assertIn("$OMEGA_FROZEN_WORKER/tools/security/deep_scan_queue.py", deep)
        self.assertIn("$OMEGA_FROZEN_WORKER/tools/security/publish_deep_scan_state.py", deep)
        self.assertIn('cron: "37 * * * *"', caller)
        self.assertIn("uses: dalagab/omega/.github/workflows/deep-scan.yml@sigmascope", caller)

    def test_regression_workflow_runs_for_yara_definition_changes_and_installs_real_yara(self) -> None:
        text = self.read("regression-tests.yml")
        self.assertIn('"security-definitions/**"', text)
        self.assertIn("Install YARA compile-check dependency", text)
        self.assertIn("apt-get install -y --no-install-recommends yara", text)
        self.assertLess(text.index("Install YARA compile-check dependency"), text.index("Run security-services Python regression suite"))

        # Every workflow that executes the full repository suite must provide the
        # same real YARA compiler first, because enabled production rules are
        # intentionally compile-checked while Definitions fixtures are built.
        for workflow in ("catalog-builder.yml", "catalog-compaction.yml"):
            workflow_text = self.read(workflow)
            self.assertIn("Install YARA compile-check dependency", workflow_text, workflow)
            self.assertIn("apt-get install -y --no-install-recommends yara", workflow_text, workflow)
            self.assertLess(
                workflow_text.index("Install YARA compile-check dependency"),
                workflow_text.index("Run repository Python regression suite"),
                workflow,
            )

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
        self.assertIn("materialize_srl_reprojection_sidecar", pipeline)
        self.assertIn('root_index["srlRuleProjections"]', pipeline)
        self.assertIn("materialize_definition_provenance_index", pipeline)
        self.assertIn('indexes["definitionProvenance"]', pipeline)
        self.assertIn("provenance_changed", pipeline)
        self.assertIn('"productionWriteBack": False', pipeline)
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

    def test_catalog_discovery_is_independent_and_non_authoritative(self) -> None:
        worker = self.read("catalog-discovery.yml")
        launcher = self.read("catalog-discovery-launcher.yml")
        builder = self.read("catalog-builder.yml")
        self.assertIn("workflow_call:", worker)
        self.assertIn("catalog_discovery.py", worker)
        self.assertIn("publish_catalog_discovery.py", worker)
        self.assertIn("--branch catalog-discovery", worker)
        self.assertNotIn("publish_catalog_state.py", worker)
        self.assertNotIn("definitions_snapshot.py", worker)
        self.assertNotIn("production_sigmascope_v2_pipeline.py", worker)
        self.assertIn('cron: "41 */6 * * *"', launcher)
        self.assertIn("uses: dalagab/omega/.github/workflows/catalog-discovery.yml@sigmascope", launcher)
        self.assertIn("ref: catalog-discovery", builder)
        self.assertIn("--canonical-source-index catalog/current-catalog/catalog/sources/index.json", builder)
        self.assertIn("--discovery-snapshot catalog/discovery-state/source-candidates.json", builder)
        self.assertIn("BRAVE_SEARCH_API_KEY", worker)
        self.assertIn("Run typed discovery collectors and validate only novel source facts", worker)
        self.assertIn("observations.json", worker)
        self.assertIn("collector-registry.json", worker)

    def test_client_cache_hints_come_from_canonical_catalog_not_previous_client_db(self) -> None:
        text = self.read("catalog-builder.yml")
        self.assertIn("Materialize canonical source cache hints", text)
        self.assertIn("Materialize canonical website cache hints", text)
        self.assertGreaterEqual(text.count("catalog_json_store.py materialize"), 3)
        self.assertNotIn("Download previous published marketplace DB for conditional request hints", text)
        self.assertNotIn("Download previous published marketplace DB for website cache hints", text)
        self.assertIn("client_database_audit.py", text)
        self.assertIn("storage-audit.json", text)

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

    def test_rift_runtime_ingestion_is_broker_bound_and_evidence_only(self) -> None:
        text = self.read("rift-evidence-ingest.yml")
        self.assertIn("omega-catalog-sigmascope-exclusive", text)
        self.assertIn("rift_evidence_adapter.py", text)
        self.assertIn("rift_evidence_audit.py", text)
        self.assertIn("security-evidence-v2", text)
        self.assertIn("publish_security_evidence_v2.py", text)
        self.assertNotIn("--allow-unbound-local", text)
        self.assertNotIn("sigmascope.py scan", text)



if __name__ == "__main__":
    unittest.main()

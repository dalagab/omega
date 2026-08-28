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

    def test_catalog_builder_is_explicit_authoritative_freeze_without_client_publication(self) -> None:
        text = self.read("catalog-builder.yml")
        self.assert_has(
            text,
            "name: Omega catalog freeze worker",
            "workflow_call:",
            "workflow_dispatch:",
            "Resolve immutable publisher toolchain",
            'ref: security-worker-images',
            'image: ${{ needs.resolve-publisher-image.outputs.image }}',
            "Validate all lane results against settled durable queues",
            "freeze_inputs.py",
            "ref: catalog-discovery-work-state",
            "ref: catalog-enrichment-state",
            "ref: catalog-scrape-state",
            "ref: source-head-state",
            "ref: threat-intelligence-state",
            "ref: osv-advisory-state",
            "ref: secondary-security-state",
            "catalog_json_store.py materialize",
            "catalog_json_store.py export",
            'schema == "omega.catalog-json.v2"',
            'identityEpoch == "omega-catalog-identity-v1"',
            "catalog_json_v1_seed.py",
            "test_identity_rows_over_16_mib_are_sharded_and_round_trip",
            "source_inventory_guard.py",
            "--aliases sources/source-url-aliases.json",
            "--report catalog/source-inventory.json",
            "--source-observations catalog/lane-results/source-head-observation/source-revision-observations.json",
            "--reputation-input catalog/lane-results/threat-intelligence/reputation-intelligence.json",
            "--advisories-input catalog/lane-results/osv-advisories/osv-advisories.json",
            "--secondary-security-asset-manifest",
            "definitions_snapshot.py build",
            "scan_queue.py build-seed",
            "catalog_state.py assemble",
            "catalog_state.py validate",
            "catalog_freeze_identity.py",
            "Publish changed frozen JSON state atomically",
            "publish_catalog_state.py",
            "--branch catalog-data",
        )
        self.assertNotIn("  schedule:", text, "freeze is an explicit release boundary")
        for forbidden in (
            "collect_sources.py", "enrich_metadata.py", "scrape_websites_incremental.py",
            "source_revision_observer.py", "collect_reputation_intelligence.py",
            "collect_public_advisories.py", "freshclam", "apt-get install", "pip install",
            "compile_marketplace_snapshot.py", "validate_marketplace_catalog.py",
            "client_database_audit.py", "gh release upload catalog-latest",
            "catalog/client-dist",
        ):
            self.assertNotIn(forbidden, text, f"freeze must not perform collector/customer publication work: {forbidden}")
        self.assertNotIn("--allow-legacy-identity", text)
        self.assertNotIn("security-evidence-latest", text)
        self.assertNotIn("omega-security-evidence.sqlite.zip", text)

    def test_customer_database_publication_reads_only_authoritative_branches(self) -> None:
        text = self.read("catalog-client-publish.yml")
        self.assert_has(
            text,
            "name: Omega catalog · publish customer database",
            "workflow_call:",
            "workflow_dispatch:",
            "ref: catalog-data",
            "path: catalog/active-state",
            "ref: security-evidence-v2",
            "path: catalog/security-v2-current",
            "catalog_state.py validate --root catalog/active-state",
            "compile_marketplace_snapshot.py",
            "--catalog-root catalog/active-state/catalog",
            "--definitions-root catalog/active-state/definitions",
            "--evidence-root catalog/security-v2-current",
            "validate_marketplace_catalog.py --root catalog/client-dist --require-v2",
            "client_database_audit.py",
            "largestGrowthTables",
            "storage-audit.json",
            "gh release upload catalog-latest",
            "omega-marketplace.sqlite.zip",
        )
        self.assertLess(
            text.index("Checkout authoritative Security Evidence v2"),
            text.index("Compile Omega customer database from authoritative state"),
        )
        for forbidden in (
            "freeze_inputs.py", "definitions_snapshot.py build", "scan_queue.py build-seed",
            "collect_sources.py", "enrich_metadata.py", "scrape_websites_incremental.py",
        ):
            self.assertNotIn(forbidden, text, f"customer publisher must not mutate authoritative inputs: {forbidden}")

    def test_catalog_publish_installs_security_dependencies_before_definitions_freeze(self) -> None:
        text = self.read("catalog-builder.yml")
        self.assertIn("Resolve immutable publisher toolchain", text)
        self.assertIn('ref: security-worker-images', text)
        self.assertIn('publisher-worker', text)
        self.assertIn('image: ${{ needs.resolve-publisher-image.outputs.image }}', text)
        self.assertIn("Verify frozen publisher toolchain", text)
        self.assertIn("import yaml", text)
        self.assertIn("yara --version", text)
        self.assertLess(text.index("Verify frozen publisher toolchain"), text.index("Freeze Definitions only from settled collector outputs"))
        self.assertNotIn("actions/setup-python", text)
        self.assertNotIn("python -m pip install", text)
        self.assertNotIn("apt-get install", text)

    def test_optional_clamav_freeze_is_atomic_and_never_blocks_definitions(self) -> None:
        worker = self.read("secondary-security-worker.yml")
        freeze = self.read("catalog-builder.yml")
        self.assertIn("freshclam --stdout", worker)
        self.assertIn("secondary_security_assets.py build-clamav", worker)
        self.assertIn("gh release upload sigmascope-definitions", worker)
        self.assertIn("retain-previous-clamav", worker)
        self.assertIn("release-create-failed", worker)
        self.assertIn("release-upload-failed", worker)
        self.assertIn("retained the previous frozen ClamAV asset", worker)
        self.assertIn("assetAvailable", worker)
        self.assertIn("work_result.py build", worker)
        self.assertIn("--branch secondary-security-state", worker)
        self.assertNotIn("freshclam", freeze)
        self.assertNotIn("secondary_security_assets.py build-clamav", freeze)
        self.assertIn("secondary-security-asset-manifest.json", freeze)
        self.assertIn("--secondary-security-asset-manifest", freeze)

    def test_catalog_json_is_authoritative_public_state_not_a_main_branch_generated_commit(self) -> None:
        builder = self.read("catalog-builder.yml")
        publisher = (common.ROOT / "tools" / "catalog" / "publish_catalog_state.py").read_text(encoding="utf-8")
        self.assertIn("catalog-data", builder)
        self.assertIn("omega.catalog-state.v1", (common.ROOT / "tools" / "catalog" / "catalog_state.py").read_text(encoding="utf-8"))
        self.assertIn("omega.catalog-json.v2", (common.ROOT / "tools" / "catalog" / "catalog_json_store.py").read_text(encoding="utf-8"))
        self.assertIn("HISTORY_FAST_FORWARD", publisher)
        self.assertIn("publish_snapshot_tree", publisher)
        self.assertNotIn("checkout", "--orphan", publisher)
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

        compaction = self.read("catalog-compaction.yml")
        self.assertIn("Install YARA compile-check dependency", compaction)
        self.assertIn("apt-get install -y --no-install-recommends yara", compaction)
        self.assertLess(compaction.index("Install YARA compile-check dependency"), compaction.index("Run repository Python regression suite"))

        # Catalog freeze no longer installs the compiler at runtime; it executes in
        # the digest-pinned publisher image and verifies the baked toolchain.
        freeze = self.read("catalog-builder.yml")
        self.assertIn("Resolve immutable publisher toolchain", freeze)
        self.assertIn("yara --version", freeze)
        self.assertNotIn("apt-get install -y --no-install-recommends yara", freeze)

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
            "Record catalog-freeze processing boundary",
            "next explicit catalog freeze",
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
        periodic = self.read("catalog-discovery-worker.yml")
        broker_provider = self.read("catalog-discovery.yml")
        reconciler = self.read("security-reconcile.yml")
        builder = self.read("catalog-builder.yml")
        self.assertIn("catalog_discovery.py", periodic)
        self.assertIn("worker_claim.py", periodic)
        self.assertIn("work_result.py build", periodic)
        self.assertIn("--branch catalog-discovery-work-state", periodic)
        self.assertIn("Publish backward-compatible typed Discovery snapshot", periodic)
        self.assertIn("publish_catalog_discovery.py", periodic)
        self.assertIn("--branch catalog-discovery", periodic)
        self.assertIn("BRAVE_SEARCH_API_KEY", periodic)
        self.assertNotIn("publish_catalog_state.py", periodic)
        self.assertNotIn("definitions_snapshot.py", periodic)
        self.assertNotIn("compile_marketplace_snapshot.py", periodic)
        policy = (common.ROOT / "security-definitions" / "orchestration" / "work-policy.json").read_text(encoding="utf-8")
        self.assertIn("catalog-discovery-worker.yml", policy)
        self.assertIn("ref: catalog-discovery-work-state", reconciler)
        self.assertIn("ref: catalog-discovery-work-state", builder)
        self.assertIn("name: Omega Discovery · broker full refresh", broker_provider)
        self.assertIn("workflow_call:", broker_provider)
        self.assertNotIn("schedule:", broker_provider)
        self.assertIn("--branch catalog-discovery", broker_provider)
        self.assertFalse((common.ROOT / ".github" / "workflows" / "catalog-discovery-launcher.yml").exists(), "legacy scheduled discovery launcher must be retired")

    def test_client_cache_hints_come_from_canonical_catalog_not_previous_client_db(self) -> None:
        enrichment = self.read("catalog-enrichment-worker.yml")
        scraper = self.read("catalog-scrape-worker.yml")
        freeze = self.read("catalog-builder.yml")
        customer = self.read("catalog-client-publish.yml")
        self.assertIn("Materialize previous catalog cache", enrichment)
        self.assertIn("catalog_json_store.py materialize", enrichment)
        self.assertIn("catalog_json_v1_seed.py", enrichment)
        self.assertIn('schema == "omega.catalog-json.v2"', enrichment)
        self.assertIn('schema == "omega.catalog-json.v1"', enrichment)
        self.assertIn("Materialize previous catalog website cache", scraper)
        self.assertIn("catalog_json_store.py materialize", scraper)
        self.assertIn("catalog_json_v1_seed.py", scraper)
        self.assertIn('schema == "omega.catalog-json.v2"', scraper)
        self.assertIn('schema == "omega.catalog-json.v1"', scraper)
        self.assertNotIn("Download previous published marketplace DB for conditional request hints", enrichment + scraper + freeze)
        self.assertNotIn("Download previous published marketplace DB for website cache hints", enrichment + scraper + freeze)
        self.assertNotIn("client_database_audit.py", freeze)
        self.assertNotIn("storage-audit.json", freeze)
        self.assertIn("client_database_audit.py", customer)
        self.assertIn("storage-audit.json", customer)

    def test_catalog_builder_ingests_community_source_metadata_explicitly(self) -> None:
        text = self.read("catalog-builder.yml")
        self.assertIn("--community sources/community-sources.json", text)
        self.assertGreaterEqual(text.count("--community sources/community-sources.json"), 2)

    def test_legacy_compactor_is_retired_from_actions(self) -> None:
        active = common.ROOT / ".github" / "workflows" / "catalog-compaction.yml"
        retired = common.ROOT / ".github" / "retired-workflows" / "legacy" / "catalog-compaction.yml"
        self.assertFalse(active.exists())
        text = retired.read_text(encoding="utf-8")
        self.assertIn("name: Omega legacy SQLite catalog compactor (disabled)", text)
        self.assertNotIn("gh release upload", text)
        self.assertNotIn("contents: write", text)

    def test_revision_and_v2_publication_tools_are_separated_by_workflow(self) -> None:
        builder = self.read("catalog-builder.yml")
        customer = self.read("catalog-client-publish.yml")
        security = self.read("sigmascope.yml")
        self.assertIn("publish_catalog_state.py", builder)
        self.assertNotIn("compile_marketplace_snapshot.py", builder)
        self.assertNotIn("validate_marketplace_catalog.py", builder)
        self.assertIn("compile_marketplace_snapshot.py", customer)
        self.assertIn("validate_marketplace_catalog.py", customer)
        self.assertIn("gh release upload catalog-latest", customer)
        self.assertIn("production_sigmascope_v2_pipeline.py", security)
        self.assertIn("publish_security_evidence_v2.py", security)
        self.assertIn("--history-mode fast-forward", builder)
        self.assertIn("--history-mode fast-forward", security)
        self.assertNotIn("--history-mode legacy-orphan", builder)
        self.assertNotIn("--history-mode legacy-orphan", security)
        self.assertNotIn("publish_catalog_state.py", customer)
        self.assertNotIn("compile_marketplace_snapshot.py", security)

    def test_catalog_and_sigmascope_are_mutually_exclusive(self) -> None:
        catalog = self.read("catalog-builder.yml")
        security = self.read("sigmascope.yml")
        drain = self.read("sigmascope-parallel-drain.yml")
        shared_group = "omega-catalog-sigmascope-exclusive"

        # Continuous serialized and parallel Evidence publication share one authority mutex.
        self.assertIn(f"group: {shared_group}", security)
        self.assertIn(f"group: {shared_group}", drain)
        self.assertIn("cancel-in-progress: false", drain)
        self.assertIn("queue: max", drain)

        # Catalog freeze retains its existing nested-authority escape hatch. The label
        # still contains the historical Phase-4 name but is only an internal group name.
        self.assertIn("inputs.authority_lock_held", catalog)
        self.assertIn("omega-catalog-freeze-under-phase4-", catalog)
        self.assertIn(f"|| '{shared_group}'", catalog)

        self.assertIn("cancel-in-progress: false", catalog)
        self.assertIn("cancel-in-progress: false", security)
        self.assertNotIn("group: omega-daily-catalog-publication", catalog)
        self.assertNotIn("group: omega-sigmascope", security)

    def test_workflows_do_not_embed_large_python_heredocs(self) -> None:
        for name in ("catalog-builder.yml", "sigmascope.yml"):
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

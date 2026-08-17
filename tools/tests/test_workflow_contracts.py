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

    def test_catalog_builder_contract(self) -> None:
        text = self.read("catalog-builder.yml")
        self.assert_has(
            text,
            "name: Omega SQLite catalog builder",
            "push:",
            "branches: [main]",
            '- "tools/catalog/**"',
            '- "sources/**"',
            '- "catalog/bootstrap/**"',
            '- ".github/workflows/catalog-builder.yml"',
            '- ".github/workflows/security-scanner.yml"',
            '- ".github/workflows/catalog-compaction.yml"',
            "workflow_dispatch:",
            "schedule:",
            "name: 4) Build and hand off authoritative catalog state",
            "needs: [collect, enrich, scrape]",
            "python tools/catalog/validate_base_catalog.py --root catalog/dist",
            "name: omega-sqlite-catalog",
            "omega-marketplace.sqlite.zip",
            "Download previous small marketplace database as catalog seed",
        )
        self.assertRegex(text, r"(?m)^  preflight:\s*$")
        self.assertRegex(text, r"(?m)^  collect:\s*\n(?:.|\n)*?    needs: preflight\s*$")
        self.assertNotIn("gh release upload catalog-latest", text, "base builder must not publish an intermediate production catalog")
        self.assertNotIn("gh release upload security-evidence-latest", text, "base builder must not publish evidence directly")


    def test_database_processing_changes_restart_from_catalog_builder(self) -> None:
        builder = self.read("catalog-builder.yml")
        security = self.read("security-scanner.yml")
        compactor = self.read("catalog-compaction.yml")

        # One broad path owns every current/future catalog-processing module. This is deliberate:
        # adding a new Python module under tools/catalog automatically restarts the whole chain.
        self.assertIn('- "tools/catalog/**"', builder)
        self.assertIn('- "sources/**"', builder)
        self.assertIn('- "catalog/bootstrap/**"', builder)
        self.assertIn('- ".github/workflows/security-scanner.yml"', builder)
        self.assertIn('- ".github/workflows/catalog-compaction.yml"', builder)

        # Security chains from the catalog builder; the retired v1 compactor is manual only.
        self.assertNotRegex(security, r"(?m)^  push:\s*$")
        self.assertNotRegex(compactor, r"(?m)^  push:\s*$")
        self.assertIn('- "Omega SQLite catalog builder"', security)
        self.assertIn("workflow_dispatch:", compactor)
        self.assertNotIn("workflow_run:", compactor)

        catalog_modules = list((common.ROOT / "tools" / "catalog").glob("*.py"))
        self.assertGreater(len(catalog_modules), 5, "catalog processing modules should exist under the trigger root")

    def test_security_scanner_stages_and_publishes_v2_fail_closed(self) -> None:
        text = self.read("security-scanner.yml")
        self.assert_has(
            text,
            "name: Omega plugin security scanner",
            '- "Omega SQLite catalog builder"',
            "github.event.workflow_run.conclusion == 'success'",
            "actions: read",
            "contents: write",
            "issues: write",
            "ref: security-evidence-v2",
            "path: catalog/security-v2-current",
            "--name omega-sqlite-catalog",
            "production_security_v2_pipeline.py",
            "--candidate-evidence catalog/security-v2-candidate",
            "--source-overrides sources/source-overrides.json",
            "validate_marketplace_catalog.py --root catalog/publication-output",
            "developer_view.py audit",
            "security-developer-audit.json",
            "publish_security_evidence_v2.py",
            "--snapshot-validation-report",
            "--audit-report",
            "--branch security-evidence-v2",
            "gh release upload catalog-latest",
            "source-scan-followups.json",
            "tools/catalog/create_source_followup_issues.py",
            "continue-on-error: true",
        )
        self.assertNotIn("security-evidence-latest", text)
        self.assertNotIn("omega-security-evidence.sqlite.zip", text)
        self.assertNotIn("omega-security-catalog", text)



    def test_source_submission_workflow_validates_before_privileged_persistence_and_restarts_minimum_chain(self) -> None:
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
            "trusted: ${{ steps.trust.outputs.trusted }}",
            "OWNER|MEMBER|COLLABORATOR",
            "needs.validate.outputs.trusted == 'true'",
            "maintainer approval",
            "contents: write",
            "actions: write",
            "gh workflow run catalog-builder.yml",
            "gh workflow run security-scanner.yml",
            'internal_names="$internal"',
        )
        validate_start = text.index("  validate:")
        persist_start = text.index("\n  persist:\n")
        validate_block = text[validate_start:persist_start]
        persist_block = text[persist_start:]
        self.assertIn("contents: read", validate_block)
        self.assertNotIn("contents: write", validate_block)
        self.assertIn("contents: write", persist_block)
        self.assertIn("needs.validate.outputs.trusted == 'true'", persist_block)
        self.assertIn("Revalidate and materialize the accepted source change", persist_block)

    def test_catalog_builder_ingests_community_source_metadata_explicitly(self) -> None:
        text = self.read("catalog-builder.yml")
        self.assertIn("--community sources/community-sources.json", text)
        self.assertGreaterEqual(text.count("--community sources/community-sources.json"), 2)

    def test_security_scanner_routes_osv_through_the_v2_pipeline(self) -> None:
        workflow = self.read("security-scanner.yml")
        pipeline = (common.ROOT / "tools" / "security" / "production_security_v2_pipeline.py").read_text(encoding="utf-8")
        self.assertIn("production_security_v2_pipeline.py", workflow)
        self.assertIn("collect_public_advisories.collect", pipeline)
        self.assertIn("nugetPackageVersionPairs", pipeline)
        self.assertIn("OSV publication gate failed", pipeline)
        self.assertIn("max_scans=0", pipeline, "advisory matches must be re-projected without starting another artifact scan")
        self.assertIn("security-advisory-refresh-report.json", pipeline)



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
        self.assertNotIn("gh release upload security-evidence-latest", text)
        self.assertNotIn("omega-security-evidence.sqlite.zip", text)
        self.assertNotIn("contents: write", text)

    def test_marketplace_publication_follows_v2_snapshot_gate(self) -> None:
        text = self.read("security-scanner.yml")
        v2_publish = text.index("Publish validated Security Evidence v2 snapshot atomically")
        marketplace = text.index("Publish small client marketplace only after all v2 gates pass")
        self.assertLess(v2_publish, marketplace)
        self.assertIn("if: steps.v2.outputs.publish_v2 == 'true'", text)
        self.assertIn("if: steps.v2.outputs.publish_marketplace == 'true'", text)
        self.assertIn("--audit-report catalog/security-v2-work/security-developer-audit.json", text)
        self.assertNotIn("omega-security-evidence.sqlite.zip", text)

    def test_builder_never_downloads_archived_v1_evidence(self) -> None:
        text = self.read("catalog-builder.yml")
        self.assertIn("omega-marketplace.sqlite.zip", text)
        self.assertNotIn("security-evidence-latest", text)
        self.assertNotIn("omega-security-evidence.sqlite.zip", text)

    def test_workflow_chain_names_match_exactly(self) -> None:
        builder = self.read("catalog-builder.yml")
        security = self.read("security-scanner.yml")
        builder_name = re.search(r"(?m)^name:\s*(.+)$", builder).group(1).strip()
        self.assertIn(builder_name, security)
        self.assertIn("Omega legacy SQLite catalog compactor (disabled)", self.read("catalog-compaction.yml"))



    def test_client_code_has_no_evidence_database_endpoint(self) -> None:
        omega_root = common.ROOT / "Omega"
        combined = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in omega_root.rglob("*.cs")
        )
        self.assertNotIn("security-evidence-latest", combined)
        self.assertNotIn("omega-security-evidence.sqlite.zip", combined)
        self.assertIn("EvidenceRevision", combined, "client may display the evidence identity without downloading evidence")

    def test_repository_regression_workflow_covers_python_and_dotnet(self) -> None:
        text = self.read("regression-tests.yml")
        self.assertIn('- "sources/**"', text)
        self.assert_has(
            text,
            "name: Omega repository regression tests",
            "pull_request:",
            "workflow_dispatch:",
            "python -m unittest discover -s tools/tests -p 'test_*.py' -v",
            "python tools/catalog/security_scan.py --self-test",
            "python tools/catalog/security_scan.py --hardening-self-test",
            "python tools/catalog/compact_sqlite_catalog.py --self-test",
            "python tools/catalog/project_marketplace_catalog.py --self-test",
            "dotnet build .\\Omega.sln -c Release",
        )

    def test_workflows_do_not_duplicate_tool_version_constants(self) -> None:
        self.assertNotIn("2.0.0", self.read("security-scanner.yml"))
        self.assertNotIn("1.2.0", self.read("catalog-compaction.yml"))
        self.assertNotIn("1.0.0", self.read("catalog-compaction.yml"))

    def test_revision_and_v2_publication_tools_are_workflow_inputs(self) -> None:
        builder = self.read("catalog-builder.yml")
        security = self.read("security-scanner.yml")
        self.assertIn('- "tools/catalog/**"', builder, "all catalog/security processing modules must restart from the builder on push")
        self.assertIn("production_security_v2_pipeline.py", security)
        self.assertIn("publish_security_evidence_v2.py", security)
        self.assertIn("validate_marketplace_catalog.py", security)

    def test_release_workflow_runs_python_and_dotnet_regressions_before_publish(self) -> None:
        text = self.read("release.yml")
        self.assert_has(
            text,
            "Run repository Python regression suite",
            "python -m unittest discover -s tools/tests -p 'test_*.py' -v",
            "Build and run regression suite",
            "dotnet build .\\Omega.sln -c Release",
            "Publish immutable versioned release",
        )
        self.assertLess(text.index("Run repository Python regression suite"), text.index("Publish immutable versioned release"))
        self.assertLess(text.index("Build and run regression suite"), text.index("Publish immutable versioned release"))

    def test_release_workflow_uses_three_part_versions_for_ziprunner(self) -> None:
        text = self.read("release.yml")
        self.assertIn('      - "v*.*.*"', text)
        self.assertNotIn('      - "v*.*.*.*"', text)
        self.assertIn(r"^v(?<version>\d+\.\d+\.\d+)$", text)
        self.assertNotIn(r"^v(?<version>\d+\.\d+\.\d+\.\d+)$", text)
        self.assertIn('$expectedAssemblyVersion = "$tagVersion.0"', text)
        self.assertIn('Distributed plugin version $distributedVersion does not match repo version $repoVersion', text)

    def test_release_package_contains_private_sqlite_runtime(self) -> None:
        text = self.read("release.yml")
        self.assertIn("e_sqlite3.dll", text)
        self.assertIn("SQLitePCLRaw.provider.e_sqlite3.dll", text)
        self.assertIn("Build output is missing the bundled e_sqlite3.dll runtime.", text)
        self.assertIn("Compress-Archive -Path (Join-Path $extract '*')", text)
        self.assertNotIn("SQLitePCLRaw.provider.winsqlite3", text)

    def test_workflows_do_not_embed_large_python_heredocs(self) -> None:
        for name in ("catalog-builder.yml", "security-scanner.yml", "catalog-compaction.yml"):
            text = self.read(name)
            self.assertNotIn("python - <<'PY'", text, f"{name} should call tested Python modules instead of inline Python")



    def test_release_uses_project_changelog(self):
        release = (common.ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        changelog = (common.ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        extractor = (common.ROOT / "tools" / "release" / "extract_changelog.py").read_text(encoding="utf-8")
        self.assertIn("extract_changelog.py", release)
        self.assertIn("--notes-file release-notes.md", release)
        self.assertIn("## [0.8.56]", changelog)
        self.assertIn("CHANGELOG.md has no release section", extractor)

if __name__ == "__main__":
    unittest.main()

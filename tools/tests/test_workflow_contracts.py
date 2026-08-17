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
            "omega-security-evidence.sqlite.zip",
            "omega-marketplace.sqlite.zip",
            "security-evidence-latest",
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

        # Downstream workflows chain from builder/scanner completion instead of also firing on the
        # same push. That prevents duplicate scans/compactions while still executing changed code.
        self.assertNotRegex(security, r"(?m)^  push:\s*$")
        self.assertNotRegex(compactor, r"(?m)^  push:\s*$")
        self.assertIn('- "Omega SQLite catalog builder"', security)
        self.assertIn('- "Omega plugin security scanner"', compactor)

        catalog_modules = list((common.ROOT / "tools" / "catalog").glob("*.py"))
        self.assertGreater(len(catalog_modules), 5, "catalog processing modules should exist under the trigger root")

    def test_security_scanner_is_read_only_and_hands_off_an_artifact(self) -> None:
        text = self.read("security-scanner.yml")
        self.assert_has(
            text,
            "name: Omega plugin security scanner",
            '- "Omega SQLite catalog builder"',
            "github.event.workflow_run.conclusion == 'success'",
            "actions: read",
            "contents: read",
            "issues: write",
            "--name omega-sqlite-catalog",
            "security-evidence-latest",
            "omega-security-evidence.sqlite.zip",
            "python tools/catalog/validate_security_catalog.py --root catalog/security-output",
            "name: omega-security-catalog",
            "--ledger catalog/security-output/security-scan-ledger.json",
            "--source-overrides sources/source-overrides.json",
            "source-scan-followups.json",
            "tools/catalog/create_source_followup_issues.py",
            "continue-on-error: true",
            "security-scan-ledger.json",
        )
        self.assertNotIn("contents: write", text)
        self.assertNotIn("gh release upload", text)


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

    def test_security_scanner_collects_public_advisories_before_dependency_projection(self) -> None:
        text = self.read("security-scanner.yml")
        collector = "python tools/catalog/collect_public_advisories.py"
        scanner = "python tools/catalog/security_scan.py"
        self.assertIn(collector, text)
        self.assertIn("--advisories catalog/security-output/public-advisories.json", text)
        self.assertIn("catalog/security-output/public-advisories.json", text)
        self.assertLess(text.index(collector), text.rindex(scanner))
        self.assertGreaterEqual(text.count(collector), 2, "advisories are refreshed after newly scanned dependencies are discovered")
        self.assertIn("--max-scans 0", text, "fresh advisory matches are re-projected without rescanning plugin artifacts")
        self.assertIn("security-advisory-refresh-report.json", text)

    def test_compactor_is_only_database_publisher_and_splits_client_from_evidence(self) -> None:
        text = self.read("catalog-compaction.yml")
        self.assert_has(
            text,
            "name: Omega SQLite catalog compactor",
            '- "Omega plugin security scanner"',
            "github.event.workflow_run.conclusion == 'success'",
            "--name omega-security-catalog",
            "python tools/catalog/project_marketplace_catalog.py",
            "python tools/catalog/validate_marketplace_catalog.py --root catalog/publication-output",
            "python tools/catalog/validate_evidence_catalog.py --root catalog/publication-output",
            "name: omega-publication-databases",
            "python tools/catalog/publication_decision.py",
            "publish_marketplace:",
            "needs: [compact, publish_evidence]",
            "needs.publish_evidence.result == 'success'",
            "Publish client marketplace catalog",
            "omega-marketplace.sqlite.zip",
            "gh release upload catalog-latest",
            "publish_evidence:",
            "if: needs.compact.outputs.publish_evidence == 'true'",
            "Publish server-side security evidence database",
            "omega-security-evidence.sqlite.zip",
            "gh release upload security-evidence-latest",
            "name: Publish scan freshness ledger only",
            "if: needs.compact.outputs.publish_marketplace == 'false' && needs.compact.outputs.publish_evidence == 'false'",
        )
        # Repository write permission must be scoped to publication jobs, never the compaction/analysis job.
        compact_start = text.index("  compact:")
        marketplace_start = text.index("\n  publish_marketplace:\n")
        compact_block = text[compact_start:marketplace_start]
        self.assertNotIn("contents: write", compact_block)

        marketplace_end = text.index("\n  publish_evidence:\n")
        marketplace_block = text[marketplace_start:marketplace_end]
        self.assertIn("contents: write", marketplace_block)
        self.assertIn("gh release upload catalog-latest", marketplace_block)
        self.assertNotIn("omega-security-evidence.sqlite.zip", marketplace_block, "client release must never publish detailed evidence database")

        evidence_end = text.index("\n  publish_scan_ledger:\n")
        evidence_block = text[marketplace_end:evidence_end]
        self.assertIn("contents: write", evidence_block)
        self.assertIn("gh release upload security-evidence-latest", evidence_block)
        self.assertIn("omega-security-evidence.sqlite.zip", evidence_block)

        ledger_block = text[evidence_end:]
        self.assertIn("security-evidence-latest", ledger_block)
        self.assertNotIn("omega-marketplace.sqlite.zip", ledger_block)
        self.assertNotIn("omega-security-evidence.sqlite.zip", ledger_block)


    def test_marketplace_publication_waits_for_required_evidence_publication(self) -> None:
        text = self.read("catalog-compaction.yml")
        marketplace_start = text.index("\n  publish_marketplace:\n")
        evidence_start = text.index("\n  publish_evidence:\n")
        marketplace_block = text[marketplace_start:evidence_start]
        self.assertIn("needs: [compact, publish_evidence]", marketplace_block)
        self.assertIn("always()", marketplace_block)
        self.assertIn("needs.compact.result == 'success'", marketplace_block)
        self.assertIn("needs.compact.outputs.publish_evidence == 'false'", marketplace_block)
        self.assertIn("needs.publish_evidence.result == 'success'", marketplace_block)

    def test_publish_jobs_checkout_validator_source(self) -> None:
        text = self.read("catalog-compaction.yml")
        marketplace_start = text.index("\n  publish_marketplace:\n")
        evidence_start = text.index("\n  publish_evidence:\n")
        ledger_start = text.index("\n  publish_scan_ledger:\n")
        for name, block, validator in (
            ("marketplace", text[marketplace_start:evidence_start], "tools/catalog/validate_marketplace_catalog.py"),
            ("evidence", text[evidence_start:ledger_start], "tools/catalog/validate_evidence_catalog.py"),
        ):
            checkout = block.index("actions/checkout@v6")
            setup = block.index("actions/setup-python@v7")
            verify = block.index(validator)
            self.assertLess(checkout, verify, f"{name} publish job must checkout repository before validator")
            self.assertLess(setup, verify, f"{name} publish job must set up Python before validator")
            self.assertIn("persist-credentials: false", block)

    def test_workflow_chain_names_match_exactly(self) -> None:
        builder = self.read("catalog-builder.yml")
        security = self.read("security-scanner.yml")
        compactor = self.read("catalog-compaction.yml")
        builder_name = re.search(r"(?m)^name:\s*(.+)$", builder).group(1).strip()
        security_name = re.search(r"(?m)^name:\s*(.+)$", security).group(1).strip()
        self.assertIn(builder_name, security)
        self.assertIn(security_name, compactor)

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

    def test_revision_and_changelog_tools_are_workflow_inputs(self) -> None:
        builder = self.read("catalog-builder.yml")
        compactor = self.read("catalog-compaction.yml")
        self.assertIn('- "tools/catalog/**"', builder, "all revision/publication modules must restart from the builder on push")
        self.assertIn("python tools/catalog/publication_decision.py", compactor)
        self.assertIn("python tools/catalog/project_marketplace_catalog.py", compactor)

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

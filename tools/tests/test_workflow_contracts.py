from __future__ import annotations

import re
import unittest
from pathlib import Path

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
            "workflow_dispatch:",
            "schedule:",
            "name: 4) Build and hand off SQLite catalog",
            "needs: [collect, enrich, scrape]",
            "python tools/catalog/validate_base_catalog.py --root catalog/dist",
            "name: omega-sqlite-catalog",
            "omega-catalog.sqlite.zip",
        )
        self.assertRegex(text, r"(?m)^  preflight:\s*$")
        self.assertRegex(text, r"(?m)^  collect:\s*\n(?:.|\n)*?    needs: preflight\s*$")
        self.assertNotIn("gh release upload catalog-latest", text, "base builder must not publish an intermediate production catalog")

    def test_security_scanner_is_read_only_and_hands_off_an_artifact(self) -> None:
        text = self.read("security-scanner.yml")
        self.assert_has(
            text,
            "name: Omega plugin security scanner",
            '      - "Omega SQLite catalog builder"',
            "github.event.workflow_run.conclusion == 'success'",
            "actions: read",
            "contents: read",
            '      - "tools/catalog/validate_security_catalog.py"',
            "--name omega-sqlite-catalog",
            "python tools/catalog/validate_security_catalog.py --root catalog/security-output",
            "name: omega-security-catalog",
            "--ledger catalog/security-output/security-scan-ledger.json",
            "security-scan-ledger.json",
        )
        self.assertNotIn("contents: write", text)
        self.assertNotIn("gh release upload", text)

    def test_compactor_is_only_production_security_publisher(self) -> None:
        text = self.read("catalog-compaction.yml")
        self.assert_has(
            text,
            "name: Omega SQLite catalog compactor",
            '      - "Omega plugin security scanner"',
            '      - "tools/catalog/validate_compacted_catalog.py"',
            "github.event.workflow_run.conclusion == 'success'",
            "--name omega-security-catalog",
            "python tools/catalog/validate_compacted_catalog.py --root catalog/compaction-output",
            "name: omega-compacted-catalog",
            "needs: compact",
            "contents: write",
            "python tools/catalog/publication_decision.py",
            "if: needs.compact.outputs.publish == 'true'",
            "gh release upload catalog-latest",
            "compaction-report.json",
            "--previous-database catalog/previous/omega-catalog.sqlite",
            "security-scan-ledger.json",
            "name: Publish scan freshness ledger without replacing catalog",
            "if: needs.compact.outputs.publish == 'false'",
        )
        publish_index = text.index("  publish:")
        write_index = text.index("contents: write")
        self.assertGreater(write_index, publish_index, "write permission must be scoped to publish job")
        ledger_job = text[text.index("  publish_scan_ledger:"):]
        self.assertNotIn("omega-catalog.sqlite.zip \\n", ledger_job, "ledger-only job must not upload database")

    def test_workflow_chain_names_match_exactly(self) -> None:
        builder = self.read("catalog-builder.yml")
        security = self.read("security-scanner.yml")
        compactor = self.read("catalog-compaction.yml")
        builder_name = re.search(r"(?m)^name:\s*(.+)$", builder).group(1).strip()
        security_name = re.search(r"(?m)^name:\s*(.+)$", security).group(1).strip()
        self.assertIn(f'- "{builder_name}"', security)
        self.assertIn(f'- "{security_name}"', compactor)

    def test_repository_regression_workflow_covers_python_and_dotnet(self) -> None:
        text = self.read("regression-tests.yml")
        self.assert_has(
            text,
            "name: Omega repository regression tests",
            "pull_request:",
            "workflow_dispatch:",
            "python -m unittest discover -s tools/tests -p 'test_*.py' -v",
            "python tools/catalog/security_scan.py --self-test",
            "python tools/catalog/security_scan.py --hardening-self-test",
            "python tools/catalog/compact_sqlite_catalog.py --self-test",
            "dotnet build .\\Omega.sln -c Release",
        )



    def test_workflows_do_not_duplicate_tool_version_constants(self) -> None:
        self.assertNotIn("1.9.0", self.read("security-scanner.yml"))
        self.assertNotIn("1.1.0", self.read("catalog-compaction.yml"))

    def test_revision_and_changelog_tools_are_workflow_inputs(self) -> None:
        security = self.read("security-scanner.yml")
        compactor = self.read("catalog-compaction.yml")
        self.assertIn('      - "tools/catalog/catalog_revisions.py"', security)
        self.assertIn('      - "tools/catalog/catalog_revisions.py"', compactor)
        self.assertIn('      - "tools/catalog/publication_decision.py"', compactor)

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

    def test_workflows_do_not_embed_large_python_heredocs(self) -> None:
        for name in ("catalog-builder.yml", "security-scanner.yml", "catalog-compaction.yml"):
            text = self.read(name)
            self.assertNotIn("python - <<'PY'", text, f"{name} should call tested Python modules instead of inline Python")


if __name__ == "__main__":
    unittest.main()

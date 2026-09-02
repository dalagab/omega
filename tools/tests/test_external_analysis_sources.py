from __future__ import annotations

import copy
import unittest

import common
import external_analysis_sources


class ExternalAnalysisSourceRegistryTests(unittest.TestCase):
    def test_repository_registry_is_valid_and_license_gated(self) -> None:
        registry = external_analysis_sources.load_registry()
        self.assertEqual("omega.sigmascope.external-analysis-sources.v1", registry["schema"])
        self.assertTrue(str(registry["revision"]).startswith("external-analysis-sources-v1-"))
        self.assertGreaterEqual(len(registry["sources"]), 6)

        by_id = {source["id"]: source for source in registry["sources"]}
        self.assertTrue(by_id["github-codeql-csharp"]["usage"]["aiIngestion"])
        self.assertTrue(by_id["dotnet-roslyn"]["usage"]["automatedInspection"])
        self.assertFalse(by_id["sonarsource-sonar-dotnet"]["usage"]["aiIngestion"])
        self.assertEqual("metadata-only", by_id["sonarsource-sonar-dotnet"]["usage"]["derivationMode"])
        self.assertEqual("blocked", by_id["semgrep-community-rules"]["usage"]["copyImplementation"])
        self.assertTrue(all(not source["usage"]["runtimeImport"] for source in registry["sources"]))

    def test_automated_research_excludes_restricted_sources(self) -> None:
        ids = {source["id"] for source in external_analysis_sources.automated_research_sources()}
        self.assertIn("github-codeql-csharp", ids)
        self.assertIn("dotnet-roslyn", ids)
        self.assertIn("security-code-scan", ids)
        self.assertIn("semgrep-engine", ids)
        self.assertNotIn("sonarsource-sonar-dotnet", ids)
        self.assertNotIn("semgrep-community-rules", ids)

    def test_restricted_source_cannot_enable_ai_ingestion(self) -> None:
        registry = external_analysis_sources.load_registry()
        document = {key: value for key, value in registry.items() if key not in {"revision", "path"}}
        document = copy.deepcopy(document)
        source = next(item for item in document["sources"] if item["id"] == "sonarsource-sonar-dotnet")
        source["usage"]["automatedInspection"] = True
        source["usage"]["aiIngestion"] = True
        with self.assertRaisesRegex(ValueError, "restricted source"):
            external_analysis_sources.validate_registry(document)

    def test_runtime_import_is_always_rejected(self) -> None:
        registry = external_analysis_sources.load_registry()
        document = {key: value for key, value in registry.items() if key not in {"revision", "path"}}
        document = copy.deepcopy(document)
        document["sources"][0]["usage"]["runtimeImport"] = True
        with self.assertRaisesRegex(ValueError, "runtime import"):
            external_analysis_sources.validate_registry(document)

    def test_repository_must_be_canonical_public_github_url(self) -> None:
        registry = external_analysis_sources.load_registry()
        document = {key: value for key, value in registry.items() if key not in {"revision", "path"}}
        document = copy.deepcopy(document)
        document["sources"][0]["repository"] = "https://github.com/example/repo/tree/main"
        with self.assertRaisesRegex(ValueError, "exactly one GitHub repository"):
            external_analysis_sources.validate_registry(document)


if __name__ == "__main__":
    unittest.main()

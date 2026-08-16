from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET
import common


class DotNetProjectContractTests(unittest.TestCase):
    def test_regression_project_links_all_product_models(self) -> None:
        project = common.ROOT / "Omega.RegressionTests" / "Omega.RegressionTests.csproj"
        tree = ET.parse(project)
        compile_items = [
            node.attrib.get("Include", "")
            for node in tree.getroot().iter("Compile")
        ]
        self.assertIn(
            r"..\Omega\Models\*.cs",
            compile_items,
            "regression project must wildcard-link product models so newly added model dependencies compile automatically",
        )

        explicit_models = [
            item for item in compile_items
            if item.startswith("..\\Omega\\Models\\") and item != r"..\Omega\Models\*.cs"
        ]
        self.assertEqual(
            [],
            explicit_models,
            "individual product model links are brittle; use the wildcard contract instead",
        )

        product_models = sorted((common.ROOT / "Omega" / "Models").glob("*.cs"))
        self.assertGreaterEqual(len(product_models), 1)
        self.assertIn(
            common.ROOT / "Omega" / "Models" / "MarketplaceAutomationCapability.cs",
            product_models,
            "automation capability model must remain part of the production model set",
        )


    def test_persistent_image_cache_is_linked_into_runtime_and_regressions(self) -> None:
        project = common.ROOT / "Omega.RegressionTests" / "Omega.RegressionTests.csproj"
        text = project.read_text(encoding="utf-8")
        self.assertIn(r"..\Omega\Services\PluginImageCacheStore.cs", text)

        plugin = (common.ROOT / "Omega" / "Plugin.cs").read_text(encoding="utf-8")
        self.assertIn("new PluginIconCache(PluginInterface.ConfigDirectory.FullName)", plugin)

        cache = (common.ROOT / "Omega" / "Services" / "PluginImageCacheStore.cs").read_text(encoding="utf-8")
        self.assertIn('DatabaseFileName = "omega-image-cache.sqlite"', cache)
        self.assertIn("MaximumCacheBytes = 256L * 1024L * 1024L", cache)
        self.assertIn("ORDER BY last_access_utc ASC", cache)

    def test_csharp_workflow_assertions_normalize_line_endings(self) -> None:
        path = common.ROOT / "Omega.RegressionTests" / "RegressionCases.SecurityIntelligence.cs"
        text = path.read_text(encoding="utf-8")
        self.assertIn('var normalized = workflow.ReplaceLineEndings("\\n");', text)
        self.assertIn('var publishStart = normalized.IndexOf("\\n  publish_marketplace:\\n"', text)
        self.assertIn('var ledgerStart = normalized.IndexOf("\\n  publish_evidence:\\n"', text)
        self.assertNotIn('workflow.IndexOf("\\n  publish_marketplace:', text)
        self.assertNotIn('workflow.IndexOf("\\n  publish_evidence:', text)

    def test_plugin_sqlite_runtime_is_self_contained_for_wine(self) -> None:
        project_path = common.ROOT / "Omega" / "DalagabOmega.csproj"
        project_text = project_path.read_text(encoding="utf-8")
        self.assertIn('PackageReference Include="SQLitePCLRaw.bundle_e_sqlite3" Version="2.1.12"', project_text)
        self.assertIn('PackageReference Include="SQLitePCLRaw.lib.e_sqlite3" Version="2.1.12" GeneratePathProperty="true"', project_text)
        self.assertIn('CopyOmegaSqliteNativeToPluginDirectory', project_text)
        self.assertIn(r'runtimes\win-x64\native\e_sqlite3.dll', project_text)
        self.assertIn('DestinationFolder="$(TargetDir)"', project_text)
        self.assertNotIn("SQLitePCLRaw.provider.winsqlite3", project_text)

        store = (common.ROOT / "Omega" / "Services" / "SqliteCatalogStore.cs").read_text(encoding="utf-8")
        self.assertIn("SQLitePCL.Batteries_V2.Init();", store)
        self.assertNotIn("SQLite3Provider_winsqlite3", store)

        regressions = (common.ROOT / "Omega.RegressionTests" / "Omega.RegressionTests.csproj").read_text(encoding="utf-8")
        self.assertIn('PackageReference Include="SQLitePCLRaw.bundle_e_sqlite3" Version="2.1.12"', regressions)
        self.assertNotIn("SQLitePCLRaw.provider.winsqlite3", regressions)


if __name__ == "__main__":
    unittest.main()

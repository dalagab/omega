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
        self.assertIn('var normalizedWorkflow = workflow.ReplaceLineEndings("\\n");', text)
        self.assertIn('Contains(normalizedWorkflow, "workflows:\\n', text)
        self.assertIn('Omega SQLite catalog builder', text)
        self.assertIn('Contains(workflow, "tools/security/sigmascope_handoff.py"', text)
        self.assertIn(r'ARTIFACT_NAME = \"omega-sqlite-catalog\"', text)
        self.assertIn(r'\"gh\", \"run\", \"download\"', text)
        self.assertNotIn('Contains(workflow, "--name omega-sqlite-catalog"', text)
        self.assertNotIn('workflow.IndexOf("\\n  publish_marketplace:', text)
        self.assertNotIn('workflow.IndexOf("\\n  publish_evidence:', text)

    def test_spotlight_shelf_regression_uses_declared_source_binding(self) -> None:
        path = common.ROOT / "Omega.RegressionTests" / "RegressionCases.CollectionsAndSpotlight.cs"
        text = path.read_text(encoding="utf-8")
        self.assertIn('var shelves = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.SpotlightShelves.cs"));', text)
        self.assertIn('Contains(shelves, "layout.Columns", "Spotlight cards wrap instead of overflowing at high UI scale");', text)
        self.assertNotIn('Contains(spotlightShelves, "layout.Columns"', text)

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



    def test_online_definitions_client_accepts_sigmascope_evidence_v2_revision(self) -> None:
        client = (common.ROOT / "Omega" / "Services" / "OnlineCatalogClient.cs").read_text(encoding="utf-8")
        regressions = (common.ROOT / "Omega.RegressionTests" / "RegressionCases.OnlineAndUi.cs").read_text(encoding="utf-8")
        self.assertIn('value.StartsWith("ev-v1", StringComparison.Ordinal)', client)
        self.assertIn('value.StartsWith("ev-v2", StringComparison.Ordinal)', client)
        self.assertIn('IsValidEvidenceRevision("ev-v2-0123456789abcdef")', regressions)
        self.assertIn('IsValidEvidenceRevision("ev-v3-0123456789abcdef")', regressions)

    def test_windows_regression_literals_follow_responsive_sigmascope_source(self) -> None:
        catalog = (common.ROOT / "Omega.RegressionTests" / "RegressionCases.Catalog.cs").read_text(encoding="utf-8")
        collections = (common.ROOT / "Omega.RegressionTests" / "RegressionCases.CollectionsAndSpotlight.cs").read_text(encoding="utf-8")
        layout = (common.ROOT / "Omega.RegressionTests" / "RegressionCases.Layout.cs").read_text(encoding="utf-8")
        install = (common.ROOT / "Omega.RegressionTests" / "RegressionCases.InstallAndDistribution.cs").read_text(encoding="utf-8")
        security = (common.ROOT / "Omega.RegressionTests" / "RegressionCases.SecurityIntelligence.cs").read_text(encoding="utf-8")
        navigation = (common.ROOT / "Omega.RegressionTests" / "RegressionCases.PluginNavigationLifecycle.cs").read_text(encoding="utf-8")
        library_sigmascope = (common.ROOT / "Omega" / "UI" / "MarketplaceWindow.LibrarySigmascope.cs").read_text(encoding="utf-8")

        self.assertIn('contentStartY + Ui(166f)', catalog)
        self.assertIn('contentStartY + Ui(178f)', collections)
        self.assertIn('var panelWidth = Math.Max(Ui(1f), ImGui.GetContentRegionAvail().X)', layout)
        self.assertIn('var rowHeight = Ui(MarketplaceLayoutRules.UpdatesRowHeight)', collections)
        self.assertIn('style.ScrollbarSize + Ui(4f)', collections)
        self.assertIn('ImGuiStyleVar.FrameRounding, Ui(4f)', install)
        self.assertIn('ImGuiStyleVar.ChildRounding, Ui(4f)', install)
        self.assertIn('if (expandedWindowSize.Y > Ui(96f))', install)
        self.assertIn('expandedWindowSize = preferredPhysical;', install)
        self.assertIn('MinimumSize = DefaultExpandedWindowSize', install)
        self.assertIn('production-sigmascope-v2-report.json', security)
        self.assertIn('cardMax - Ui(0.5f, 0.5f)', navigation)
        self.assertIn('Sigmascope evidence shared by', library_sigmascope)
        self.assertIn('ImGui.Dummy(Ui(0f, 6f))', collections)
        self.assertIn('CalculateInlineFilterPanelHeight()', install)
        self.assertIn('ResponsiveColumns(available, 230f, 3, 12f)', install)
        self.assertIn('gridRows * frame * 2.15f', install)
        self.assertIn('var leftInset = Ui(12f)', security)
        self.assertIn('rowMax - Ui(0.5f, 0.5f)', navigation)

        self.assertNotIn('contentStartY + 166f', catalog)
        self.assertNotIn('contentStartY + 178f', collections)
        self.assertNotIn('style.ScrollbarSize + 4f', collections)
        self.assertNotIn('production-security-v2-report.json', security)
        self.assertNotIn('cardMax - new Vector2(0.5f, 0.5f)', navigation)
        self.assertNotIn('ImGui.Dummy(new Vector2(0f, 6f))', collections)
        self.assertNotIn('ImGuiStyleVar.ChildRounding, 4f', install)
        self.assertNotIn('if (expandedWindowSize.Y > 96f)', install)
        self.assertNotIn('expandedWindowSize = DefaultExpandedWindowSize;', install)
        self.assertNotIn('Math.Max(minimum, scaled)', install)
        self.assertNotIn('const float leftInset = 12f', security)
        self.assertNotIn('rowMax - new Vector2(0.5f, 0.5f)', navigation)


    def test_definitions_database_size_is_cached_with_loaded_snapshot(self) -> None:
        service = (common.ROOT / "Omega" / "Services" / "MarketplaceCatalogService.cs").read_text(encoding="utf-8")
        refresh = (common.ROOT / "Omega" / "Services" / "MarketplaceCatalogService.Refresh.cs").read_text(encoding="utf-8")
        store = (common.ROOT / "Omega" / "Services" / "SqliteCatalogStore.cs").read_text(encoding="utf-8")
        self.assertIn("public long DatabaseSizeBytes { get; private set; }", service)
        self.assertIn("DatabaseSizeBytes = store.DatabaseSizeBytes", refresh)
        self.assertIn("new FileInfo(DatabasePath).Length", store)


if __name__ == "__main__":
    unittest.main()

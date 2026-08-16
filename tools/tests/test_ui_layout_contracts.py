import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class UiLayoutContractTests(unittest.TestCase):
    def test_shared_layout_rules_guard_row_geometry(self):
        rules = (ROOT / "Omega" / "UI" / "MarketplaceLayoutRules.cs").read_text(encoding="utf-8")
        self.assertIn("LibraryRowHeight = 88f", rules)
        self.assertIn("CollectionRowHeight = 88f", rules)
        self.assertIn("ControlCornerRadius = 6f", rules)
        self.assertIn("ProductCollectionRowHeight = 36f", rules)
        self.assertIn("ProductCollectionImpactLineHeight = 21f", rules)
        self.assertIn("InstallSourceRowHeight = 98f", rules)
        self.assertIn("CenterY", rules)
        self.assertIn("FitsTextLines", rules)

    def test_library_uses_aligned_rows_and_switch_state_control(self):
        source = (ROOT / "Omega" / "UI" / "MarketplaceWindow.Library.cs").read_text(encoding="utf-8")
        self.assertIn("MarketplaceLayoutRules.CenterY", source)
        self.assertIn("DrawToggleSwitch", source)
        self.assertIn("GetPluginDirectControlState", source)
        self.assertIn("DrawRoundedButton", source)
        self.assertNotIn("DrawPillButton(\n                canOpen ? \"Open\"", source)

    def test_collection_rows_do_not_regress_to_short_capsule_layout(self):
        source = (ROOT / "Omega" / "UI" / "MarketplaceWindow.Collections.cs").read_text(encoding="utf-8")
        self.assertIn("MarketplaceLayoutRules.CollectionRowHeight", source)
        self.assertIn("DrawToggleSwitch", source)
        self.assertIn("DrawRoundedButton", source)
        self.assertNotIn("const float rowHeight = 76f", source)
        self.assertNotIn("entry.WantsEnabled ? \"Enabled\" : \"Disabled\",\n                $\"collection-plugin-state", source)

    def test_discover_collection_management_is_compact_expandable_and_actionable(self):
        source = (ROOT / "Omega" / "UI" / "MarketplaceWindow.ProductPage.cs").read_text(encoding="utf-8")
        self.assertIn("Managed by collection", source)
        self.assertNotIn("Direct toggle unavailable", source)
        self.assertNotIn("ImGui.TextWrapped(control.Reason)", source)
        self.assertIn("FontAwesomeIcon.CaretRight", source)
        self.assertIn("FontAwesomeIcon.CaretDown", source)
        self.assertIn("StartCollectionToggle(collection, !collection.IsEnabled)", source)
        self.assertIn("collection.Plugins", source)
        self.assertIn("OpenCollectionView(collection)", source)

    def test_product_packages_stay_collapsed_and_use_metadata_channel_cues(self):
        source = (ROOT / "Omega" / "UI" / "MarketplaceWindow.SourcePackages.cs").read_text(encoding="utf-8")
        self.assertNotIn("ImGuiTreeNodeFlags.DefaultOpen", source)
        self.assertNotIn("Packages {packages.Count}  •  Repository manifests {manifestCount}", source)
        self.assertIn("API: {package.ApiLevel}", source)
        self.assertIn("FontAwesomeIcon.Flask", source)
        self.assertIn("headerMax.X - glyphSize.X - 10f", source)
        self.assertIn("package.IsTestingOnly", source)
        self.assertIn("0.23f, 0.20f, 0.07f", source)
        self.assertIn("else if (preferredInstall)", source)
        self.assertIn("0.07f, 0.24f, 0.13f", source)
        self.assertIn("0.08f, 0.09f, 0.11f", source)
        self.assertNotIn("package.Channels", source)


    def test_dependency_view_is_always_visible_on_product_page(self):
        dependencies = (ROOT / "Omega" / "UI" / "MarketplaceWindow.Dependencies.cs").read_text(encoding="utf-8")
        product_page = (ROOT / "Omega" / "UI" / "MarketplaceWindow.ProductPage.cs").read_text(encoding="utf-8")
        self.assertIn("DrawDependencyEmptyState", dependencies)
        self.assertIn("No external plugin or IPC dependencies were detected for this package.", dependencies)
        self.assertIn("IsDisplayablePluginDependency", dependencies)
        self.assertIn("dependency.IsFramework", dependencies)
        self.assertNotIn("Provided by framework", dependencies)
        self.assertNotIn("Bundled / observed", dependencies)
        self.assertNotIn(
            "if (!plugin.HasCompletedSecurityScan || plugin.SecurityDependencyTotalCount <= 0 || plugin.SecurityDependencies.Count == 0)",
            dependencies,
        )
        self.assertLess(
            product_page.index("DrawProductDependencies(plugin, installed)"),
            product_page.index("DrawProductSourcePackages(plugin, currentApi, currentDalamudVersion)"),
        )

    def test_repository_chooser_selection_and_provider_presentation_contract(self):
        install = (ROOT / "Omega" / "UI" / "MarketplaceWindow.Install.cs").read_text(encoding="utf-8")
        providers = (ROOT / "Omega" / "Services" / "RepositoryProviderRules.cs").read_text(encoding="utf-8")
        presentation = (ROOT / "Omega" / "UI" / "MarketplaceWindow.RepositoryPresentation.cs").read_text(encoding="utf-8")
        self.assertIn("ImGuiSelectableFlags.DontClosePopups", install)
        self.assertNotIn("DrawInstallProviderFilters", install)
        self.assertIn("MarketplaceLayoutRules.InstallSourceRowHeight", install)
        self.assertIn("DrawInstallRepositoryPresentMarker", install)
        self.assertIn("FontAwesomeIcon.Check", install)
        self.assertNotIn('ImGui.Button("Cancel")', install)
        self.assertLess(install.index('ImGui.Button("Install"'), install.index("foreach (var candidate in candidates)"))
        self.assertIn("RepositoryProviderKind.Dalamud", providers)
        self.assertIn("RepositoryProviderKind.PuniSh", providers)
        self.assertIn("RepositoryProviderKind.NightmareXiv", providers)
        self.assertIn("RepositoryProviderKind.CombatReborn", providers)
        self.assertIn("RepositoryProviderKind.LargeRepository", providers)
        self.assertIn("RepositoryProviderKind.Other", providers)
        self.assertIn("DalamudIconUrl", providers)
        self.assertIn("PuniShIconUrl", providers)
        self.assertIn("NightmareXivIconUrl", providers)
        self.assertIn("CombatRebornIconUrl", providers)
        self.assertNotIn('"Large list"', presentation)
        self.assertIn("DrawRepositoryName", presentation)

    def test_discover_installed_check_overlays_artwork_without_shifting_layout(self):
        source = (ROOT / "Omega" / "UI" / "MarketplaceWindow.Discover.cs").read_text(encoding="utf-8")
        self.assertIn("DrawDiscoverInstalledMarker(artworkMin", source)
        self.assertIn("Installed state is an artwork overlay, never part of row/card geometry", source)
        self.assertIn("ImGui.SetCursorPos(new Vector2(12f, 12f))", source)
        self.assertIn("ImGui.SetCursorPos(new Vector2(12f, 18f))", source)
        self.assertNotIn("installed ? 44f : 12f", source)
        self.assertNotIn("var artworkX = installed ?", source)

    def test_spotlight_security_matches_product_page_package_and_keeps_automation_separate(self):
        spotlight = (ROOT / "Omega" / "UI" / "MarketplaceWindow.Spotlight.cs").read_text(encoding="utf-8")
        shelves = (ROOT / "Omega" / "UI" / "MarketplaceWindow.SpotlightShelves.cs").read_text(encoding="utf-8")
        discover = (ROOT / "Omega" / "UI" / "MarketplaceWindow.Discover.cs").read_text(encoding="utf-8")
        security = (ROOT / "Omega" / "UI" / "MarketplaceWindow.PluginSecurity.cs").read_text(encoding="utf-8")
        artwork = (ROOT / "Omega" / "UI" / "MarketplaceWindow.Artwork.cs").read_text(encoding="utf-8")
        self.assertIn("=> ResolveDefaultVariant(plugin)", spotlight)
        self.assertIn("DrawPluginScanAndAutomationIndicators", spotlight)
        self.assertIn("DrawPluginScanAndAutomationIndicators", shelves)
        self.assertIn("DrawPluginSecurityScanIndicator", discover)
        self.assertIn("Automation is deliberately separate from scan severity", discover)
        self.assertIn("ResolvePluginSecurityVisual", security)
        self.assertIn("DrawProductSecuritySummary", security)
        self.assertIn("selectedPlugin = ResolveDefaultVariant(plugin)", artwork)
        self.assertNotIn(".Concat(catalog.GetPresentationVariants(plugin.InternalName))", discover)



if __name__ == "__main__":
    unittest.main()

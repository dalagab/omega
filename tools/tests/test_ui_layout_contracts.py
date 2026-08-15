import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class UiLayoutContractTests(unittest.TestCase):
    def test_shared_layout_rules_guard_row_geometry(self):
        rules = (ROOT / "Omega" / "UI" / "MarketplaceLayoutRules.cs").read_text(encoding="utf-8")
        self.assertIn("LibraryRowHeight = 88f", rules)
        self.assertIn("CollectionRowHeight = 88f", rules)
        self.assertIn("ControlCornerRadius = 6f", rules)
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

    def test_discover_explains_collection_managed_state_and_navigates(self):
        source = (ROOT / "Omega" / "UI" / "MarketplaceWindow.ProductPage.cs").read_text(encoding="utf-8")
        self.assertIn("Direct toggle unavailable", source)
        self.assertIn("OpenCollectionView(membership.Collection)", source)
        self.assertIn("CountProductCollectionChipRows", source)
        self.assertIn("DrawToggleSwitch", source)


if __name__ == "__main__":
    unittest.main()

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


if __name__ == "__main__":
    unittest.main()

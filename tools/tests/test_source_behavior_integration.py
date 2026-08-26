from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "tools" / "catalog"
if str(CATALOG) not in sys.path:
    sys.path.insert(0, str(CATALOG))

import sigmascope


PROJECT = b"""<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><AssemblyName>Buyer</AssemblyName></PropertyGroup></Project>"""
SOURCE = b"""
public sealed class Buyer {
    public async Task Run() {
        var prices = await httpClient.GetStringAsync(\"https://universalis.app/api/v2/Europe/5333\");
        marketBoard.Purchase(prices);
    }
}
"""


class SourceBehaviorProductionIntegrationTests(unittest.TestCase):
    def test_selected_source_scope_collects_source_behavior(self) -> None:
        files = {"Buyer.csproj": PROJECT, "Buyer.cs": SOURCE}
        entries = {name: len(data) for name, data in files.items()}
        intel, scope, _files_scanned, _manifest, _profile = sigmascope._inspect_source_tree(
            entries, lambda path: files[path], defaultdict(list), "Buyer", "Buyer", "1.0.0", analyze=True
        )
        self.assertEqual("Buyer.csproj", scope.get("primaryProject"))
        behavior = intel.get("sourceBehavior") or {}
        self.assertEqual(1, behavior.get("contractVersion"))
        operations = behavior.get("operations") or []
        self.assertTrue(any(row.get("operation") == "network.http.request" for row in operations))
        self.assertTrue(any(row.get("operation") == "game.marketboard.purchase" for row in operations))
        self.assertTrue(any(row.get("serviceId") == "ffxiv.universalis" for row in operations))

    def test_candidate_resolution_does_not_claim_complete_behavior_analysis(self) -> None:
        files = {"Buyer.csproj": PROJECT, "Buyer.cs": SOURCE}
        entries = {name: len(data) for name, data in files.items()}
        intel, _scope, _files_scanned, _manifest, _profile = sigmascope._inspect_source_tree(
            entries, lambda path: files[path], defaultdict(list), "Buyer", "Buyer", "1.0.0", analyze=False
        )
        self.assertEqual({}, intel.get("sourceBehavior"))

    def test_unrelated_monorepo_project_does_not_contribute_behavior(self) -> None:
        other_project = b"""<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><AssemblyName>Other</AssemblyName></PropertyGroup></Project>"""
        other_source = b"""public sealed class Other { public void Run() { marketBoard.Sell(item); } }"""
        files = {
            "Buyer.csproj": PROJECT, "Buyer.cs": SOURCE,
            "Other/Other.csproj": other_project, "Other/Other.cs": other_source,
        }
        entries = {name: len(data) for name, data in files.items()}
        intel, scope, _files_scanned, _manifest, _profile = sigmascope._inspect_source_tree(
            entries, lambda path: files[path], defaultdict(list), "Buyer", "Buyer", "1.0.0", analyze=True
        )
        self.assertEqual("Buyer.csproj", scope.get("primaryProject"))
        self.assertGreaterEqual(int(scope.get("excludedSourceFiles") or 0), 1)
        operations = intel["sourceBehavior"]["operations"]
        self.assertTrue(any(row.get("operation") == "game.marketboard.purchase" for row in operations))
        self.assertFalse(any(row.get("operation") == "game.marketboard.sell" for row in operations))



if __name__ == "__main__":
    unittest.main()

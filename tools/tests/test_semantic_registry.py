from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "catalog"))

import semantic_registry


class SemanticRegistryTests(unittest.TestCase):
    def test_universalis_is_data_not_scanner_code(self):
        item = semantic_registry.service_for_host("universalis.app")
        self.assertEqual("ffxiv.universalis", item["serviceId"])
        self.assertIn("ffxiv.market-data", item["serviceCapabilities"])
        self.assertEqual("established", item["serviceRecognition"])
        self.assertTrue(item["serviceRegistryRevision"].startswith("services-v1-"))

    def test_unknown_hosts_get_stable_identity_without_safety_claim(self):
        item = semantic_registry.service_for_host("api.plugin-example.invalid")
        self.assertEqual("host:api.plugin-example.invalid", item["serviceId"])
        self.assertEqual("unknown", item["serviceRecognition"])
        self.assertEqual([], item["serviceCapabilities"])

    def test_source_api_matching_is_registry_driven(self):
        item = semantic_registry.match_source_call("navmesh", "PathfindAndMoveTo")
        self.assertEqual("game.character.move", item["operation"])
        self.assertTrue(item["semanticApiRegistryRevision"].startswith("semantic-apis-v1-"))
        purchase = semantic_registry.match_source_call("marketBoard", "Purchase")
        self.assertEqual("game.marketboard.purchase", purchase["operation"])


if __name__ == "__main__":
    unittest.main()

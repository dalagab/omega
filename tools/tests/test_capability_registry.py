from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import common
import capability_registry


class CapabilityRegistryTests(unittest.TestCase):
    def test_registry_is_valid_and_aliases_normalize(self) -> None:
        registry = capability_registry.load_registry()
        self.assertEqual("omega.sigmascope.capability-registry.v1", registry["schema"])
        self.assertGreaterEqual(len(registry["capabilities"]), 30)
        self.assertTrue(str(registry["revision"]).startswith("capabilities-v1-"))
        self.assertEqual("process.execute", capability_registry.normalize_capability_id("process.launch", registry))
        self.assertEqual("process.execute", capability_registry.normalize_capability_id("Process execution", registry))
        self.assertEqual("privacy.clipboard", capability_registry.normalize_capability_id("clipboard", registry))

    def test_legacy_adapter_combines_labels_permissions_and_automation(self) -> None:
        registry = capability_registry.load_registry()
        result = capability_registry.legacy_capability_ids(
            ["Network access", "Process execution"],
            [{"permissionId": "game.state.read"}],
            [{"capabilityId": "game.character.move"}],
            registry,
        )
        self.assertEqual(
            ["game.character.move", "game.state.read", "network.http", "process.execute"],
            result,
        )

    def test_duplicate_alias_is_rejected(self) -> None:
        registry = capability_registry.load_registry()
        doc = {key: value for key, value in registry.items() if key not in {"revision", "path"}}
        doc = json.loads(json.dumps(doc))
        doc["capabilities"][1]["aliases"].append(doc["capabilities"][0]["label"])
        with self.assertRaisesRegex(ValueError, "collision"):
            capability_registry.validate_registry(doc)


if __name__ == "__main__":
    unittest.main()

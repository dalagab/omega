from __future__ import annotations

import unittest

import common
import component_registry
import execution_topology


class ExecutionTopologyTests(unittest.TestCase):
    def test_topology_is_descriptive_read_only_and_component_bound(self) -> None:
        payload = execution_topology.build_topology()
        self.assertEqual("omega.execution-topology.v1", payload["schema"])
        self.assertTrue(payload["readOnly"])
        self.assertEqual("none", payload["mutationAuthority"])
        self.assertFalse(payload["policyInput"])
        self.assertFalse(payload["launchAuthority"])
        self.assertEqual(execution_topology.topology_revision(), payload["revision"])
        components = component_registry.component_map()
        self.assertGreaterEqual(payload["nodeCount"], 10)
        self.assertEqual(payload["nodeCount"], len(payload["nodes"]))
        for node in payload["nodes"]:
            self.assertIn(node["componentId"], components)
            self.assertTrue(node["workflow"].endswith((".yml", ".yaml")))
            self.assertTrue(node["step"])

    def test_topology_contains_current_scanner_and_discovery_execution_nodes(self) -> None:
        nodes = execution_topology.node_map()
        self.assertEqual("omega.discovery", nodes["source-discovery"]["componentId"])
        self.assertEqual("catalog-discovery.yml", nodes["source-discovery"]["workflow"])
        self.assertEqual("omega.sigmascope", nodes["sigmascope-batch"]["componentId"])
        self.assertEqual("sigmascope.yml", nodes["sigmascope-batch"]["workflow"])
        self.assertEqual("omega.sigmascope", nodes["sigmascope-authenticode"]["componentId"])
        self.assertEqual(["binarySignatureTrust"], nodes["sigmascope-authenticode"]["provides"])
        self.assertIn("Windows", nodes["sigmascope-authenticode"]["title"])
        self.assertEqual(["elfBinaryStructure", "machOBinaryStructure"], nodes["sigmascope-native-structure"]["provides"])
        self.assertIn("ELF", nodes["sigmascope-native-structure"]["title"])


if __name__ == "__main__":
    unittest.main()

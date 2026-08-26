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
        self.assertEqual("catalog-discovery-worker.yml", nodes["source-discovery"]["workflow"])
        self.assertEqual("omega.sigmascope", nodes["sigmascope-batch"]["componentId"])
        self.assertEqual("sigmascope.yml", nodes["sigmascope-batch"]["workflow"])
        self.assertEqual("sigmascope-parallel-worker.yml", nodes["sigmascope-parallel-result-worker"]["workflow"])
        self.assertEqual("omega.sigmascope", nodes["sigmascope-parallel-result-worker"]["componentId"])
        self.assertEqual("sigmascope-parallel-shadow.yml", nodes["sigmascope-parallel-merge-plan"]["workflow"])
        self.assertEqual("omega.evidence-v2", nodes["sigmascope-parallel-merge-plan"]["componentId"])
        self.assertIn("shadow", nodes["sigmascope-parallel-merge-plan"]["cadenceMode"])
        self.assertEqual("sigmascope-parallel-shadow.yml", nodes["sigmascope-parallel-candidate-merger"]["workflow"])
        self.assertEqual("omega.evidence-v2", nodes["sigmascope-parallel-candidate-merger"]["componentId"])
        self.assertIn("zero publication authority", nodes["sigmascope-parallel-candidate-merger"]["purpose"])
        self.assertEqual("sigmascope-parallel-shadow.yml", nodes["sigmascope-parallel-equivalence-preflight"]["workflow"])
        self.assertIn("cannot publish Evidence-v2", nodes["sigmascope-parallel-equivalence-preflight"]["purpose"])
        self.assertEqual("sigmascope-parallel-publish.yml", nodes["sigmascope-parallel-one-writer-publisher"]["workflow"])
        self.assertEqual("omega.evidence-v2", nodes["sigmascope-parallel-one-writer-publisher"]["componentId"])
        self.assertIn("Evidence-v2 before publishing Deep Scan", nodes["sigmascope-parallel-one-writer-publisher"]["purpose"])
        self.assertEqual("omega.sigmascope", nodes["sigmascope-authenticode"]["componentId"])
        self.assertEqual(["binarySignatureTrust"], nodes["sigmascope-authenticode"]["provides"])
        self.assertIn("Windows", nodes["sigmascope-authenticode"]["title"])
        self.assertEqual(["elfBinaryStructure", "machOBinaryStructure"], nodes["sigmascope-native-structure"]["provides"])
        self.assertIn("ELF", nodes["sigmascope-native-structure"]["title"])
        self.assertEqual("catalog-enrichment-worker.yml", nodes["manifest-normalization"]["workflow"])
        self.assertEqual("catalog-scrape-worker.yml", nodes["website-enrichment"]["workflow"])
        self.assertEqual("source-head-worker.yml", nodes["source-revision-observer"]["workflow"])
        self.assertEqual("threat-intelligence-worker.yml", nodes["threat-intelligence"]["workflow"])
        self.assertEqual("osv-worker.yml", nodes["advisory-collector"]["workflow"])
        self.assertEqual("secondary-security-worker.yml", nodes["secondary-security-definitions"]["workflow"])
        self.assertEqual("security-reconcile.yml", nodes["security-work-reconciler"]["workflow"])
        self.assertEqual("catalog-freeze.yml", nodes["catalog-freeze"]["workflow"])
        self.assertEqual("manual", nodes["catalog-freeze"]["cadenceMode"])


if __name__ == "__main__":
    unittest.main()

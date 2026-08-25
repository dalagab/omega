from __future__ import annotations

import unittest

import common
import deltascope_collectors
import deltascope_operations


class DeltaScopePlatformRegistryTests(unittest.TestCase):
    def test_component_registry_adds_future_components_without_code_mapping(self) -> None:
        operations = {
            "schema": deltascope_operations.SCHEMA, "available": True, "components": [],
            "events": [{
                "workflowPath": ".github/workflows/future-worker.yml", "workflow": "future-worker.yml",
                "state": "healthy", "stateDetail": "success", "title": "future run", "runNumber": 7,
            }],
        }
        registry = {
            "schema": "omega.component-registry.v1", "revision": "component-registry-v1-test",
            "components": [{
                "id": "omega.future", "name": "Future Analyzer", "type": "analysis-service", "status": "active",
                "executionClass": "future-analysis",
                "launch": {"mode": "reusable-workflow", "available": True, "workflow": ".github/workflows/future-worker.yml"},
            }],
        }
        result = deltascope_operations.merge_component_registry(operations, registry)
        self.assertTrue(result["componentRegistryAvailable"])
        self.assertEqual("component-registry-v1-test", result["componentRegistryRevision"])
        row = next(item for item in result["components"] if item["componentId"] == "omega.future")
        self.assertEqual("Future Analyzer", row["component"])
        self.assertEqual("healthy", row["state"])
        self.assertTrue(row["registryDriven"])

    def test_collector_registry_projects_new_provider_generically(self) -> None:
        registry = {
            "schema": "omega.collector-registry.v1", "revision": "collector-registry-v1-test",
            "components": {"omega.future": {"name": "Future Analyzer"}},
            "collectors": [{
                "id": "omega.collector.future", "componentId": "omega.future", "title": "Future provider",
                "status": "planned", "cadence": "on-demand", "authority": "observation-only", "network": False,
                "provides": ["futureObservation"],
            }],
        }
        result = deltascope_collectors.project_collectors({}, {}, {}, platform_registry=registry)
        self.assertEqual(1, result["registeredProviderCount"])
        provider = result["registeredProviders"][0]
        self.assertEqual("omega.collector.future", provider["id"])
        self.assertEqual("Future Analyzer", provider["component"])
        self.assertEqual(["futureObservation"], provider["provides"])

    def test_execution_topology_adds_future_runner_node_without_deltascope_mapping(self) -> None:
        topology = {
            "schema": "omega.execution-topology.v1", "revision": "execution-topology-v1-future",
            "nodes": [{
                "id": "future-analysis", "title": "Future analysis", "componentId": "omega.future",
                "workflow": "future-worker.yml", "job": "Future worker", "step": "Run future analysis",
                "purpose": "Future platform work", "inputs": ["request"], "outputs": ["observation"],
                "implementation": "external/future", "cadenceMode": "event-driven",
            }],
        }
        histories = {
            "future-worker.yml": {"available": True, "runs": [{
                "runId": 9, "runNumber": 9, "createdAtUtc": "2026-08-25T10:00:00Z", "updatedAtUtc": "2026-08-25T10:01:00Z",
                "jobs": [{
                    "name": "Future worker", "status": "completed", "conclusion": "success",
                    "steps": [{"name": "Run future analysis", "status": "completed", "conclusion": "success"}],
                }],
            }]},
        }
        result = deltascope_collectors.project_collectors(histories, {"counts": {}}, {}, execution_topology=topology)
        self.assertEqual("execution-topology-v1-future", result["executionTopologyRevision"])
        self.assertEqual(1, result["collectorCount"])
        row = result["collectors"][0]
        self.assertEqual("future-analysis", row["id"])
        self.assertEqual("healthy", row["state"])
        self.assertEqual("omega.future", row["componentId"])



if __name__ == "__main__":
    unittest.main()

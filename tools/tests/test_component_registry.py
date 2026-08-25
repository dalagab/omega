from __future__ import annotations
import unittest

import common  # noqa: F401
import component_registry


class ComponentRegistryTests(unittest.TestCase):
    def test_registry_distinguishes_components_from_collectors(self) -> None:
        registry = component_registry.build_registry()
        self.assertEqual("omega.component-registry.v1", registry["schema"])
        self.assertIn("omega.sigmascope", registry["byId"])
        self.assertIn("omega.analysis-dispatcher", registry["byId"])
        self.assertIn("omega.discovery", registry["byId"])
        self.assertIn("omega.rift", registry["byId"])
        self.assertIn("omega.rebuilder", registry["byId"])
        self.assertIn("omega.threat-intelligence", registry["byId"])
        self.assertTrue(registry["policy"]["mainOwnsWorkflowLaunch"])
        self.assertFalse(registry["policy"]["rulesMayDispatch"])

    def test_only_active_reusable_workflows_are_dispatchable(self) -> None:
        self.assertTrue(component_registry.is_launchable("omega.sigmascope"))
        self.assertTrue(component_registry.is_dispatchable("omega.sigmascope"))
        self.assertEqual(1, component_registry.dispatch_contract("omega.sigmascope")["maxConcurrent"])
        self.assertEqual("generic-analysis-request-v1", component_registry.dispatch_contract("omega.sigmascope")["requestMode"])
        self.assertFalse(component_registry.is_launchable("omega.analysis-dispatcher"))
        self.assertFalse(component_registry.is_dispatchable("omega.analysis-dispatcher"))
        self.assertTrue(component_registry.is_launchable("omega.discovery"))
        self.assertTrue(component_registry.is_dispatchable("omega.discovery"))
        self.assertEqual(1, component_registry.dispatch_contract("omega.discovery")["maxConcurrent"])
        self.assertFalse(component_registry.is_dispatchable("omega.rift"))
        self.assertFalse(component_registry.is_dispatchable("omega.rebuilder"))
        self.assertFalse(component_registry.is_dispatchable("omega.threat-intelligence"))
        rift = component_registry.dispatch_contract("omega.rift")
        self.assertEqual("external", rift["status"])
        self.assertEqual("external-contract", rift["launchMode"])

    def test_registry_revision_is_stable_and_content_addressed(self) -> None:
        first = component_registry.component_revision()
        second = component_registry.component_revision()
        self.assertEqual(first, second)
        self.assertRegex(first, r"^component-registry-v1-[0-9a-f]{20}$")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest

import common  # noqa: F401
import security_scan


class SecurityAutomationTests(unittest.TestCase):
    def test_reachable_action_execution_is_full_gameplay_automation(self) -> None:
        intel = security_scan.empty_dependency_intelligence("fixture")
        intel["managedCallSites"] = [{
            "sourceMethodToken": "0x06000001",
            "targetDeclaringType": "FFXIVClientStructs.FFXIV.Client.Game.ActionManager",
            "targetName": "UseAction",
            "targetNativeEntryPoint": "",
            "evidence": ["ActionManager.UseAction"],
        }]
        intel["managedReachability"] = [{"methodToken": "0x06000001"}]
        result = security_scan.derive_automation_capabilities(intel)
        self.assertEqual("full-gameplay-automation", result["level"])
        cap = next(x for x in result["capabilities"] if x["capabilityId"] == "game.character.execute_action")
        self.assertTrue(cap["reachable"])
        self.assertEqual("very-high", cap["confidence"])
        self.assertFalse(cap["indirect"])

    def test_ui_callback_is_classified_as_ui_automation(self) -> None:
        intel = security_scan.empty_dependency_intelligence("fixture")
        intel["managedCallSites"] = [{
            "sourceMethodToken": "0x06000002",
            "targetDeclaringType": "FFXIVClientStructs.FFXIV.Component.GUI.AtkUnitBase",
            "targetName": "FireCallback",
            "targetNativeEntryPoint": "",
            "evidence": ["AtkUnitBase.FireCallback"],
        }]
        result = security_scan.derive_automation_capabilities(intel)
        self.assertEqual("ui-automation", result["level"])
        self.assertTrue(any(x["capabilityId"] == "game.ui.callback" for x in result["capabilities"]))

    def test_navigation_ipc_is_indirect_character_control(self) -> None:
        intel = security_scan.empty_dependency_intelligence("fixture")
        intel["ipcIntegrations"] = [{"channel": "vnavmesh.Path.MoveTo", "origin": "artifact", "path": "Plugin.dll"}]
        result = security_scan.derive_automation_capabilities(intel)
        self.assertEqual("full-gameplay-automation", result["level"])
        cap = next(x for x in result["capabilities"] if x["capabilityId"] == "game.character.move")
        self.assertTrue(cap["indirect"])
        self.assertEqual("medium", cap["confidence"])
        self.assertFalse(cap["reachable"])

    def test_observation_only_does_not_claim_control(self) -> None:
        intel = security_scan.empty_dependency_intelligence("fixture")
        intel["dalamudServices"] = [{"service": "IClientState", "origin": "artifact", "path": "Plugin.cs"}]
        result = security_scan.derive_automation_capabilities(intel)
        self.assertEqual("observational", result["level"])
        self.assertEqual([], result["capabilities"])
        self.assertEqual([], result["findings"])


if __name__ == "__main__":
    unittest.main()

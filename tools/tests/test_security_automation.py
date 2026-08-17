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

    def test_ipc_provider_is_not_misclassified_as_consumed_automation(self) -> None:
        intel = security_scan.empty_dependency_intelligence("fixture")
        intel["ipcIntegrations"] = [{
            "channel": "vnavmesh.Path.MoveTo", "role": "provider", "origin": "source", "path": "Provider.cs"
        }]
        result = security_scan.derive_automation_capabilities(intel)
        self.assertEqual("none", result["level"])
        self.assertEqual([], result["capabilities"])
        self.assertEqual([], result["findings"])

    def test_navigation_ipc_is_indirect_character_control(self) -> None:
        intel = security_scan.empty_dependency_intelligence("fixture")
        intel["ipcIntegrations"] = [{"channel": "vnavmesh.Path.MoveTo", "origin": "artifact", "path": "Plugin.dll"}]
        result = security_scan.derive_automation_capabilities(intel)
        self.assertEqual("full-gameplay-automation", result["level"])
        cap = next(x for x in result["capabilities"] if x["capabilityId"] == "game.character.move")
        self.assertTrue(cap["indirect"])
        self.assertEqual("medium", cap["confidence"])
        self.assertFalse(cap["reachable"])

    def test_ipc_relationship_inference_is_conservative(self) -> None:
        cases = [
            (
                'class Client { void Initialize(dynamic pi) { var gate = pi.GetIpcSubscriber<int>("Omega.Required"); gate.InvokeFunc(); } }',
                "required", "High",
            ),
            (
                'class Client { void Feature(dynamic pi) { var gate = pi.GetIpcSubscriber<int>("Omega.Feature"); if (!gate.IsValid) return; Config.EnableFeature = true; } }',
                "feature", "High",
            ),
            (
                'class Client { void TryConnect(dynamic pi) { var gate = pi.GetIpcSubscriber<int>("Omega.Optional"); if (!gate.IsValid) return; } }',
                "optional", "High",
            ),
            (
                'class Client { void Use(dynamic pi) { var gate = pi.GetIpcSubscriber<int>("Omega.Unknown"); } }',
                "unknown", "Low",
            ),
        ]
        for text, expected_relationship, expected_confidence in cases:
            with self.subTest(expected_relationship=expected_relationship):
                start = text.index("GetIpcSubscriber")
                end = text.index(");", start) + 1
                result = security_scan.infer_ipc_consumer_relationship(text, start, end)
                self.assertEqual(expected_relationship, result["relationship"])
                self.assertEqual(expected_confidence, result["confidence"])
                self.assertTrue(result["evidence"])

    def test_observation_only_does_not_claim_control(self) -> None:
        intel = security_scan.empty_dependency_intelligence("fixture")
        intel["dalamudServices"] = [{"service": "IClientState", "origin": "artifact", "path": "Plugin.cs"}]
        result = security_scan.derive_automation_capabilities(intel)
        self.assertEqual("observational", result["level"])
        self.assertEqual([], result["capabilities"])
        self.assertEqual([], result["findings"])


if __name__ == "__main__":
    unittest.main()

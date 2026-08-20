from __future__ import annotations

import unittest

import common  # noqa: F401
import sigmascope
from security_component_summary import build_component_summary


class ComponentSummaryTests(unittest.TestCase):
    def test_component_families_and_native_relationships_are_separate(self) -> None:
        intel = sigmascope.empty_dependency_intelligence("artifact")
        sigmascope.add_dependency(intel, "nuget-lock", "Newtonsoft.Json", "13.0.3", "packages.lock.json", "analyzed", requirement="bundled", resolved_version="13.0.3")
        sigmascope.add_dependency(intel, "native-library", "helper.dll", "", "native/helper.dll", "binary-only", requirement="bundled")
        sigmascope.add_dependency(intel, "external-plugin", "Penumbra", "", "Plugin.cs", "external-plugin", requirement="soft", relationship="optional", relationship_confidence="High")
        intel["nativeImports"].extend([
            {"origin": "artifact", "library": "helper.dll", "path": "Plugin.dll", "entryPoint": "DoThing", "managedName": "DoThing"},
            {"origin": "artifact", "library": "kernel32.dll", "path": "Plugin.dll", "entryPoint": "CreateFileW", "managedName": "CreateFileW"},
            {"origin": "artifact", "library": "vendor_runtime.dll", "path": "Plugin.dll", "entryPoint": "Init", "managedName": "Init"},
        ])
        intel["managedCallSites"].append({
            "origin": "artifact", "path": "Plugin.dll", "sourceMethodToken": "0x06000001", "ilOffset": 0,
            "opcode": "call", "targetToken": "0x06000002", "targetNativeLibrary": "helper.dll",
            "targetNativeEntryPoint": "DoThing",
        })
        summary = build_component_summary(intel)
        self.assertEqual("omega.sigmascope.component-summary.v1", summary["schema"])
        self.assertEqual(1, summary["families"]["nuget"])
        self.assertEqual(1, summary["families"]["native"])
        self.assertEqual(1, summary["families"]["plugin"])
        self.assertEqual(1, summary["nativeRelationshipCounts"]["bundledComponent"])
        self.assertEqual(1, summary["nativeRelationshipCounts"]["platformLibrary"])
        self.assertEqual(1, summary["nativeRelationshipCounts"]["externalOrRuntimeResolved"])
        bundled = next(item for item in summary["nativeRelationships"] if item["library"] == "helper.dll")
        self.assertEqual("bundled-component", bundled["disposition"])
        self.assertEqual("native/helper.dll", bundled["targetPath"])
        self.assertTrue(bundled["directManagedCallObserved"])
        self.assertEqual(1, bundled["directManagedCallCount"])
        self.assertTrue(summary["fingerprint"])

    def test_finalize_intelligence_materializes_component_summary(self) -> None:
        intel = sigmascope.empty_dependency_intelligence("artifact")
        sigmascope.add_dependency(intel, "nuget", "Example.Package", "1.2.3", "Plugin.csproj", "known", resolved_version="1.2.3")
        sigmascope.finalize_intelligence(intel)
        self.assertEqual(1, intel["componentSummary"]["dependencyCount"])
        self.assertEqual(1, intel["componentSummary"]["exactVersionObservedCount"])


if __name__ == "__main__":
    unittest.main()

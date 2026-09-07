from __future__ import annotations

from pathlib import Path
import sys
import unittest

SECURITY = Path(__file__).resolve().parents[1] / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_plugin_dependencies as deps


class FakeInspector:
    def __init__(self, graph=None, *, include_descriptor=True):
        graph = graph if graph is not None else self.empty_graph()
        self.root = {
            "schema": "omega.security-evidence.v2",
            "formatVersion": 2,
            "revisions": {
                "evidenceRevision": "evidence-test",
                "dependencyGraphRevision": graph.get("dependencyGraphRevision", ""),
            },
            "counts": {
                "pluginDependencyEdges": len(graph.get("edges") or []),
                "pluginDependencyProviders": len(graph.get("providers") or []),
            },
            "indexes": {},
        }
        if include_descriptor:
            self.root["indexes"]["pluginDependencies"] = {
                "path": "indexes/plugin-dependencies.json",
                "sha256": "a" * 64,
                "records": len(graph.get("edges") or []),
            }
        self._graph = graph
        self.entries = {
            10: {"summary": {"plugin_id": 1, "internal_name": "Consumer", "canonical_name": "Consumer", "assembly_version": "1.0.0"}},
            20: {"summary": {"plugin_id": 2, "internal_name": "Provider", "canonical_name": "Provider", "assembly_version": "2.0.0"}},
            30: {"summary": {"plugin_id": 3, "internal_name": "Optional.Provider", "canonical_name": "Optional Provider", "assembly_version": "3.0.0"}},
        }
        self.ipc_rows = [{"provider": "Penumbra", "endpoint": "GetCollection"}]
        self.relationships = {
            "components": [{
                "componentKey": "nuget:Example.Package",
                "kind": "nuget",
                "displayName": "Example.Package",
                "versions": ["1.2.3"],
                "usage": [{"variantId": 10, "pluginId": 1, "observedVersion": "1.2.3"}],
            }]
        }

    @staticmethod
    def empty_graph():
        return {
            "schema": deps.GRAPH_SCHEMA,
            "authority": deps.GRAPH_AUTHORITY,
            "dependencyGraphRevision": "plugin-deps-v1-empty",
            "semantics": {
                "securityEvidenceIsObservationOnly": True,
                "ipcIsPackageDependency": False,
                "projectReferencesArePackageDependencies": False,
                "unresolvedPluginRequirementsRetained": True,
                "providerIdentity": "stable-plugin-id",
                "consumerIdentity": "catalog-variant",
            },
            "counts": {"edges": 0, "providers": 0, "requiredEdges": 0, "installEligibleEdges": 0},
            "edges": [],
            "providers": [],
        }

    def _index_payload(self, name):
        if name != "pluginDependencies":
            return {}
        return self._graph

    def _entry_identity(self, variant_id, *, require_current=False):
        del require_current
        row = dict(self.entries[variant_id]["summary"])
        row["variant_id"] = variant_id
        return row

    def plugin_dataset(self, variant_id, name):
        if variant_id != 10 or name != "ipc":
            return []
        return list(self.ipc_rows)

    def workbench_relationship_index(self):
        return self.relationships

    def table_catalog(self):
        return [{"name": "v2_ipc_providers", "label": "IPC", "category": "Global evidence", "columnCount": 1}]

    def _special_table_rows(self, name):
        return [{"legacy": name}]


def nonempty_graph():
    edges = [
        {
            "consumerVariantId": 10, "consumerPluginId": 1, "consumerInternalName": "Consumer",
            "consumerVersion": "1.0.0", "providerPluginId": 2, "providerInternalName": "Provider",
            "relationship": "required", "versionConstraint": ">=2", "resolvedVersion": "2.0.0",
            "resolutionStatus": "resolved", "versionStatus": "compatible", "confidence": "high",
            "sourceKind": "plugin", "origins": ["manifest"], "installEligible": True,
        },
        {
            "consumerVariantId": 10, "consumerPluginId": 1, "consumerInternalName": "Consumer",
            "consumerVersion": "1.0.0", "providerPluginId": 3, "providerInternalName": "Optional.Provider",
            "relationship": "optional", "versionConstraint": "", "resolvedVersion": "3.0.0",
            "resolutionStatus": "resolved", "versionStatus": "compatible", "confidence": "high",
            "sourceKind": "plugin", "origins": ["manifest"], "installEligible": True,
        },
        {
            "consumerVariantId": 20, "consumerPluginId": 2, "consumerInternalName": "Provider",
            "consumerVersion": "2.0.0", "providerPluginId": 1, "providerInternalName": "Consumer",
            "relationship": "recommended", "versionConstraint": "", "resolvedVersion": "1.0.0",
            "resolutionStatus": "resolved", "versionStatus": "compatible", "confidence": "medium",
            "sourceKind": "plugin", "origins": ["manifest"], "installEligible": True,
        },
    ]
    providers = [
        {
            "providerPluginId": 1, "providerInternalName": "Consumer",
            "requiredByCount": 0, "recommendedByCount": 1, "optionalByCount": 0,
            "totalDependentPlugins": 1, "requiredBy": [],
        },
        {
            "providerPluginId": 2, "providerInternalName": "Provider",
            "requiredByCount": 1, "recommendedByCount": 0, "optionalByCount": 0,
            "totalDependentPlugins": 1, "requiredBy": [{"pluginId": 1, "internalName": "Consumer"}],
        },
        {
            "providerPluginId": 3, "providerInternalName": "Optional.Provider",
            "requiredByCount": 0, "recommendedByCount": 0, "optionalByCount": 1,
            "totalDependentPlugins": 1, "requiredBy": [],
        },
    ]
    return {
        "schema": deps.GRAPH_SCHEMA,
        "authority": deps.GRAPH_AUTHORITY,
        "dependencyGraphRevision": "plugin-deps-v1-test",
        "semantics": {
            "securityEvidenceIsObservationOnly": True,
            "ipcIsPackageDependency": False,
            "projectReferencesArePackageDependencies": False,
            "unresolvedPluginRequirementsRetained": True,
            "providerIdentity": "stable-plugin-id",
            "consumerIdentity": "catalog-variant",
        },
        "counts": {
            "edges": len(edges), "providers": len(providers), "requiredEdges": 1,
            "installEligibleEdges": 3,
        },
        "edges": edges,
        "providers": providers,
    }


class DeltaScopePluginDependencyTests(unittest.TestCase):
    def test_valid_empty_graph_is_available_not_unavailable(self):
        inspector = FakeInspector()
        graph = deps.load_plugin_dependency_graph(inspector)
        self.assertTrue(graph["available"])
        self.assertEqual(0, graph["counts"]["edges"])
        result = deps.project_plugin_dependency_context(inspector, 10)
        self.assertTrue(result["graph"]["available"])
        self.assertTrue(result["graph"]["globallyEmpty"])
        self.assertEqual(
            "No normalized plugin dependency relationships are currently published.",
            result["message"],
        )

    def test_absent_graph_is_distinct_from_valid_empty_graph(self):
        inspector = FakeInspector(include_descriptor=False)
        inspector.root["revisions"]["dependencyGraphRevision"] = ""
        result = deps.project_plugin_dependency_context(inspector, 10)
        self.assertFalse(result["graph"]["available"])
        self.assertFalse(result["graph"]["globallyEmpty"])
        self.assertIn("not published", result["message"])

    def test_requires_and_required_by_use_only_normalized_graph_edges(self):
        inspector = FakeInspector(nonempty_graph())
        result = deps.project_plugin_dependency_context(inspector, 10)
        self.assertEqual(["Provider"], [x["providerInternalName"] for x in result["requires"]["required"]])
        self.assertEqual(["Optional.Provider"], [x["providerInternalName"] for x in result["requires"]["optional"]])
        self.assertEqual([], result["requires"]["recommended"])
        self.assertEqual(["Provider"], [x["consumerInternalName"] for x in result["requiredBy"]["recommended"]])
        self.assertEqual([20], result["requires"]["required"][0]["targetVariantIds"])
        self.assertEqual(20, result["requires"]["required"][0]["preferredVariantId"])
        self.assertEqual(20, result["requiredBy"]["recommended"][0]["preferredVariantId"])

    def test_ipc_integration_is_never_reinterpreted_as_requires(self):
        inspector = FakeInspector(nonempty_graph())
        inspector.ipc_rows = [{"provider": "Penumbra", "endpoint": "GetCollection"}]
        result = deps.project_plugin_dependency_context(inspector, 10)
        requires_names = {
            row["providerInternalName"]
            for group in ("required", "recommended", "optional")
            for row in result["requires"][group]
        }
        self.assertNotIn("Penumbra", requires_names)
        self.assertEqual("Penumbra", result["integrations"]["rows"][0]["provider"])
        self.assertFalse(result["integrations"]["ipcIsPackageDependency"])
        self.assertTrue(result["semanticBoundary"]["ipcMayAppearOnlyAsIntegrationWithoutDependencyEdge"])

    def test_components_remain_distinct_from_plugin_requirements(self):
        inspector = FakeInspector(nonempty_graph())
        result = deps.project_plugin_dependency_context(inspector, 10)
        self.assertEqual("Example.Package", result["components"]["rows"][0]["displayName"])
        self.assertTrue(result["semanticBoundary"]["componentObservationIsNotPluginRequirement"])
        self.assertNotIn(
            "Example.Package",
            {row["providerInternalName"] for row in result["requires"]["required"]},
        )

    def test_graph_revision_mismatch_fails_closed(self):
        inspector = FakeInspector(nonempty_graph())
        inspector.root["revisions"]["dependencyGraphRevision"] = "different"
        with self.assertRaisesRegex(ValueError, "revision does not match"):
            deps.load_plugin_dependency_graph(inspector)

    def test_ipc_package_dependency_semantics_cannot_flip_true(self):
        graph = nonempty_graph()
        graph["semantics"]["ipcIsPackageDependency"] = True
        inspector = FakeInspector(graph)
        with self.assertRaisesRegex(ValueError, "ipcIsPackageDependency=false"):
            deps.load_plugin_dependency_graph(inspector)

    def test_root_and_payload_counts_are_validated(self):
        inspector = FakeInspector(nonempty_graph())
        inspector.root["counts"]["pluginDependencyEdges"] = 99
        with self.assertRaisesRegex(ValueError, "pluginDependencyEdges count mismatch"):
            deps.load_plugin_dependency_graph(inspector)

    def test_unexpected_authority_is_rejected(self):
        graph = nonempty_graph()
        graph["authority"] = "security-evidence-observation"
        inspector = FakeInspector(graph)
        with self.assertRaisesRegex(ValueError, "unexpected authority"):
            deps.load_plugin_dependency_graph(inspector)

    def test_raw_browser_tables_are_added_without_replacing_ipc_tables(self):
        class InspectorClass(FakeInspector):
            pass
        deps._install_inspector_extensions(InspectorClass)
        inspector = InspectorClass(nonempty_graph())
        names = [row["name"] for row in inspector.table_catalog()]
        self.assertIn("v2_ipc_providers", names)
        self.assertIn("v2_plugin_dependencies", names)
        self.assertIn("v2_plugin_dependency_providers", names)
        self.assertEqual(3, len(inspector._special_table_rows("v2_plugin_dependencies")))
        self.assertEqual(3, len(inspector._special_table_rows("v2_plugin_dependency_providers")))

    def test_context_has_no_install_or_security_authority(self):
        result = deps.project_plugin_dependency_context(FakeInspector(nonempty_graph()), 10)
        self.assertTrue(result["readOnly"])
        self.assertEqual("none", result["mutationAuthority"])
        self.assertFalse(result["policyInput"])
        self.assertFalse(result["installAuthority"])
        self.assertFalse(result["packageManagementAuthority"])
        self.assertTrue(result["semanticBoundary"]["omegaOwnsPackageManagement"])
        self.assertTrue(result["semanticBoundary"]["deltaScopeOwnsInvestigationOnly"])

    def test_ui_patch_explicitly_separates_requires_ipc_and_components(self):
        patched = deps._patch_html("<html><script>function loadAssetRelationships(){}</script></html>")
        self.assertIn("__deltascopePluginDependenciesInstalled", patched)
        self.assertIn("Plugin dependency graph", patched)
        self.assertIn("IPC is explicitly", patched)
        self.assertIn("Package requirements come only from", patched)
        self.assertIn("NuGet/native/framework/assembly observations", patched)

    def test_entrypoint_installs_dependency_graph_compatibility(self):
        entrypoint = SECURITY / "deltascope.py"
        source = entrypoint.read_text(encoding="utf-8")
        self.assertIn("import deltascope_plugin_dependencies", source)
        self.assertIn("deltascope_plugin_dependencies.install()", source)


if __name__ == "__main__":
    unittest.main()

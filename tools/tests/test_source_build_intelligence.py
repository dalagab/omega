from __future__ import annotations

from collections import defaultdict
import json
import unittest

import common  # noqa: F401
import collector_contracts
import observation_projection
import rule_author_reference
import sigmascope
import srl


class SourceBuildIntelligenceTests(unittest.TestCase):
    def _inspect(self, files: dict[str, bytes]):
        entries = {path: len(raw) for path, raw in files.items()}
        return sigmascope._inspect_source_tree(
            entries,
            lambda path: files[path],
            defaultdict(list),
            "ExamplePlugin",
            "Example Plugin",
            "1.0.0",
            analyze=True,
        )

    def test_selected_plugin_build_graph_collects_projects_edges_inputs_dependencies_and_release_context(self) -> None:
        files = {
            "Plugin/Plugin.csproj": b'''<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework><AssemblyName>ExamplePlugin</AssemblyName><Version>1.0.0</Version><AllowUnsafeBlocks>true</AllowUnsafeBlocks></PropertyGroup><ItemGroup><PackageReference Include="DalamudPackager" Version="13.0.0" PrivateAssets="all"/><ProjectReference Include="../Shared/Shared.csproj" /></ItemGroup></Project>''',
            "Shared/Shared.csproj": b'''<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>''',
            "Plugin/Plugin.cs": b"using Dalamud.Plugin; class P {}",
            "Directory.Packages.props": b'''<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.4"/></ItemGroup></Project>''',
            "global.json": b'{"sdk":{"version":"10.0.100","rollForward":"latestPatch"}}',
            ".github/workflows/release.yml": b'''name: Release\non:\n  push:\njobs:\n  build:\n    runs-on: windows-latest\n    steps:\n      - uses: actions/checkout@v6\n      - run: dotnet publish Plugin/Plugin.csproj -c Release\n      - uses: actions/upload-artifact@v4\n''',
            "Plugin/ExamplePlugin.json": b'{"InternalName":"ExamplePlugin","AssemblyVersion":"1.0.0"}',
        }
        intel, scope, _scanned, _manifest, _profile = self._inspect(files)
        build = intel["sourceBuildIntelligence"]
        self.assertEqual("plugin-build-graph", scope["mode"])
        self.assertEqual(1, build["contractVersion"])
        by_path = {row["path"]: row for row in build["projects"]}
        self.assertEqual("primary", by_path["Plugin/Plugin.csproj"]["role"])
        self.assertEqual("1.0.0", by_path["Plugin/Plugin.csproj"]["projectVersion"])
        self.assertEqual(["net10.0-windows"], by_path["Plugin/Plugin.csproj"]["targetFrameworks"])
        self.assertTrue(by_path["Plugin/Plugin.csproj"]["allowUnsafeBlocks"])
        self.assertEqual("Shared/Shared.csproj", build["edges"][0]["toProject"])
        input_paths = {row["path"] for row in build["inputs"]}
        self.assertIn("Directory.Packages.props", input_paths)
        self.assertIn("global.json", input_paths)
        environments = {row["kind"]: row for row in build["environment"]}
        self.assertEqual("10.0.100", environments["dotnet-sdk"]["sdkVersion"])
        self.assertNotIn("allowPrerelease", environments["dotnet-sdk"])
        self.assertTrue(environments["msbuild-policy"]["managePackageVersionsCentrally"])
        declarations = {(row["kind"], row["name"]): row for row in build["dependencies"]}
        self.assertEqual("all", declarations[("nuget", "DalamudPackager")]["privateAssets"])
        self.assertEqual("13.0.4", declarations[("nuget-central-version", "Newtonsoft.Json")]["versionExpression"])
        workflow = build["releaseWorkflows"][0]
        self.assertEqual(["publish"], workflow["dotnetVerbs"])
        self.assertEqual(["Plugin/Plugin.csproj"], workflow["dotnetTargets"])
        self.assertNotIn("commands", workflow)
        self.assertTrue(workflow["uploadsArtifacts"])
        self.assertFalse(workflow["publishesRelease"])
        self.assertTrue(workflow["identityMatched"])
        self.assertTrue(build["fingerprints"]["buildGraphSha256"])
        self.assertTrue(build["fingerprints"]["dependencyDeclarationSha256"])
        self.assertTrue(build["fingerprints"]["releaseWorkflowSha256"])

    def test_lock_and_assets_files_keep_framework_and_resolved_package_identity(self) -> None:
        files = {
            "Plugin/Plugin.csproj": b'''<Project Sdk="Dalamud.NET.Sdk/13.0.0"><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework><AssemblyName>ExamplePlugin</AssemblyName></PropertyGroup></Project>''',
            "Plugin/Plugin.cs": b"class P {}",
            "Plugin/packages.lock.json": json.dumps({
                "version": 1,
                "dependencies": {"net10.0-windows": {"Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.4", "contentHash": "abc"}}},
            }).encode(),
            "Plugin/project.assets.json": json.dumps({
                "targets": {"net10.0-windows": {"Example.Transitive/2.1.0": {"type": "package"}}},
                "libraries": {"Example.Transitive/2.1.0": {"type": "package", "sha512": "def"}},
            }).encode(),
            "Plugin/ExamplePlugin.json": b'{"InternalName":"ExamplePlugin","AssemblyVersion":"1.0.0"}',
        }
        intel, _scope, _scanned, _manifest, _profile = self._inspect(files)
        build = intel["sourceBuildIntelligence"]
        lock = next(row for row in build["dependencies"] if row["sourceKind"] == "packages-lock")
        self.assertEqual("net10.0-windows", lock["targetFramework"])
        self.assertEqual("13.0.4", lock["resolvedVersion"])
        self.assertTrue(lock["direct"])
        assets = next(row for row in build["dependencies"] if row["sourceKind"] == "project-assets")
        self.assertEqual("Example.Transitive", assets["name"])
        self.assertEqual("2.1.0", assets["resolvedVersion"])
        self.assertTrue(assets["transitive"])

    def test_nuget_package_sources_drop_credentials_and_query_material(self) -> None:
        files = {
            "Plugin/Plugin.csproj": b"<Project Sdk='Dalamud.NET.Sdk/13.0.0'><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework><AssemblyName>ExamplePlugin</AssemblyName></PropertyGroup></Project>",
            "Plugin/Plugin.cs": b"class P {}",
            "NuGet.config": b"<configuration><packageSources><add key='private' value='https://user:secret@packages.example.invalid/v3/index.json?token=abc' /></packageSources><packageSourceCredentials><private><add key='ClearTextPassword' value='dont-retain-me' /></private></packageSourceCredentials></configuration>",
            "Plugin/ExamplePlugin.json": b'{"InternalName":"ExamplePlugin","AssemblyVersion":"1.0.0"}',
        }
        intel, _scope, _scanned, _manifest, _profile = self._inspect(files)
        build = intel["sourceBuildIntelligence"]
        nuget = next(row for row in build["environment"] if row["kind"] == "nuget-config")
        self.assertEqual(["https://packages.example.invalid/v3/index.json"], nuget["packageSources"])
        encoded = json.dumps(build)
        self.assertNotIn("secret", encoded)
        self.assertNotIn("dont-retain-me", encoded)
        self.assertNotIn("token=abc", encoded)

    def test_unrelated_monorepo_release_workflow_is_not_attributed_to_plugin(self) -> None:
        files = {
            "Plugin/Plugin.csproj": b'''<Project Sdk="Dalamud.NET.Sdk/13.0.0"><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework><AssemblyName>ExamplePlugin</AssemblyName></PropertyGroup></Project>''',
            "Plugin/Plugin.cs": b"class P {}",
            "Server/Server.csproj": b'''<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>''',
            ".github/workflows/server.yml": b'''name: Server\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker build -t example-server Server\n''',
            "Plugin/ExamplePlugin.json": b'{"InternalName":"ExamplePlugin","AssemblyVersion":"1.0.0"}',
        }
        intel, _scope, _scanned, _manifest, _profile = self._inspect(files)
        self.assertEqual([], intel["sourceBuildIntelligence"]["releaseWorkflows"])

    def test_build_collections_are_complete_only_under_new_source_contract(self) -> None:
        report = {"source": {"dependencyIntelligence": {"sourceBuildIntelligence": {"contractVersion": 1}}}}
        for name in (
            "sourceBuildProjects", "sourceBuildEdges", "sourceBuildInputs", "sourceBuildEnvironment",
            "sourceDependencyDeclarations", "sourceReleaseWorkflows",
        ):
            self.assertTrue(observation_projection.report_collection_complete(report, name), name)
        self.assertFalse(observation_projection.report_collection_complete({"source": {"dependencyIntelligence": {}}}, "sourceBuildProjects"))

    def test_srl_can_reason_over_build_observations_without_special_collector_binding(self) -> None:
        rule = r"""
schema: omega.sigmascope.rule.v1
id: source.build.unsafe
kind: observation
status: reviewed
requires: [sourceBuildProjects]
selectors:
  unsafe_project:
    collection: sourceBuildProjects
    where:
      allowUnsafeBlocks:
        equals: true
condition: unsafe_project
emit:
  fact: source.build.unsafe
  confidence: high
  title: Source project enables unsafe blocks
"""
        compiled = srl.compile_yaml_text(rule)
        result = srl.evaluate_ruleset(compiled, {"sourceBuildProjects": [{"path": "Plugin.csproj", "allowUnsafeBlocks": True}]})
        self.assertEqual(["source.build.unsafe"], result["facts"])

    def test_source_provider_and_srl_reference_publish_new_collections(self) -> None:
        provider = collector_contracts.collector_map()["omega.collector.sigmascope.source-analysis"]
        for name in (
            "sourceBuildProjects", "sourceBuildEdges", "sourceBuildInputs", "sourceBuildEnvironment",
            "sourceDependencyDeclarations", "sourceReleaseWorkflows",
        ):
            self.assertIn(name, provider["provides"])
            self.assertIn(name, observation_projection.COLLECTIONS)
            self.assertIn(name, rule_author_reference.COLLECTIONS)


if __name__ == "__main__":
    unittest.main()

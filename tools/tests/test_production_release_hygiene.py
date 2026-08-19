import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class ProductionReleaseHygieneTests(unittest.TestCase):
    def test_operator_only_material_is_not_in_production_tree(self):
        self.assertFalse((ROOT / "SESSION_STARTER.md").exists())
        self.assertFalse((ROOT / "handover").exists())

    def test_release_metadata_is_synchronized_and_release_oriented(self):
        csproj = (ROOT / "Omega" / "DalagabOmega.csproj").read_text(encoding="utf-8")
        build_info = (ROOT / "Omega" / "BuildInfo.cs").read_text(encoding="utf-8")
        legacy_manifest = json.loads((ROOT / "repository" / "pluginmaster.json").read_text(encoding="utf-8"))[0]
        template = json.loads((ROOT / "repository" / "pluginmaster.template.json").read_text(encoding="utf-8"))[0]

        match = re.search(r"<Version>([^<]+)</Version>", csproj)
        self.assertIsNotNone(match)
        version = match.group(1)
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertIn(f'Version = "{version}"', build_info)
        self.assertIn(f'BuildStamp = "omega-{version}"', build_info)

        release_url = legacy_manifest["DownloadLinkInstall"]
        release_match = re.search(r"/releases/download/v(\d+\.\d+\.\d+)/Omega\.zip$", release_url)
        self.assertIsNotNone(release_match)
        self.assertEqual(f"{release_match.group(1)}.0", legacy_manifest["AssemblyVersion"])
        self.assertEqual(release_url, legacy_manifest["DownloadLinkUpdate"])
        self.assertNotIn("/omega-latest/Omega.zip", release_url)
        self.assertEqual("", template["AssemblyVersion"])
        self.assertEqual("", template["DownloadLinkInstall"])
        self.assertEqual("", template["DownloadLinkUpdate"])

    def test_production_tree_contains_only_product_regression_release_and_sigmascope_material(self):
        required = [
            "Omega.sln",
            "Omega/DalagabOmega.csproj",
            "Omega/DalagabOmega.json",
            "Omega.RegressionTests/Omega.RegressionTests.csproj",
            "EULA.md",
            "CHANGELOG.md",
            ".omega/index.json",
            "images/omega-banner.png",
            "catalog/catalog-endpoint.json",
            "sources/curated-sources.json",
            "sources/community-sources.json",
            "sources/source-overrides.json",
            "repository/pluginmaster.json",
            "repository/pluginmaster.template.json",
            "tools/catalog/sigmascope.py",
            "tools/catalog/catalog_json_store.py",
            "tools/catalog/definitions_snapshot.py",
            "tools/catalog/catalog_state.py",
            "tools/catalog/publish_catalog_state.py",
            "tools/catalog/compile_marketplace_snapshot.py",
            "tools/security/production_sigmascope_v2_pipeline.py",
            "tools/release/generate_pluginmaster.py",
            ".github/workflows/catalog-builder.yml",
            ".github/workflows/catalog-compaction.yml",
            ".github/workflows/regression-tests.yml",
            ".github/workflows/release.yml",
            ".github/workflows/sigmascope.yml",
            ".github/workflows/source-submissions.yml",
            ".github/ISSUE_TEMPLATE/plugin-source.yml",
            "README.md",
            "SECURITY.md",
        ]
        for relative in required:
            self.assertTrue((ROOT / relative).is_file(), relative)

        omega_index = json.loads((ROOT / ".omega" / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(1, omega_index["SchemaVersion"])
        self.assertIn("images/omega-banner.png", omega_index["OmegaBannerUrl"])

        builder_workflow = (ROOT / ".github" / "workflows" / "catalog-builder.yml").read_text(encoding="utf-8")
        regression_workflow = (ROOT / ".github" / "workflows" / "regression-tests.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "17 2 * * *"', builder_workflow)
        self.assertIn("workflow_dispatch:", builder_workflow)
        self.assertNotRegex(builder_workflow, r"(?m)^  push:\s*$")
        self.assertIn("publish_catalog_state.py", builder_workflow)
        self.assertIn("compile_marketplace_snapshot.py", builder_workflow)
        self.assertIn('- ".omega/**"', regression_workflow)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Build Omega", readme)
        self.assertIn("Sigmascope", readme)
        self.assertIn(".omega/index.json", readme)
        self.assertNotIn("Install-OmegaRepository.ps1", readme)

        security_policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("Reporting a vulnerability", security_policy)
        self.assertIn("Sigmascope", security_policy)
        self.assertIn("Security Evidence v2", security_policy)
        self.assertIn("catalog/catalog-endpoint.json", security_policy)
        self.assertNotIn("CodeQL", security_policy)

        removed = [
            "site",
            "tools/site",
            "installer",
            "examples",
            "package.json",
            "package-lock.json",
            "repository/README.md",
            "tools/security/README.md",
            "tools/tests/test_site_contracts.py",
            "tools/validate-package.ps1",
            "tools/apply-marketplace-ui-design-pass.ps1",
            "tools/validate-marketplace-ui-design-pass.ps1",
            ".github/dependabot.yml",
            ".github/workflows/pages.yml",
            ".github/workflows/codeql.yml",
            ".github/workflows/dependency-review.yml",
            ".github/workflows/scorecards.yml",
        ]
        for relative in removed:
            self.assertFalse((ROOT / relative).exists(), relative)


if __name__ == "__main__":
    unittest.main()

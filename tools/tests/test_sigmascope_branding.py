from __future__ import annotations

import unittest

import common


class SigmascopeBrandingTests(unittest.TestCase):
    def test_sigmascope_is_the_canonical_engine_identity(self) -> None:
        root = common.ROOT
        workflow = root / ".github" / "workflows" / "sigmascope.yml"
        self.assertTrue(workflow.is_file())
        self.assertFalse((root / ".github" / "workflows" / "security-scanner.yml").exists())
        workflow_text = workflow.read_text(encoding="utf-8")
        self.assertIn("name: Omega Sigmascope", workflow_text)
        self.assertIn("tools/catalog/sigmascope.py", workflow_text)
        self.assertIn("production_sigmascope_v2_pipeline.py", workflow_text)
        self.assertIn("sigmascope_source_followups.py", workflow_text)

        engine = (root / "tools" / "catalog" / "sigmascope.py").read_text(encoding="utf-8")
        self.assertIn('SIGMASCOPE_NAME = "Sigmascope"', engine)
        self.assertIn('SIGMASCOPE_VERSION = "2.5.0"', engine)
        self.assertIn("SCANNER_VERSION = SIGMASCOPE_VERSION", engine)
        self.assertIn("Omega-Sigmascope/", engine)

        # The old executable names remain compatibility shims only; new infrastructure
        # and presentation code must use the Sigmascope names.
        shim = (root / "tools" / "catalog" / "security_scan.py").read_text(encoding="utf-8")
        self.assertIn("Compatibility shim", shim)
        self.assertIn("from sigmascope import", shim)

        identity = (root / "Omega" / "SigmascopeInfo.cs").read_text(encoding="utf-8")
        self.assertIn('Name = "Sigmascope"', identity)
        self.assertIn("Sigmascape", identity)
        self.assertIn("scope examines closely", identity)
        self.assertIn("evidence, not a final judgement", identity)

        library = (root / "Omega" / "UI" / "MarketplaceWindow.Library.cs").read_text(encoding="utf-8")
        product = (root / "Omega" / "UI" / "MarketplaceWindow.Sigmascope.cs").read_text(encoding="utf-8")
        self.assertIn("library-tab-sigmascope", library)
        self.assertIn("SigmascopeInfo.Name", library)
        self.assertIn("SigmascopeInfo.Description", product)
        self.assertIn("SigmascopeInfo.Lore", product)

        # ZipRunner applies production packages as overlays. These retired source paths
        # therefore remain as behavior-free tombstones long enough to overwrite a
        # pre-Sigmascope workspace rather than leaving duplicate partial members behind.
        for legacy_name, canonical_name in (
            ("MarketplaceWindow.PluginSecurity.cs", "MarketplaceWindow.Sigmascope.cs"),
            ("MarketplaceWindow.LibrarySecurity.cs", "MarketplaceWindow.LibrarySigmascope.cs"),
        ):
            legacy = (root / "Omega" / "UI" / legacy_name).read_text(encoding="utf-8")
            self.assertIn("ZipRunner overlay compatibility tombstone", legacy)
            self.assertIn(canonical_name, legacy)
            self.assertNotIn("partial class MarketplaceWindow", legacy)


if __name__ == "__main__":
    unittest.main()

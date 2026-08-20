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
        self.assertIn('SIGMASCOPE_VERSION = "2.14.0"', engine)
        self.assertIn("SCANNER_VERSION = SIGMASCOPE_VERSION", engine)
        self.assertIn("Omega-Sigmascope/", engine)

        # The old executable names remain compatibility shims only; new infrastructure
        # and presentation code must use the Sigmascope names.
        shim = (root / "tools" / "catalog" / "security_scan.py").read_text(encoding="utf-8")
        self.assertIn("Compatibility shim", shim)
        self.assertIn("from sigmascope import", shim)

        # Client-side Sigmascope presentation identity belongs to main after the branch split.
        self.assertFalse((root / "Omega").exists())
        deltascope = (root / "tools" / "security" / "deltascope.py").read_text(encoding="utf-8")
        self.assertIn("DeltaScope", deltascope)
        self.assertIn("developer-only, read-only", deltascope)



if __name__ == "__main__":
    unittest.main()

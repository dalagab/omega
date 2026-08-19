from __future__ import annotations
import unittest
import common

class BranchSplitContractTests(unittest.TestCase):
    def test_security_branch_has_no_client_source(self) -> None:
        self.assertFalse((common.ROOT / "Omega").exists())
        self.assertFalse((common.ROOT / "Omega.sln").exists())

    def test_reusable_workflows_checkout_sigmascope_branch(self) -> None:
        for name in ("catalog-builder.yml", "sigmascope.yml", "source-submissions.yml", "catalog-compaction.yml", "deltascope.yml"):
            text = (common.ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
            self.assertIn("workflow_call:", text, name)
            self.assertIn("ref: sigmascope", text, name)

if __name__ == "__main__":
    unittest.main()

from __future__ import annotations
import unittest
import common

class DeltaScopeContractTests(unittest.TestCase):
    def test_deltascope_is_explicit_and_read_only(self) -> None:
        wrapper = (common.ROOT / "tools" / "security" / "deltascope.py").read_text(encoding="utf-8")
        view = (common.ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        workflow = (common.ROOT / ".github" / "workflows" / "deltascope.yml").read_text(encoding="utf-8")
        self.assertIn("developer-only, read-only", wrapper)
        self.assertIn("DeltaScope", view)
        self.assertIn("--no-download", workflow)
        self.assertNotIn("publish_security_evidence_v2.py", workflow)
        self.assertNotIn("publish_catalog_state.py", workflow)
        self.assertNotIn("schedule:", workflow)

if __name__ == "__main__":
    unittest.main()

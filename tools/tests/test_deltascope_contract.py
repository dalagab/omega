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
        self.assertIn('class="omega-mark"', view)
        self.assertIn('aria-label="Omega">O</span>', view)
        self.assertIn("TONI", view)
        self.assertIn("deterministic evidence guide", view)
        for token in ("SECURITY RESEARCH WORKBENCH", "Research queue", "Triage", "Malware", "ClamAV & YARA", "ClamAV antivirus", "YARA rules", "Endpoint intelligence", "Code & native", "Supply chain", "Immutable evidence", "Metrics & coverage · exact drill-down counts", "SOURCE CODE", "ARTIFACT ONLY", "Advanced · raw Evidence-v2 / database browser", "v2_unscanned_queue", "v2_review_variants", "v2_queue_items", "v2_historical_snapshots", "v2_analyses", "v2_finding_breakdown", 'parsed.path == "/api/snapshot"', 'parsed.path == "/api/analysis-manifest"'):
            self.assertIn(token, view)
        self.assertIn("--no-download", workflow)
        self.assertNotIn("publish_security_evidence_v2.py", workflow)
        self.assertNotIn("publish_catalog_state.py", workflow)
        self.assertNotIn("schedule:", workflow)

if __name__ == "__main__":
    unittest.main()

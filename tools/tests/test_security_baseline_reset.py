from __future__ import annotations

import sys
import tempfile
from pathlib import Path
import unittest

import common

for root in (common.ROOT / "tools" / "security", common.ROOT / "tools" / "catalog"):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

import reset_security_baseline  # noqa: E402
import test_production_sigmascope_v2_pipeline as production_tests  # noqa: E402


class SecurityBaselineResetTests(unittest.TestCase):
    def test_reset_preserves_catalog_rows_and_emits_valid_empty_v2(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-security-reset-") as td:
            root = Path(td)
            fixture = production_tests.ProductionSecurityV2PipelineTests(
                methodName="test_bounded_batch_report_aggregates_multiple_queue_invocations"
            )
            database, _variant_id, _plugin_id = fixture.make_catalog_with_security(root)
            receipt = reset_security_baseline.build(
                database,
                root / "evidence",
                root / "deep",
                root / "receipt.json",
                previous_evidence_head="a" * 40,
            )

            self.assertEqual("omega.security-baseline-reset.v1", receipt["schema"])
            self.assertEqual(0, receipt["evidence"]["currentVariants"])
            self.assertTrue(receipt["evidence"]["validation"]["ok"])
            self.assertEqual(0, receipt["deepScan"]["items"])
            self.assertGreater(receipt["database"]["securityRowsBefore"], 0)
            self.assertEqual(0, receipt["database"]["securityRowsAfter"])
            self.assertGreater(receipt["database"]["preservedRows"], 0)
            self.assertEqual("a" * 40, receipt["previousEvidenceHead"])


if __name__ == "__main__":
    unittest.main()

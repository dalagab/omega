from __future__ import annotations

import unittest

import common


class SigmaScopeParallelBaselineBundleContractTests(unittest.TestCase):
    def test_exact_result_bundles_support_clean_baseline_rebuilds(self) -> None:
        text = (
            common.ROOT / "tools" / "security" / "sigmascope_result_bundle.py"
        ).read_text(encoding="utf-8")

        self.assertNotIn(
            "parallel bundle is disabled during baseline security rebuilds",
            text,
        )
        self.assertIn("parallel bundle cannot cross a catalog identity epoch", text)
        self.assertIn(
            "pipeline report is not bound to exactly the requested queue key",
            text,
        )
        self.assertIn(
            "SigmaScope result bundle requires an immutable worker image @sha256 reference",
            text,
        )


if __name__ == "__main__":
    unittest.main()

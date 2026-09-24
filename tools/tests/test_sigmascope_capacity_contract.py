from __future__ import annotations

import sys
import unittest

import common


for root in (common.ROOT / "tools" / "security", common.ROOT / "tools" / "catalog"):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

import sigmascope_parallel_drain_plan  # noqa: E402
import sigmascope_result_merger  # noqa: E402


class SigmaScopeCapacityContractTests(unittest.TestCase):
    def test_canonical_parallel_and_serialized_capacity_are_aligned(self) -> None:
        self.assertEqual(128, sigmascope_parallel_drain_plan.MAX_ASSIGNMENTS)
        self.assertEqual(128, sigmascope_result_merger.MAX_STANDARD_BUNDLES)
        self.assertEqual(1, sigmascope_parallel_drain_plan.MAX_LARGE_ASSIGNMENTS)
        self.assertEqual(1, sigmascope_result_merger.MAX_LARGE_ARTIFACT_BUNDLES)
        self.assertEqual(129, sigmascope_result_merger.MAX_BUNDLES)
        self.assertEqual(129, sigmascope_result_merger.MAX_VARIANTS)

    def test_wake_breaker_uses_current_canonical_capacity(self) -> None:
        text = (
            common.ROOT / ".github" / "workflows" / "sigmascope-drain-wake.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('[ "$previous_capacity" -ge 128 ]', text)


if __name__ == "__main__":
    unittest.main()

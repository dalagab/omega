from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

from sigmascope_drain_bundle_intake import build_intake


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


class SigmaScopeDrainBundleIntakeTests(unittest.TestCase):
    def test_accepts_non_empty_exact_subset_and_records_missing_keys(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-drain-intake-") as td:
            root = Path(td)
            plan = {
                "schema": "omega.sigmascope-parallel-drain-plan.v1",
                "planRevision": "sigmascope-drain-plan-v1-test",
                "assignments": [
                    {"queueKey": "variant-1:artifact", "workType": "artifact", "variantId": 1, "targetFingerprint": "a"},
                    {"queueKey": "variant-2:source", "workType": "source", "variantId": 2, "targetFingerprint": "b"},
                ],
            }
            write_json(root / "plan.json", plan)
            write_json(root / "artifacts" / "slot-0" / "key-01" / "bundle.json", {
                "work": {"queueKey": "variant-1:artifact", "workType": "artifact", "variantId": 1, "targetFingerprint": "a"}
            })
            write_json(root / "artifacts" / "slot-0" / "slot-summary.json", {
                "schema": "omega.sigmascope-worker-slot-summary.v1",
                "planRevision": "sigmascope-drain-plan-v1-test",
                "slot": 0,
                "lane": "updates",
                "plannedQueueKeys": ["variant-1:artifact", "variant-2:source"],
                "bundledQueueKeys": ["variant-1:artifact"],
                "unprocessedQueueKeys": ["variant-2:source"],
            })

            intake = build_intake(
                plan_path=root / "plan.json",
                artifacts_root=root / "artifacts",
                expected_assignments=2,
                workers_result="failure",
                output=root / "intake.json",
            )

            self.assertEqual(1, intake["receivedCount"])
            self.assertEqual(["variant-2:source"], intake["missingQueueKeys"])
            self.assertEqual("operational-result-intake-only", intake["authority"])
            self.assertTrue((root / "intake.json").is_file())

    def test_rejects_duplicate_unplanned_mismatched_and_empty_deliveries(self) -> None:
        base_plan = {
            "schema": "omega.sigmascope-parallel-drain-plan.v1",
            "planRevision": "sigmascope-drain-plan-v1-test",
            "assignments": [
                {"queueKey": "variant-1:artifact", "workType": "artifact", "variantId": 1, "targetFingerprint": "a"},
            ],
        }
        cases = [
            ("duplicate", [
                {"queueKey": "variant-1:artifact", "workType": "artifact", "variantId": 1, "targetFingerprint": "a"},
                {"queueKey": "variant-1:artifact", "workType": "artifact", "variantId": 1, "targetFingerprint": "a"},
            ], "duplicate delivered queue keys"),
            ("unplanned", [
                {"queueKey": "variant-2:artifact", "workType": "artifact", "variantId": 2, "targetFingerprint": "b"},
            ], "outside the exact drain plan"),
            ("mismatch", [
                {"queueKey": "variant-1:artifact", "workType": "source", "variantId": 1, "targetFingerprint": "a"},
            ], "mismatched workType"),
        ]
        for name, works, message in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="omega-drain-intake-") as td:
                root = Path(td)
                write_json(root / "plan.json", base_plan)
                for index, work in enumerate(works):
                    write_json(root / "artifacts" / f"bundle-{index}" / "bundle.json", {"work": work})
                with self.assertRaisesRegex(ValueError, message):
                    build_intake(
                        plan_path=root / "plan.json",
                        artifacts_root=root / "artifacts",
                        expected_assignments=1,
                        workers_result="failure",
                        output=root / "intake.json",
                    )
        with tempfile.TemporaryDirectory(prefix="omega-drain-intake-") as td:
            root = Path(td)
            write_json(root / "plan.json", base_plan)
            with self.assertRaisesRegex(ValueError, "no finalized SigmaScope result bundles"):
                build_intake(
                    plan_path=root / "plan.json",
                    artifacts_root=root / "artifacts",
                    expected_assignments=1,
                    workers_result="failure",
                    output=root / "intake.json",
                )


if __name__ == "__main__":
    unittest.main()

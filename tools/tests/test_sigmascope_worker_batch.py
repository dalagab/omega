from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

from sigmascope_worker_batch import load_queue_keys, planned_selector, run_frozen_pipeline, split_report_for_key


class SigmaScopeWorkerBatchTests(unittest.TestCase):
    def test_load_queue_keys_rejects_duplicates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-sigmascope-batch-") as td:
            path = Path(td) / "keys.txt"
            path.write_text("variant-1\nvariant-1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_queue_keys(path)

    def test_planned_selector_preserves_exact_planner_order_and_fails_closed(self) -> None:
        states = {"variant-2": {"queueKey": "variant-2"}, "variant-1": {"queueKey": "variant-1"}}

        def select_key(_state, key):
            return states.get(key)

        select_next = planned_selector(select_key, ["variant-2", "variant-1"])
        self.assertEqual("variant-2", select_next({})["queueKey"])
        self.assertEqual("variant-1", select_next({})["queueKey"])
        self.assertIsNone(select_next({}))

        fail = planned_selector(select_key, ["variant-missing"])
        with self.assertRaisesRegex(RuntimeError, "no longer eligible"):
            fail({})

    def test_run_frozen_pipeline_constrains_select_next_to_planned_keys(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-sigmascope-frozen-batch-") as td:
            root = Path(td)
            work = root / "work"
            pipeline = root / "fake_pipeline.py"
            pipeline.write_text(
                "from pathlib import Path\n"
                "import json, sys\n"
                "class Queue:\n"
                "    @staticmethod\n"
                "    def select_key(state, key):\n"
                "        return dict(state.get(key)) if key in state else None\n"
                "    @staticmethod\n"
                "    def select_next(state):\n"
                "        return next(iter(state.values()), None)\n"
                "scan_queue = Queue()\n"
                "def main():\n"
                "    args = sys.argv[1:]\n"
                "    work = Path(args[args.index('--work-dir') + 1])\n"
                "    count = int(args[args.index('--max-scans') + 1])\n"
                "    state = {k: {'queueKey': k, 'variantId': i + 1} for i, k in enumerate(['variant-1','variant-2','variant-3'])}\n"
                "    selected = [scan_queue.select_next(state) for _ in range(count)]\n"
                "    work.mkdir(parents=True, exist_ok=True)\n"
                "    (work / 'production-sigmascope-v2-report.json').write_text(json.dumps({'queue': {'selectedItems': selected}}))\n"
                "    return 0\n",
                encoding="utf-8",
            )
            report = run_frozen_pipeline(
                pipeline, ["variant-3", "variant-1"], ["--work-dir", str(work)]
            )
            self.assertEqual(
                ["variant-3", "variant-1"],
                [item["queueKey"] for item in report["queue"]["selectedItems"]],
            )

    def test_split_report_retains_only_one_exact_result(self) -> None:
        report = {
            "queue": {
                "selected": {"queueKey": "variant-1", "variantId": 1},
                "selectedItems": [
                    {"queueKey": "variant-1", "variantId": 1},
                    {"queueKey": "variant-2", "variantId": 2},
                ],
                "selectedCount": 2,
                "requestedQueueKey": "",
            },
            "successfulVariantIds": [1],
            "failedRetainedVariantIds": [2],
            "scan": {
                "plugins": [
                    {"variantId": 1, "status": "complete", "elapsedSeconds": 1.25},
                    {"variantId": 2, "status": "failed", "elapsedSeconds": 0.5},
                ],
                "selected": 2,
                "completed": 1,
                "failed": 1,
                "invocations": 2,
            },
        }
        split = split_report_for_key(report, "variant-2")
        self.assertEqual(["variant-2"], [item["queueKey"] for item in split["queue"]["selectedItems"]])
        self.assertEqual(1, split["queue"]["selectedCount"])
        self.assertEqual("variant-2", split["queue"]["requestedQueueKey"])
        self.assertEqual([], split["successfulVariantIds"])
        self.assertEqual([2], split["failedRetainedVariantIds"])
        self.assertEqual([2], [item["variantId"] for item in split["scan"]["plugins"]])
        self.assertEqual(0, split["scan"]["completed"])
        self.assertEqual(1, split["scan"]["failed"])

    def test_parallel_drain_workflow_batches_and_suppresses_duplicate_successors(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        self.assertIn("sigmascope_worker_batch.py run", workflow)
        self.assertIn("sigmascope_worker_batch.py bundles", workflow)
        self.assertNotIn("while IFS= read -r queue_key; do", workflow)
        self.assertIn("gh run list", workflow)
        self.assertIn("Another active parallel drain already owns successor dispatch", workflow)


if __name__ == "__main__":
    unittest.main()

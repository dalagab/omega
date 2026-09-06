from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

from sigmascope_worker_batch import (
    load_queue_keys,
    planned_selector,
    prepare_frozen_transport_view,
    run_frozen_pipeline,
    split_report_for_key,
    validated_selected_queue_keys,
)


class SigmaScopeWorkerBatchTests(unittest.TestCase):
    def test_load_queue_keys_rejects_duplicates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-sigmascope-batch-") as td:
            path = Path(td) / "keys.txt"
            path.write_text("variant-1\nvariant-1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_queue_keys(path)

    def test_budget_stop_accepts_only_an_exact_planned_prefix(self) -> None:
        planned = ["variant-1", "variant-2", "variant-3"]
        stopped = {
            "queue": {
                "selectedItems": [
                    {"queueKey": "variant-1"},
                    {"queueKey": "variant-2"},
                ],
                "stoppedByBatchBudget": True,
            }
        }
        self.assertEqual(["variant-1", "variant-2"], validated_selected_queue_keys(stopped, planned))
        with self.assertRaisesRegex(RuntimeError, "expected"):
            validated_selected_queue_keys({
                "queue": {
                    "selectedItems": [{"queueKey": "variant-2"}],
                    "stoppedByBatchBudget": True,
                }
            }, planned)
        with self.assertRaisesRegex(RuntimeError, "expected"):
            validated_selected_queue_keys({
                "queue": {
                    "selectedItems": [{"queueKey": "variant-1"}],
                    "stoppedByBatchBudget": False,
                }
            }, planned)

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

    def test_frozen_transport_view_repairs_only_derived_plugin_summaries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-sigmascope-transport-compat-") as td:
            root = Path(td)
            current = root / "current"
            variant_path = current / "variants" / "0000" / "1.json"
            variant_path.parent.mkdir(parents=True, exist_ok=True)
            variant_path.write_text(
                json.dumps({"variantId": 1, "lifecycle": {"schema": "omega.security-evidence.variant-lifecycle.v1"}}),
                encoding="utf-8",
            )
            plugins_path = current / "indexes" / "plugins.json"
            plugins_path.parent.mkdir(parents=True, exist_ok=True)
            plugins = {
                "schema": "omega.security-evidence.plugins-index.v2",
                "lifecycleContractVersion": 1,
                "currentVariants": [{
                    "variantId": 1,
                    "variantPath": "variants/0000/1.json",
                    "summary": {"coverage_status": "complete", "variant_id": 1},
                }],
                "terminalVariants": [],
                "historicalSnapshots": [],
            }
            plugins_path.write_text(json.dumps(plugins, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            root_index = {
                "schema": "omega.security-evidence.v2",
                "indexes": {"plugins": {
                    "path": "indexes/plugins.json",
                    "bytes": plugins_path.stat().st_size,
                    "sha256": hashlib.sha256(plugins_path.read_bytes()).hexdigest(),
                }},
            }
            (current / "index.json").write_text(
                json.dumps(root_index, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )

            def frozen_summary(payload, *, lifecycle_contract_version=None):
                self.assertEqual(1, lifecycle_contract_version)
                return {"variant_id": int(payload.get("variantId") or 0)}

            view, changed = prepare_frozen_transport_view(current, root / "compat", frozen_summary)
            self.assertEqual(1, changed)
            self.assertEqual({"coverage_status": "complete", "variant_id": 1}, plugins["currentVariants"][0]["summary"])
            original = json.loads(plugins_path.read_text(encoding="utf-8"))
            self.assertEqual({"coverage_status": "complete", "variant_id": 1}, original["currentVariants"][0]["summary"])
            compat_plugins = json.loads((view / "indexes" / "plugins.json").read_text(encoding="utf-8"))
            self.assertEqual({"variant_id": 1}, compat_plugins["currentVariants"][0]["summary"])
            compat_root = json.loads((view / "index.json").read_text(encoding="utf-8"))
            descriptor = compat_root["indexes"]["plugins"]
            self.assertEqual((view / "indexes" / "plugins.json").stat().st_size, descriptor["bytes"])
            self.assertEqual(
                hashlib.sha256((view / "indexes" / "plugins.json").read_bytes()).hexdigest(),
                descriptor["sha256"],
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
        entrypoint = (ROOT / "tools" / "security" / "sigmascope_parallel_worker_entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn("sigmascope_parallel_worker_entrypoint.sh process", workflow)
        self.assertIn("sigmascope_worker_batch.py run", entrypoint)
        self.assertIn("sigmascope_worker_batch.py bundles", entrypoint)
        self.assertIn("--summary catalog/slot-result-bundles/slot-summary.json", entrypoint)
        self.assertIn("WORKER_MAX_BATCH_SECONDS:-3600", entrypoint)
        self.assertIn("if: always()", workflow)
        intake = (ROOT / "tools" / "security" / "sigmascope_drain_bundle_intake.py").read_text(encoding="utf-8")
        self.assertIn("omega.sigmascope-drain-bundle-intake.v1", intake)
        self.assertNotIn("needs.workers.result == 'success'", workflow)
        self.assertNotIn("while IFS= read -r queue_key; do", workflow)
        self.assertIn("gh run list", workflow)
        self.assertIn("Another active parallel drain already owns successor dispatch", workflow)


if __name__ == "__main__":
    unittest.main()

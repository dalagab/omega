from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "actions" / "github_artifact_lifecycle.py"
spec = importlib.util.spec_from_file_location("github_artifact_lifecycle", MODULE_PATH)
artifact_lifecycle = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(artifact_lifecycle)


class ArtifactLifecycleTests(unittest.TestCase):
    def test_selection_is_scoped_to_explicit_name_or_prefix(self) -> None:
        artifacts = [
            {"id": 1, "name": "omega-sigmascope-drain-plan", "size_in_bytes": 100, "expired": False},
            {"id": 2, "name": "omega-sigmascope-drain-123-slot-0", "size_in_bytes": 200, "expired": False},
            {"id": 3, "name": "omega-sigmascope-drain-publication", "size_in_bytes": 300, "expired": False},
            {"id": 4, "name": "unrelated", "size_in_bytes": 400, "expired": False},
            {"id": 5, "name": "omega-sigmascope-drain-123-slot-1", "size_in_bytes": 500, "expired": True},
        ]
        selected = artifact_lifecycle.select_artifacts(
            artifacts,
            names={"omega-sigmascope-drain-plan"},
            prefixes=("omega-sigmascope-drain-123-slot-",),
        )
        self.assertEqual([1, 2], [row["id"] for row in selected])
        summary = artifact_lifecycle.artifact_summary("delete", "dalagab/omega", 123, selected)
        self.assertEqual(2, summary["matchedCount"])
        self.assertEqual(300, summary["matchedBytes"])

    def test_delete_attempts_every_selected_artifact_and_reports_failures(self) -> None:
        calls = []

        def request(url: str, _token: str, *, method: str = "GET") -> dict:
            calls.append((url, method))
            if url.endswith("/2"):
                raise RuntimeError("fixture failure")
            return {}

        selected = [
            {"id": 1, "name": "one", "size_in_bytes": 100},
            {"id": 2, "name": "two", "size_in_bytes": 200},
            {"id": 3, "name": "three", "size_in_bytes": 300},
        ]
        deleted_count, deleted_bytes, failures = artifact_lifecycle.delete_selected(
            "dalagab/omega", "token", selected, request_json=request
        )
        self.assertEqual(2, deleted_count)
        self.assertEqual(400, deleted_bytes)
        self.assertEqual([2], [failure["id"] for failure in failures])
        self.assertEqual(3, len(calls))

    def test_workflow_uses_one_day_fallback_and_bounded_cleanup(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "sigmascope-parallel-drain.yml").read_text(encoding="utf-8")
        plan = workflow[workflow.index("name: omega-sigmascope-drain-plan"): workflow.index("\n  workers:")]
        workers = workflow[workflow.index("\n  workers:"): workflow.index("\n  worker-orchestration-guard:")]
        merge = workflow[workflow.index("\n  merge:"): workflow.index("\n  publish:")]
        publish = workflow[workflow.index("\n  publish:"): workflow.index("\n  notify-discord:")]
        self.assertIn("retention-days: 1", plan)
        self.assertIn("retention-days: 1", workers)
        self.assertIn("actions: write", merge)
        self.assertIn("github_artifact_lifecycle.py", merge)
        self.assertIn("delete_args=(", merge)
        self.assertIn("omega-sigmascope-drain-${GITHUB_RUN_ID}-slot-", merge)
        self.assertIn("github_artifact_lifecycle.py report", merge)
        self.assertIn("actions: write", publish)
        self.assertIn("--name omega-sigmascope-drain-publication", publish)
        self.assertIn("continue-on-error: true", publish[publish.index("Delete consumed publication artifact"):])


if __name__ == "__main__":
    unittest.main()

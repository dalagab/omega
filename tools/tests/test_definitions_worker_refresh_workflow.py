from __future__ import annotations

import unittest

import common


class DefinitionsWorkerRefreshWorkflowTests(unittest.TestCase):
    def test_scanner_changes_refresh_frozen_definitions_without_rebuilding_catalog_identity(self) -> None:
        text = (common.ROOT / ".github" / "workflows" / "definitions-worker-refresh.yml").read_text(encoding="utf-8")
        self.assertIn("branches: [sigmascope]", text)
        self.assertIn('"tools/catalog/**/*.py"', text)
        self.assertIn('"tools/security/**/*.py"', text)
        self.assertIn('"security-definitions/**"', text)
        self.assertIn("group: omega-catalog-sigmascope-exclusive", text)
        self.assertIn("definitions_snapshot.py build", text)
        self.assertIn("--built-from-dev-commit \"$GITHUB_SHA\"", text)
        self.assertIn("cp -a catalog/current-state/catalog catalog/state-catalog", text)
        self.assertIn("scan_queue.py build-seed", text)
        self.assertIn("catalog_state.py assemble", text)
        self.assertIn("catalog_state.py validate", text)
        self.assertIn("--expected-parent-sha \"$expected_parent\"", text)
        self.assertIn("--branch catalog-data", text)
        self.assertIn("sigmascope-drain-wake.yml", text)
        self.assertNotIn("build_sqlite_catalog.py", text)
        self.assertNotIn("freeze_inputs.py", text)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import unittest

import common


class DeltaScope42117ConsolidationTests(unittest.TestCase):
    def test_operations_extensions_install_in_layered_order(self) -> None:
        source = (common.ROOT / "tools" / "security" / "deltascope.py").read_text(encoding="utf-8")
        names = [
            "deltascope_live_operations.install()",
            "deltascope_operations_history.install()",
            "deltascope_operations_correlation.install()",
            "deltascope_operations_diagnostics.install()",
        ]
        positions = [source.index(name) for name in names]
        self.assertEqual(sorted(positions), positions)

    def test_release_identity_is_4_21_17(self) -> None:
        root = common.ROOT
        contract = json.loads((root / "deltascope" / "runtime-contract.json").read_text(encoding="utf-8"))
        view = (root / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        desktop = (root / "desktop" / "cmd" / "deltascope-desktop" / "main.go").read_text(encoding="utf-8")
        self.assertEqual("4.21.17", contract["runtime"]["deltascopeVersion"])
        self.assertIn('server_version = "OmegaDeltaScope/4.21.17"', view)
        self.assertIn('var version = "4.21.17-dev"', desktop)

    def test_operations_docs_cover_4_21_17_layers(self) -> None:
        docs = (common.ROOT / "docs" / "operations" / "README.md").read_text(encoding="utf-8")
        self.assertIn("Retained operations history and correlation", docs)
        self.assertIn("sanitized `omega.actions.telemetry.v1`", docs)
        self.assertIn("exact-variant Detection Coverage", docs)
        self.assertIn("Operations diagnostics", docs)

    def test_desktop_docs_keep_managed_updater_as_planned_work(self) -> None:
        docs = (common.ROOT / "docs" / "platform" / "DESKTOP-SHELL.md").read_text(encoding="utf-8")
        self.assertIn("Planned managed DeltaScope source updater", docs)
        self.assertIn("should **not** require a new Go build", docs)
        self.assertIn("desktop/assets/deltascope.ico", docs)
        self.assertIn("planned work, not current behavior", docs)


if __name__ == "__main__":
    unittest.main()

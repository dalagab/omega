from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "desktop" / "window_host.py"


class DeltaScopeWindowsIconCallbackTests(unittest.TestCase):
    def source(self) -> str:
        return HELPER.read_text(encoding="utf-8")

    def test_before_show_handler_uses_pywebview_window_injection_contract(self) -> None:
        source = self.source()
        tree = ast.parse(source)
        handlers = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "before_show"
        ]
        self.assertEqual(1, len(handlers))
        self.assertEqual(["window"], [arg.arg for arg in handlers[0].args.args])
        self.assertIn("window.events.before_show += before_show", source)
        self.assertNotIn("lambda current_window", source)

    def test_native_form_icon_is_set_before_hwnd_fallback(self) -> None:
        source = self.source()
        self.assertIn("from System.Drawing import Icon", source)
        self.assertIn("native.Icon = Icon(str(path))", source)
        self.assertIn("WM_SETICON", source)
        self.assertIn("ICON_BIG", source)
        self.assertIn("ICON_SMALL", source)

    def test_windows_identity_is_established_before_pywebview_import(self) -> None:
        source = self.source()
        self.assertIn(
            'if not args.probe:\n        set_windows_identity()\n\n    try:\n        import webview',
            source,
        )

    def test_icon_application_is_observable_in_desktop_log(self) -> None:
        source = self.source()
        self.assertIn("DeltaScope Desktop icon source:", source)
        self.assertIn("DeltaScope Desktop native icon:", source)
        self.assertIn("WinForms icon assignment failed", source)
        self.assertIn("HWND icon assignment failed", source)


if __name__ == "__main__":
    unittest.main()

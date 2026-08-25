from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

import common


LAUNCHER = common.ROOT / "deltascope.py"
_spec = importlib.util.spec_from_file_location("omega_root_deltascope_launcher", LAUNCHER)
assert _spec and _spec.loader
launcher = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(launcher)


class DeltaScopeRootLauncherTests(unittest.TestCase):
    def test_root_launchers_exist(self) -> None:
        self.assertTrue(LAUNCHER.is_file())
        self.assertTrue((common.ROOT / "deltascope.cmd").is_file())
        self.assertTrue((common.ROOT / "deltascope.sh").is_file())

    def test_runtime_dependencies_are_owned_by_deltascope(self) -> None:
        self.assertEqual(common.ROOT / "deltascope" / "requirements.txt", launcher.REQUIREMENTS)
        self.assertNotEqual(common.ROOT / "tools" / "requirements-security.txt", launcher.REQUIREMENTS)
        self.assertTrue(launcher.REQUIREMENTS.is_file())

    def test_default_launch_is_online_workbench(self) -> None:
        self.assertEqual(["serve-online"], launcher.delta_args([]))
        self.assertEqual(["serve-online", "--no-browser"], launcher.delta_args(["--no-browser"]))
        self.assertEqual(["audit", "--json"], launcher.delta_args(["audit", "--json"]))
        self.assertEqual(["--help"], launcher.delta_args(["--help"]))

    def test_requirement_digest_invalidates_private_runtime_marker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-deltascope-launcher-") as td:
            root = Path(td)
            venv_dir = root / "venv"
            requirements = root / "requirements.txt"
            requirements.write_text("PyYAML==6.0.3\n", encoding="utf-8")
            python = launcher._venv_python(venv_dir)
            python.parent.mkdir(parents=True)
            python.write_text("", encoding="utf-8")
            marker = venv_dir / launcher.MARKER.name
            marker.write_text(launcher._requirements_digest(requirements) + "\n", encoding="utf-8")
            self.assertFalse(launcher._needs_bootstrap(venv_dir, requirements))
            requirements.write_text("PyYAML==6.0.4\n", encoding="utf-8")
            self.assertTrue(launcher._needs_bootstrap(venv_dir, requirements))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import unittest

import common


class DeltaScopeDesktopShellTests(unittest.TestCase):
    def test_go_desktop_shell_is_packaged_as_outer_runtime(self) -> None:
        root = common.ROOT
        expected = [
            root / "desktop" / "go.mod",
            root / "desktop" / "requirements.txt",
            root / "desktop" / "window_host.py",
            root / "desktop" / "cmd" / "deltascope-desktop" / "main.go",
            root / "desktop" / "internal" / "backend" / "backend.go",
            root / "desktop" / "internal" / "download" / "manager.go",
            root / "desktop" / "internal" / "host" / "server.go",
            root / "desktop" / "internal" / "processutil" / "quiet_windows.go",
            root / "desktop" / "internal" / "processutil" / "quiet_other.go",
            root / "desktop" / "internal" / "window" / "window.go",
            root / "deltascope-desktop.cmd",
            root / "deltascope-desktop.sh",
            root / "docs" / "platform" / "DESKTOP-SHELL.md",
        ]
        for path in expected:
            self.assertTrue(path.is_file(), path)

    def test_desktop_shell_does_not_replace_python_authority_contract(self) -> None:
        contract = json.loads((common.ROOT / "deltascope" / "runtime-contract.json").read_text(encoding="utf-8"))
        self.assertEqual("python", contract["runtime"]["language"])
        shell = contract["desktopShell"]
        self.assertEqual("go", shell["language"])
        self.assertEqual("loopback-reverse-proxy", shell["frontDoor"])
        self.assertFalse(shell["securityAuthority"])
        self.assertFalse(shell["browserDownloaderEndpoint"])

    def test_universal_downloader_is_not_exposed_to_browser(self) -> None:
        host = (common.ROOT / "desktop" / "internal" / "host" / "server.go").read_text(encoding="utf-8")
        downloader = (common.ROOT / "desktop" / "internal" / "download" / "manager.go").read_text(encoding="utf-8")
        self.assertIn("download URL must use HTTPS", downloader)
        self.assertIn("SHA-256 mismatch", downloader)
        self.assertNotIn("/__deltascope/download", host)

    def test_desktop_version_matches_python_ui(self) -> None:
        view = (common.ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        self.assertIn('server_version = "OmegaDeltaScope/4.21.12"', view)
        contract = json.loads((common.ROOT / "deltascope" / "runtime-contract.json").read_text(encoding="utf-8"))
        self.assertEqual("4.21.12", contract["runtime"]["deltascopeVersion"])



    def test_windows_desktop_launch_is_quiet_by_default(self) -> None:
        root = common.ROOT
        windows_process = (root / "desktop" / "internal" / "processutil" / "quiet_windows.go").read_text(encoding="utf-8")
        build = (root / "desktop" / "build.ps1").read_text(encoding="utf-8")
        main = (root / "desktop" / "cmd" / "deltascope-desktop" / "main.go").read_text(encoding="utf-8")
        backend = (root / "desktop" / "internal" / "backend" / "backend.go").read_text(encoding="utf-8")
        runtime = (root / "desktop" / "internal" / "backend" / "runtime.go").read_text(encoding="utf-8")
        window = (root / "desktop" / "internal" / "window" / "window.go").read_text(encoding="utf-8")
        wrapper = (root / "deltascope-desktop.cmd").read_text(encoding="utf-8")
        self.assertIn("createNoWindow = 0x08000000", windows_process)
        self.assertIn("HideWindow = true", windows_process)
        self.assertIn("-H windowsgui", build)
        self.assertIn("DeltaScope-console.exe", build)
        self.assertIn("main.buildFlavor=gui", build)
        self.assertIn('filepath.Join(cache, "Omega", "DeltaScope", "logs")', main)
        self.assertIn('buildFlavor == "gui"', main)
        self.assertIn("processutil.HideWindow(cmd)", backend)
        self.assertGreaterEqual(runtime.count("processutil.HideWindow(cmd)"), 4)
        self.assertGreaterEqual(window.count("processutil.HideWindow(cmd)"), 3)
        self.assertIn(r'start "" "%~dp0dist\DeltaScope.exe"', wrapper)
        contract = json.loads((root / "deltascope" / "runtime-contract.json").read_text(encoding="utf-8"))
        self.assertIn("CREATE_NO_WINDOW", contract["desktopShell"]["windowsProcessModel"])

    def test_windows_native_window_is_preferred_with_safe_browser_fallback(self) -> None:
        root = common.ROOT
        helper = (root / "desktop" / "window_host.py").read_text(encoding="utf-8")
        requirements = (root / "desktop" / "requirements.txt").read_text(encoding="utf-8")
        launcher = (root / "desktop" / "internal" / "window" / "window.go").read_text(encoding="utf-8")
        view = (root / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        self.assertIn("pywebview==6.2.1", requirements)
        self.assertIn('start_kwargs["gui"] = "edgechromium"', helper)
        self.assertIn("SetCurrentProcessExplicitAppUserModelID", helper)
        self.assertIn("png_to_ico", helper)
        self.assertIn("WM_SETICON", helper)
        self.assertIn("LoadImageW", helper)
        self.assertIn("apply_windows_window_icon", helper)
        self.assertIn("window.events.before_show", helper)
        self.assertIn('Engine: "pywebview/edgechromium"', launcher)
        self.assertIn("(app-mode fallback)", launcher)
        self.assertIn('filepath.Join(root, "images", "title-icon.png")', launcher)
        self.assertIn("--icon", (root / "desktop" / "cmd" / "deltascope-desktop" / "main.go").read_text(encoding="utf-8"))
        self.assertIn("DeltaScope 4.21.12 fixed navigation rail", view)
        self.assertIn("#perspectiveNav{overflow:hidden!important", view)



if __name__ == "__main__":
    unittest.main()

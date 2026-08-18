import json
import pathlib
import tempfile
import unittest
import zipfile
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "release"))
import generate_pluginmaster  # noqa: E402


class ReleasePluginMasterTests(unittest.TestCase):
    def test_generated_manifest_uses_packaged_version_and_immutable_tag_asset(self):
        template = json.loads((ROOT / "repository" / "pluginmaster.template.json").read_text(encoding="utf-8"))[0]
        packaged = {
            "Author": "Dalagab Group",
            "Name": "Omega",
            "InternalName": "DalagabOmega",
            "AssemblyVersion": "0.9.10.0",
            "DalamudApiLevel": 15,
        }
        result = generate_pluginmaster.generate(template, packaged, "v0.9.10", "Release notes")
        self.assertEqual("0.9.10.0", result["AssemblyVersion"])
        self.assertEqual(
            "https://github.com/dalagab/omega/releases/download/v0.9.10/Omega.zip",
            result["DownloadLinkInstall"],
        )
        self.assertEqual(result["DownloadLinkInstall"], result["DownloadLinkUpdate"])
        self.assertEqual("Release notes", result["Changelog"])

    def test_generator_rejects_tag_package_version_mismatch(self):
        template = json.loads((ROOT / "repository" / "pluginmaster.template.json").read_text(encoding="utf-8"))[0]
        packaged = {
            "Author": "Dalagab Group",
            "Name": "Omega",
            "InternalName": "DalagabOmega",
            "AssemblyVersion": "0.8.82.0",
            "DalamudApiLevel": 15,
        }
        with self.assertRaisesRegex(ValueError, "does not match release tag"):
            generate_pluginmaster.generate(template, packaged, "v0.9.10", "Release notes")

    def test_package_reader_requires_exactly_one_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = pathlib.Path(tmp) / "Omega.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("DalagabOmega.json", json.dumps({"AssemblyVersion": "0.9.10.0"}))
            manifest = generate_pluginmaster._read_packaged_manifest(package)
            self.assertEqual("0.9.10.0", manifest["AssemblyVersion"])


if __name__ == "__main__":
    unittest.main()

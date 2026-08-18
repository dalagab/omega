import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class ProductionReleaseHygieneTests(unittest.TestCase):
    def test_operator_only_material_is_not_in_production_tree(self):
        session_doc = "SESSION_" + "STARTER.md"
        operator_dir = "hand" + "over"
        self.assertFalse((ROOT / session_doc).exists())
        self.assertFalse((ROOT / operator_dir).exists())

    def test_release_metadata_is_synchronized_and_release_oriented(self):
        csproj = (ROOT / "Omega" / "DalagabOmega.csproj").read_text(encoding="utf-8")
        build_info = (ROOT / "Omega" / "BuildInfo.cs").read_text(encoding="utf-8")
        legacy_manifest = json.loads((ROOT / "repository" / "pluginmaster.json").read_text(encoding="utf-8"))[0]
        template = json.loads((ROOT / "repository" / "pluginmaster.template.json").read_text(encoding="utf-8"))[0]

        match = re.search(r"<Version>([^<]+)</Version>", csproj)
        self.assertIsNotNone(match)
        version = match.group(1)
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertIn(f'Version = "{version}"', build_info)
        self.assertIn(f'BuildStamp = "omega-{version}"', build_info)

        # Work builds intentionally do not advance the public raw-main compatibility feed.
        # That feed must instead be self-consistent with one immutable tagged package.
        release_url = legacy_manifest["DownloadLinkInstall"]
        release_match = re.search(r"/releases/download/v(\d+\.\d+\.\d+)/Omega\.zip$", release_url)
        self.assertIsNotNone(release_match)
        self.assertEqual(f"{release_match.group(1)}.0", legacy_manifest["AssemblyVersion"])
        self.assertEqual(release_url, legacy_manifest["DownloadLinkUpdate"])
        self.assertNotIn("/omega-latest/Omega.zip", release_url)
        self.assertEqual("", template["AssemblyVersion"])
        self.assertEqual("", template["DownloadLinkInstall"])
        self.assertEqual("", template["DownloadLinkUpdate"])

    def test_public_release_docs_do_not_describe_omega_as_nonproduction(self):
        public_files = [
            ROOT / "README.md",
            ROOT / "SECURITY.md",
            ROOT / "EULA.md",
            ROOT / "repository" / "README.md",
            ROOT / "installer" / "README.md",
        ]
        # ZipRunner/GitHub source packages deliberately omit the generated root catalog/ tree.
        # When validating a full workflow checkout, its authored catalog documentation is still checked.
        public_files.extend(path for path in (
            ROOT / "catalog" / "README.md",
            ROOT / "catalog" / "WORKFLOW.md",
        ) if path.exists())
        forbidden_terms = [
            "stag" + "ing",
            "develop" + "ment build",
            "develop" + "ment phase",
            "prototype",
            "pre-release",
            "pre release",
        ]
        forbidden = re.compile(r"\b(?:" + "|".join(map(re.escape, forbidden_terms)) + r")\b", re.I)
        for path in public_files:
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(forbidden.search(text), f"non-production wording in {path.relative_to(ROOT)}")


if __name__ == "__main__":
    unittest.main()

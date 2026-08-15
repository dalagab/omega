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
        manifest = json.loads((ROOT / "repository" / "pluginmaster.json").read_text(encoding="utf-8"))[0]

        match = re.search(r"<Version>([^<]+)</Version>", csproj)
        self.assertIsNotNone(match)
        version = match.group(1)
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertEqual(version, manifest["AssemblyVersion"])
        self.assertIn(f'Version = "{version}"', build_info)
        self.assertIn(f'BuildStamp = "omega-{version}"', build_info)

    def test_public_release_docs_do_not_describe_omega_as_nonproduction(self):
        public_files = [
            ROOT / "README.md",
            ROOT / "SECURITY.md",
            ROOT / "EULA.md",
            ROOT / "catalog" / "README.md",
            ROOT / "catalog" / "WORKFLOW.md",
            ROOT / "repository" / "README.md",
            ROOT / "installer" / "README.md",
        ]
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

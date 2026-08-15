import pathlib
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[2]
class PublicSiteContractTests(unittest.TestCase):
    def test_pages_workflow_and_site_sources_are_packaged(self):
        workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        for path in (ROOT/"site"/"index.html", ROOT/"package.json", ROOT/"package-lock.json", ROOT/"tools"/"site"/"build_site.py", ROOT/"tools"/"site"/"validate_site.py"):
            self.assertTrue(path.is_file(), str(path))
        self.assertIn("npm ci --no-audit --no-fund", workflow)
        self.assertIn("python tools/site/build_site.py", workflow)
        self.assertIn("python tools/site/validate_site.py", workflow)
        self.assertIn("actions/deploy-pages@v4", workflow)
    def test_site_keeps_marketplace_discovery_in_game(self):
        index = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
        self.assertIn("The marketplace stays in game.", index)
        self.assertIn("does not expose a browsable copy of the plugin database", index)
if __name__ == "__main__":
    unittest.main()

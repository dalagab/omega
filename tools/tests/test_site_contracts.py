import pathlib
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[2]
class PublicSiteContractTests(unittest.TestCase):
    def test_pages_workflow_and_site_sources_are_packaged(self):
        workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        for path in (ROOT/"site"/"index.html", ROOT/"site"/"about.html", ROOT/"package.json", ROOT/"package-lock.json", ROOT/"tools"/"site"/"build_site.py", ROOT/"tools"/"site"/"validate_site.py"):
            self.assertTrue(path.is_file(), str(path))
        self.assertIn("npm ci --no-audit --no-fund", workflow)
        self.assertIn("python tools/site/build_site.py", workflow)
        self.assertIn("python tools/site/validate_site.py", workflow)
        self.assertIn("actions/deploy-pages@v4", workflow)
        self.assertIn("branches: [website]", workflow)
        self.assertIn("if: github.ref_name == 'website'", workflow)
        self.assertIn("ref: website", workflow)
        self.assertNotIn("branches: [main]", workflow)
    def test_homepage_leads_with_marketplace_and_integrated_security(self):
        index = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Dalamud Plugin Marketplace &amp; Security Scanner", index)
        self.assertIn("in-game Dalamud plugin marketplace with integrated security scanning", index)
        self.assertIn("Your plugin marketplace.", index)
        self.assertIn("Security intelligence included.", index)
        self.assertIn('property="og:title"', index)
        self.assertNotIn("Gather the evidence. Choose your own trial.", index)

    def test_site_keeps_marketplace_discovery_in_game(self):
        index = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
        self.assertIn("No giant plugin dump on a random website.", index)
        self.assertIn("That is where Omega is useful, not in another browser tab.", index)
        self.assertIn("We believe informed consent is better than ignorance.", index)
        self.assertIn('href="faq.html"', index)

    def test_faq_explains_deterministic_non_ai_scanning(self):
        faq = (ROOT / "site" / "faq.html").read_text(encoding="utf-8")
        self.assertIn("There are no models, LLMs, or AI verdicts in the scanner.", faq)
        self.assertIn("No fleshbags were harmed in the making of this software.", faq)
        self.assertIn("Toni: Omega does not, I however am not so picky", faq)
        self.assertIn("Has AI been used in the production of Omega?", faq)

    def test_security_page_explains_the_record_and_its_limits(self):
        security = (ROOT / "site" / "security.html").read_text(encoding="utf-8")
        self.assertIn("Omega keeps the receipts.", security)
        self.assertIn("A security record, not a verdict", security)
        self.assertIn("No models, LLMs, or AI verdicts are used in the scanner.", security)

    def test_install_page_uses_the_normal_dalamud_flow(self):
        install = (ROOT / "site" / "install.html").read_text(encoding="utf-8")
        self.assertIn("Install Omega through Dalamud.", install)
        self.assertIn("Omega never replaces the install, update, disable, or removal flow", install)
        self.assertNotIn("{{OMEGA_VERSION}}", install)

    def test_features_page_uses_the_shared_product_story(self):
        features = (ROOT / "site" / "features.html").read_text(encoding="utf-8")
        self.assertIn("More to look at.", features)
        self.assertIn("Omega finds it. Dalamud installs it.", features)
        self.assertIn("assets/screenshots/product-provenance.png", features)

    def test_about_page_introduces_the_dalabag_group(self):
        about = (ROOT / "site" / "about.html").read_text(encoding="utf-8")
        self.assertIn("The Dalabag Group.", about)
        self.assertIn("more than 20 years of professional R&amp;D experience in defensive security", about)
        self.assertIn("A curated gate cannot also map the whole Rift.", about)
        self.assertIn("informed consent is better than ignorance", about)
        self.assertIn("What Omega adds", about)
        self.assertIn("We are players too, and we believe you deserve a clear view", about)
if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import sqlite3
import sys
import unittest
from contextlib import closing

import common
import build_sqlite_catalog
import scrape_websites

RELEASE_TOOLS = common.ROOT / "tools" / "release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

import extract_changelog  # noqa: E402
import finalize_changelog  # noqa: E402


class OmegaMetadataAndReleaseTests(unittest.TestCase):
    def test_omega_index_accepts_https_and_repository_relative_banner_urls(self) -> None:
        relative = scrape_websites.parse_omega_index(
            json.dumps({"SchemaVersion": 1, "OmegaBannerUrl": "images/banner.png"}).encode(),
            "example",
            "plugin",
            "main",
        )
        self.assertEqual(
            "https://raw.githubusercontent.com/example/plugin/main/images/banner.png",
            relative["OmegaBannerUrl"],
        )

        blob = scrape_websites.parse_omega_index(
            json.dumps({
                "SchemaVersion": 1,
                "OmegaBannerUrl": "https://github.com/example/plugin/blob/main/.omega/banner.webp",
                "FutureIndexHint": "preserved",
            }).encode(),
            "example",
            "plugin",
            "main",
        )
        self.assertEqual(
            "https://raw.githubusercontent.com/example/plugin/main/.omega/banner.webp",
            blob["OmegaBannerUrl"],
        )
        self.assertEqual("preserved", blob["FutureIndexHint"])

    def test_omega_index_rejects_insecure_or_unsupported_metadata(self) -> None:
        insecure = scrape_websites.parse_omega_index(
            json.dumps({"SchemaVersion": 1, "OmegaBannerUrl": "http://example.invalid/banner.png"}).encode(),
            "example",
            "plugin",
            "main",
        )
        self.assertNotIn("OmegaBannerUrl", insecure)
        self.assertEqual({}, scrape_websites.parse_omega_index(
            json.dumps({"SchemaVersion": 99, "OmegaBannerUrl": "images/banner.png"}).encode(),
            "example",
            "plugin",
            "main",
        ))

    def test_builder_persists_omega_index_and_projects_banner(self) -> None:
        with closing(sqlite3.connect(":memory:")) as db:
            db.row_factory = sqlite3.Row
            db.executescript(build_sqlite_catalog.SCHEMA_SQL)
            build_sqlite_catalog.import_websites(db, {"repos": {
                "https://github.com/example/plugin": {
                    "url": "https://github.com/example/plugin",
                    "ok": True,
                    "omegaIndex": {
                        "SchemaVersion": 1,
                        "OmegaBannerUrl": "https://cdn.example.invalid/banner.png",
                        "FutureIndexHint": "preserved",
                    },
                    "omegaBannerUrl": "https://cdn.example.invalid/banner.png",
                },
            }}, "2026-08-17T00:00:00Z")
            row = db.execute(
                "SELECT omega_index_json,omega_banner_url FROM websites"
            ).fetchone()
        self.assertEqual("https://cdn.example.invalid/banner.png", row["omega_banner_url"])
        self.assertEqual("preserved", json.loads(row["omega_index_json"])["FutureIndexHint"])

    def test_repository_metadata_reference_and_ui_contracts_exist(self) -> None:
        omega_index = json.loads((common.ROOT / ".omega" / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(1, omega_index["SchemaVersion"])
        self.assertIn("images/omega-banner.png", omega_index["OmegaBannerUrl"])
        self.assertTrue((common.ROOT / "images" / "omega-banner.png").is_file())
        self.assertTrue((common.ROOT / "images" / "sigmascope-banner.png").is_file())

        model = (common.ROOT / "Omega" / "Models" / "MarketplacePlugin.cs").read_text(encoding="utf-8")
        store = (common.ROOT / "Omega" / "Services" / "SqliteCatalogStore.cs").read_text(encoding="utf-8")
        product = (common.ROOT / "Omega" / "UI" / "MarketplaceWindow.ProductPage.cs").read_text(encoding="utf-8")
        about = (common.ROOT / "Omega" / "UI" / "MarketplaceWindow.Security.cs").read_text(encoding="utf-8")
        project = (common.ROOT / "Omega" / "DalagabOmega.csproj").read_text(encoding="utf-8")
        self.assertIn("OmegaBannerUrl", model)
        self.assertIn("omega_banner_url", store)
        self.assertIn("DrawProductHeroBanner", product)
        self.assertIn("iconCache.GetOrQueue(plugin.OmegaBannerUrl)", product)
        self.assertIn("translucent", product)
        self.assertIn("DrawAboutSigmascopeFeature", about)
        self.assertIn("sigmascopeBannerTexture", about)
        self.assertIn("Sigmascope is Omega's online scanning engine", about)
        self.assertIn("sends the results to Omega in Definitions packages", about)
        self.assertIn("Definitions also carry Omega's plugin listings", about)
        self.assertNotIn("Omega's static evidence-gathering engine", about)
        self.assertIn("sigmascope-banner.png", project)

    def test_release_notes_use_unreleased_until_tag_is_finalized(self) -> None:
        text = """# Changelog\n\n## [Unreleased]\n\n<sub>work build: 0.8.93</sub>\n\n### Added\n- Banner metadata.\n\n## [0.8.92] - 2026-08-17\n\n- Previous.\n"""
        notes = extract_changelog.extract(text, "0.8.93")
        self.assertIn("work build: 0.8.93", notes)
        self.assertIn("Banner metadata", notes)

        finalized = finalize_changelog.finalize(text, "0.8.93", "2026-08-17")
        self.assertIn("## [Unreleased]", finalized)
        self.assertIn("## [0.8.93] - 2026-08-17", finalized)
        self.assertEqual(finalized, finalize_changelog.finalize(finalized, "0.8.93", "2026-08-17"))
        self.assertIn("Banner metadata", extract_changelog.extract(finalized, "0.8.93"))

    def test_repository_changelog_is_pending_not_work_build_versioned(self) -> None:
        changelog = (common.ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [Unreleased]", changelog)
        self.assertIn("<sub>work build: 0.8.95</sub>", changelog)
        self.assertIn("<sub>work build: 0.8.94</sub>", changelog)
        self.assertIn("<sub>work build: 0.8.93</sub>", changelog)
        self.assertNotIn("## [0.8.95]", changelog)
        self.assertNotIn("## [0.8.94]", changelog)
        release = (common.ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("finalize_changelog.py", release)
        self.assertIn("Default branch '$defaultBranch' moved beyond tagged commit", release)


if __name__ == "__main__":
    unittest.main()

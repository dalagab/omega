from __future__ import annotations

import json
import datetime as dt
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import common  # noqa: F401
import build_sqlite_catalog
import collect_sources
import compact_sqlite_catalog
import enrich_metadata
import scrape_websites
import scrape_websites_incremental
import security_scan


class CatalogPythonUnitTests(unittest.TestCase):
    def test_curated_source_loader_rejects_non_https_entries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "curated.json"
            path.write_text(json.dumps([
                {"id": "good", "name": "Good", "url": "https://example.invalid/repo.json"},
                {"id": "bad", "name": "Bad", "url": "http://example.invalid/repo.json"},
                {"id": "empty", "url": ""},
            ]), encoding="utf-8")
            rows = collect_sources.collect_curated_file(str(path))
        self.assertEqual(1, len(rows))
        self.assertEqual("Good", rows[0]["provider"])
        self.assertEqual("curated-sources.json", rows[0]["discoveredBy"])

    def test_punish_discovery_deduplicates_publisher_slugs(self) -> None:
        html = b'<a href="/directory/alpha"></a><a href="/directory/alpha"></a><a href="/directory/beta"></a>'
        with mock.patch.object(collect_sources, "http_get", return_value=html):
            rows = collect_sources.collect_punish_publisher_urls()
        self.assertEqual(["puni.sh-studio", "alpha", "beta"], [row["provider"] for row in rows])

    def test_enrichment_accepts_nested_pluginmaster_and_preserves_raw_manifest(self) -> None:
        raw = {
            "Author": "Omega",
            "Name": "Example",
            "InternalName": "Example",
            "Punchline": "Useful",
            "Description": "A sufficiently long description used for deterministic metadata testing.",
            "RepoUrl": "https://example.invalid/project",
            "AssemblyVersion": "1.2.3.4",
            "DalamudApiLevel": 15,
            "FutureField": "preserved",
        }
        extracted = enrich_metadata._extract_plugin_list({"data": {"plugins": [raw]}})
        self.assertEqual([raw], extracted)
        normalized = enrich_metadata._normalize_plugin(raw)
        self.assertTrue(enrich_metadata._is_metadata_complete(normalized))
        self.assertEqual("preserved", normalized["rawManifest"]["FutureField"])

    def test_enrichment_accepts_pluginmaster_trailing_commas_without_touching_strings(self) -> None:
        source = {"url": "https://example.invalid/repo.json", "provider": "Community"}
        body = b'''[
          {
            "Author": "Pyon",
            "Name": "PartyPyon",
            "InternalName": "PartyPyon",
            "Punchline": "Automatically recreate party finder listing.",
            "Description": "Automatically recreate party finder listing while preserving text such as comma,} literally.",
            "AssemblyVersion": "1.0.5.0",
            "DalamudApiLevel": 15,
            "RepoUrl": "https://example.invalid/project",
            "DownloadLinkUpdate": "https://example.invalid/PartyPyon.zip",
          },
        ]'''
        with mock.patch.object(enrich_metadata, "http_get", return_value=(200, body, {})):
            row = enrich_metadata.fetch_source(source)

        self.assertTrue(row["ok"], row["error"])
        self.assertEqual(1, row["pluginCount"])
        self.assertEqual("PartyPyon", row["plugins"][0]["internalName"])
        self.assertIn("comma,}", row["plugins"][0]["description"])
        self.assertEqual("https://example.invalid/PartyPyon.zip", row["plugins"][0]["rawManifest"]["DownloadLinkUpdate"])

    def test_enrichment_trailing_comma_tolerance_does_not_accept_other_malformed_json(self) -> None:
        source = {"url": "https://example.invalid/broken.json", "provider": "Broken"}
        body = b'[{"Name":"Broken","InternalName":"Broken",,}]'
        with mock.patch.object(enrich_metadata, "http_get", return_value=(200, body, {})):
            row = enrich_metadata.fetch_source(source)

        self.assertFalse(row["ok"])
        self.assertEqual(0, row["pluginCount"])
        self.assertIn("Non-JSON response:", row["error"])

    def test_conditional_manifest_304_preserves_cache_metadata(self) -> None:
        source = {"url": "https://example.invalid/repo.json", "provider": "Example"}
        cache = {source["url"]: {"etag": '"abc"', "last_modified": "yesterday", "content_sha256": "deadbeef"}}
        with mock.patch.object(enrich_metadata, "http_get", return_value=(304, b"", {})):
            row = enrich_metadata.fetch_source(source, cache=cache)
        self.assertTrue(row["ok"])
        self.assertTrue(row["notModified"])
        self.assertEqual('"abc"', row["etag"])
        self.assertEqual("deadbeef", row["contentSha256"])
        self.assertEqual([], row["plugins"])


    def test_github_tree_links_use_repository_api_identity(self) -> None:
        self.assertEqual(
            ("TheNickoos", "FFXIVPluginRepo"),
            scrape_websites.parse_github_repo("https://github.com/TheNickoos/FFXIVPluginRepo/tree/main"),
        )
        self.assertEqual(
            "https://github.com/TheNickoos/FFXIVPluginRepo",
            scrape_websites.canonical_github_repo_url(("TheNickoos", "FFXIVPluginRepo")),
        )

    def test_github_tree_link_enrichment_is_mapped_back_to_manifest_alias(self) -> None:
        plugin = {
            "internalName": "DalamudRepoInfo",
            "name": "DalamudRepoInfo",
            "repoUrl": "https://github.com/TheNickoos/FFXIVPluginRepo/tree/main",
        }
        record = {
            "url": "https://github.com/TheNickoos/FFXIVPluginRepo",
            "ok": True,
            "title": "FFXIVPluginRepo",
            "description": "This is my personal big mod list for Final Fantasy XIV.",
            "imageUrls": [],
        }
        with mock.patch.object(scrape_websites, "scrape_github_repo", return_value=record):
            out = scrape_websites.scrape_all({"plugins": [plugin]}, token=None, concurrency=1, verbose=False)
        alias = plugin["repoUrl"]
        self.assertIn(alias, out["repos"])
        self.assertEqual(alias, out["repos"][alias]["url"])
        self.assertEqual("https://github.com/TheNickoos/FFXIVPluginRepo", out["repos"][alias]["canonicalUrl"])
        self.assertTrue(out["plugins"][0]["webEnriched"])
        self.assertEqual(record["description"], out["plugins"][0]["website"]["description"])

    def test_http_diagnostics_are_rejected_from_presentation_text(self) -> None:
        poisoned = "404:\n- https://example.invalid/a at line 1\n- https://example.invalid/b at line 1\n\n500:\n- https://example.invalid/c"
        self.assertTrue(scrape_websites.looks_like_http_diagnostic(poisoned))
        self.assertIsNone(scrape_websites.sanitize_presentation_text(poisoned))
        self.assertEqual(
            "A normal project description.",
            scrape_websites.sanitize_presentation_text("A normal project description."),
        )

    def test_incremental_website_cache_rejects_poisoned_presentation_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "seed.sqlite"
            now = dt.datetime.now(dt.timezone.utc).isoformat()
            with closing(sqlite3.connect(path)) as db:
                db.executescript("""
                    CREATE TABLE websites(
                        url TEXT, ok INTEGER, last_success_utc TEXT, metadata_json TEXT,
                        description TEXT, homepage TEXT, stars INTEGER, forks INTEGER, watchers INTEGER,
                        language TEXT, license TEXT, default_branch TEXT, last_commit_utc TEXT,
                        readme_excerpt TEXT, topics_json TEXT, image_urls_json TEXT
                    );
                """)
                db.execute(
                    "INSERT INTO websites VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "https://github.com/example/repo/tree/main", 1, now, "{}",
                        "404:\n- https://example.invalid/missing", "", None, None, None, "", "", "main", "",
                        "", "[]", "[]",
                    ),
                )
            cache = scrape_websites_incremental.load_cache(path, 168.0)
        self.assertEqual({}, cache)

    def test_builder_cleans_seeded_plugin_display_fields_but_preserves_audit_storage_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "seed.sqlite"
            with closing(sqlite3.connect(path)) as db:
                db.row_factory = sqlite3.Row
                db.execute("CREATE TABLE plugin_variants(variant_id INTEGER PRIMARY KEY, punchline TEXT, description TEXT, raw_manifest_json TEXT)")
                raw = json.dumps({"Description": "404:\n- https://example.invalid/a"})
                db.execute("INSERT INTO plugin_variants(punchline,description,raw_manifest_json) VALUES(?,?,?)", (
                    "Information sur ce script",
                    "404:\n- https://example.invalid/a",
                    raw,
                ))
                changed = build_sqlite_catalog.sanitize_seeded_plugin_presentation_fields(db)
                row = db.execute("SELECT punchline,description,raw_manifest_json FROM plugin_variants").fetchone()
            self.assertEqual(1, changed)
            self.assertEqual("Information sur ce script", row[0])
            self.assertEqual("", row[1])
            self.assertEqual(raw, row[2])

    def test_builder_cleans_seeded_http_diagnostics_before_presentation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "seed.sqlite"
            with closing(sqlite3.connect(path)) as db:
                db.row_factory = sqlite3.Row
                db.execute("CREATE TABLE websites(website_id INTEGER PRIMARY KEY, description TEXT, readme_excerpt TEXT)")
                db.execute("INSERT INTO websites(description,readme_excerpt) VALUES(?,?)", (
                    "404:\n- https://example.invalid/a",
                    "500:\n- https://example.invalid/b",
                ))
                changed = build_sqlite_catalog.sanitize_seeded_website_cache(db)
                row = db.execute("SELECT description,readme_excerpt FROM websites").fetchone()
            self.assertEqual(1, changed)
            self.assertEqual("", row[0])
            self.assertEqual("", row[1])

    def test_incremental_scraper_seed_urls_ignore_inactive_variants(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "seed.sqlite"
            with closing(sqlite3.connect(path)) as db:
                db.executescript("""
                    CREATE TABLE plugin_variants(repo_url TEXT, active INTEGER);
                    INSERT INTO plugin_variants VALUES('https://example.invalid/active/',1);
                    INSERT INTO plugin_variants VALUES('https://example.invalid/inactive',0);
                """)
            urls = scrape_websites_incremental.load_seed_repo_urls(path)
        self.assertEqual({"https://example.invalid/active": "https://example.invalid/active"}, urls)

    def test_version_helpers_remain_conservative(self) -> None:
        self.assertGreater(build_sqlite_catalog.version_key("1.10.0"), build_sqlite_catalog.version_key("1.9.9"))
        self.assertTrue(security_scan.version_satisfies("2.5.0", ">=2.0 <3.0"))
        self.assertFalse(security_scan.version_satisfies("3.0.0", ">=2.0 <3.0"))
        self.assertIsNone(security_scan.version_satisfies("2.0.0", "banana"))

    def test_archive_path_normalization_rejects_escape(self) -> None:
        self.assertEqual("folder/plugin.dll", security_scan.normalized_archive_member_name("folder\\plugin.dll"))
        self.assertFalse(security_scan.safe_member_name("../escape.dll"))
        self.assertFalse(security_scan.safe_member_name("C:\\escape.dll"))
        self.assertTrue(security_scan.safe_member_name("folder/plugin.dll"))

    def test_security_resource_ceilings_cover_current_production_cases(self) -> None:
        self.assertGreaterEqual(security_scan.MAX_ARTIFACT_BYTES, 156_649_087)
        self.assertGreaterEqual(security_scan.MAX_ARCHIVE_ENTRIES, 2_342)
        self.assertGreater(security_scan.MAX_ARCHIVE_UNCOMPRESSED, security_scan.MAX_ARTIFACT_BYTES)


    def test_builder_handoff_compression_is_bounded_for_large_evidence_seed(self) -> None:
        source = Path(build_sqlite_catalog.__file__).read_text(encoding="utf-8")
        self.assertIn("compresslevel=6", source)
        self.assertNotIn("compresslevel=9", source)

    def test_compactor_summary_ceiling_is_bounded(self) -> None:
        self.assertEqual(64 * 1024, compact_sqlite_catalog.MAX_SUMMARY_BYTES)
        self.assertEqual("omega.plugin-security.scan-summary.v1", compact_sqlite_catalog.SUMMARY_SCHEMA)

    def test_scan_ledger_suppresses_timestamp_only_revalidation_without_changing_security_identity(self) -> None:
        now = dt.datetime(2026, 8, 15, 12, 0, tzinfo=dt.timezone.utc)
        entry = {
            "status": "complete",
            "scannerVersion": security_scan.SCANNER_VERSION,
            "lastValidatedAtUtc": "2026-08-15T11:00:00Z",
            "assemblyVersion": "1.2.3.4",
            "artifactUrl": "https://example.invalid/plugin.zip",
        }
        self.assertTrue(security_scan.ledger_entry_is_fresh(entry, "1.2.3.4", "https://example.invalid/plugin.zip", now, 168))
        self.assertFalse(security_scan.ledger_entry_is_fresh(entry, "1.2.3.5", "https://example.invalid/plugin.zip", now, 168))
        stale = dict(entry, lastValidatedAtUtc="2026-08-01T00:00:00Z")
        self.assertFalse(security_scan.ledger_entry_is_fresh(stale, "1.2.3.4", "https://example.invalid/plugin.zip", now, 168))


if __name__ == "__main__":
    unittest.main()

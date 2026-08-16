from __future__ import annotations

import base64
import json
import datetime as dt
from collections import defaultdict
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import common  # noqa: F401
import build_sqlite_catalog
import catalog_presentation
import collect_sources
import collect_public_advisories
import compact_sqlite_catalog
import enrich_metadata
import scrape_websites
import scrape_websites_incremental
import security_endpoint_inventory
import security_scan
import security_hash_consensus


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

    def test_github_scraper_captures_bounded_readme_and_project_image_urls(self) -> None:
        project = {"name": "Fixture", "default_branch": "main", "stargazers_count": 0, "forks_count": 0}
        readme = "# Fixture\n![Preview](images/preview.png)\n" + ("x" * 6000)
        encoded = base64.b64encode(readme.encode("utf-8")).decode("ascii")
        with mock.patch.object(scrape_websites, "github_get", side_effect=[project, {"encoding": "base64", "content": encoded}]):
            record = scrape_websites.scrape_github_repo(("example", "fixture"), token=None)
        self.assertEqual(readme, record["readmeExcerpt"])
        self.assertEqual(
            ["https://raw.githubusercontent.com/example/fixture/main/images/preview.png"],
            record["imageUrls"],
        )

    def test_discord_join_images_do_not_consume_project_image_slots(self) -> None:
        widget = "https://discord.com/api/guilds/123456/widget.png?style=banner2"
        readme = "\n".join(
            [f"![Discord]({widget})"]
            + [f"![Preview {index}](images/preview-{index}.png)" for index in range(1, 7)]
        )
        project = {"name": "Fixture", "default_branch": "main", "stargazers_count": 0, "forks_count": 0}
        encoded = base64.b64encode(readme.encode("utf-8")).decode("ascii")
        with mock.patch.object(scrape_websites, "github_get", side_effect=[project, {"encoding": "base64", "content": encoded}]):
            record = scrape_websites.scrape_github_repo(("example", "fixture"), token=None)
        self.assertEqual(scrape_websites.MAX_IMAGES, len(record["imageUrls"]))
        self.assertEqual([widget], record["discordJoinImageUrls"])
        self.assertTrue(record["imageUrls"][-1].endswith("preview-5.png"))

    def test_discord_join_images_are_classified_out_of_project_media(self) -> None:
        widget = "https://discord.com/api/guilds/123456/widget.png?style=banner2"
        preview = "https://example.invalid/preview.png"
        self.assertTrue(catalog_presentation.is_discord_join_image(widget))
        self.assertEqual(([preview], [widget]), catalog_presentation.split_project_image_urls([widget, preview]))

    def test_adult_content_detection_uses_declared_or_explicit_markers(self) -> None:
        self.assertTrue(catalog_presentation.is_adult_content(["NSFW"], ["General utility plugin"]))
        self.assertTrue(catalog_presentation.is_adult_content([], ["An 18+ only plugin."]))
        self.assertFalse(catalog_presentation.is_adult_content([], ["A general utility plugin."]))

    def test_scanner_reports_hard_coded_external_paths_only_with_filesystem_api_evidence(self) -> None:
        hits = defaultdict(list)
        intel = security_scan.empty_dependency_intelligence("source")
        security_scan.scan_source_text("Plugin.cs", b"", 'File.ReadAllText(@"C:\\Users\\Example\\secret.txt");', intel, hits)
        self.assertIn("filesystem.external-path", hits)
        self.assertIn("C:\\Users\\Example\\secret.txt", hits["filesystem.external-path"][0])
        self.assertEqual([], security_scan.external_hard_coded_paths('var path = @"C:\\Users\\Example\\secret.txt";'))

    def test_endpoint_inventory_classifies_hosts_and_redacts_url_queries(self) -> None:
        endpoints = security_endpoint_inventory.endpoint_candidates(
            'new HttpClient().GetStringAsync("https://api.github.com/repos/example?access_token=secret");',
            "source:Plugin.cs",
        )
        self.assertEqual("https://api.github.com/repos/example", endpoints[0]["url"])
        self.assertEqual("recognised-platform", endpoints[0]["classification"])
        findings, capabilities = security_endpoint_inventory.endpoint_findings(endpoints, has_network_capability=True)
        self.assertEqual("informational", findings[0]["severity"])
        self.assertIn("Endpoint: api.github.com", capabilities)

    def test_endpoint_inventory_marks_unknown_and_private_hosts_without_claiming_connections(self) -> None:
        endpoints = security_endpoint_inventory.endpoint_candidates(
            'HttpClient client; client.GetStringAsync("https://collector.example.invalid/v1"); File.ReadAllText("http://127.0.0.1:8080/admin");',
            "artifact:Plugin.dll",
        )
        findings, _capabilities = security_endpoint_inventory.endpoint_findings(endpoints, has_network_capability=True)
        severities = {finding["ruleId"].split(".")[2]: finding["severity"] for finding in findings}
        self.assertEqual("caution", severities["unrecognised-host"])
        self.assertEqual("high", severities["private-or-loopback"])
        self.assertIn("not proof of a runtime connection", findings[0]["description"])

    def test_endpoint_inventory_reports_dynamic_destinations_when_network_target_is_not_literal(self) -> None:
        findings, capabilities = security_endpoint_inventory.endpoint_findings([], has_network_capability=True)
        self.assertEqual("network.endpoint.dynamic-or-undetermined", findings[0]["ruleId"])
        self.assertEqual(["Network destination undetermined"], capabilities)

    def test_cross_source_hash_consensus_marks_an_unshared_artifact(self) -> None:
        with closing(sqlite3.connect(":memory:")) as db:
            db.row_factory = sqlite3.Row
            db.executescript(build_sqlite_catalog.SCHEMA_SQL)
            security_scan.ensure_schema(db)
            db.execute("INSERT INTO plugins(plugin_id,internal_name,canonical_name,first_seen_utc,last_seen_utc,active) VALUES(1,'Fixture','Fixture','','',1)")
            for source_id in range(1, 4):
                db.execute("INSERT INTO sources(source_id,url,name) VALUES(?,?,?)", (source_id, f"https://example.invalid/{source_id}.json", f"Source {source_id}"))
                db.execute("INSERT INTO plugin_variants(variant_id,plugin_id,source_id,source_entry_key,assembly_version,first_seen_utc,last_seen_utc,active) VALUES(?,?,?,?,?,?,?,1)", (source_id, 1, source_id, f"Fixture-{source_id}", "1.0.0", "", ""))
            report = json.dumps({"findings": [], "capabilities": []})
            for variant_id, artifact_hash in ((1, "a" * 64), (2, "a" * 64), (3, "b" * 64)):
                db.execute("INSERT INTO plugin_security_scans(scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_sha256,status,report_json) VALUES(?,?,?,?,?,?,?,?)", (variant_id, 1, variant_id, variant_id, "1.0.0", artifact_hash, "complete", report))
                db.execute("INSERT INTO plugin_security_current(variant_id,scan_id,assembly_version,artifact_sha256,status,report_json) VALUES(?,?,?,?,?,?)", (variant_id, variant_id, "1.0.0", artifact_hash, "complete", report))
            summary = security_hash_consensus.refresh_cross_source_hash_findings(db)
            outlier = db.execute("SELECT highest_severity,findings_json FROM plugin_security_current WHERE variant_id=3").fetchone()
        self.assertEqual(1, summary["groupsWithMismatches"])
        self.assertEqual("high", outlier["highest_severity"])
        self.assertIn("artifact.cross-source-hash-mismatch", outlier["findings_json"])

    def test_public_advisory_collector_normalizes_osv_matches_for_observed_nuget_versions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            database = root / "catalog.sqlite"
            output = root / "public-advisories.json"
            with closing(sqlite3.connect(database)) as db:
                db.executescript("""
                    CREATE TABLE plugin_security_dependencies(scan_id INTEGER,kind TEXT,name TEXT,version TEXT,resolved_version TEXT);
                    CREATE TABLE plugin_security_current(scan_id INTEGER,status TEXT);
                """)
                db.execute("INSERT INTO plugin_security_current VALUES(1,'complete')")
                db.execute("INSERT INTO plugin_security_dependencies VALUES(1,'nuget','Example.Package','1.2.3','')")
                db.commit()
            with mock.patch.object(collect_public_advisories, "post_json", return_value={"results": [{"vulns": [{"id": "GHSA-test"}]}]}), \
                 mock.patch.object(collect_public_advisories, "get_json", return_value={"id": "GHSA-test", "summary": "Example vulnerability", "aliases": ["CVE-2026-0001"], "database_specific": {"severity": "HIGH"}}):
                document = collect_public_advisories.collect(database, output)
        self.assertEqual(1, document["queriedPackages"])
        self.assertEqual(1, document["matchedPackages"])
        advisory = document["advisories"][0]
        self.assertEqual("Example.Package", advisory["name"])
        self.assertEqual(["1.2.3"], advisory["affectedVersions"])
        self.assertEqual("high", advisory["severity"])
        self.assertEqual("CVE-2026-0001", advisory["aliases"][0])

    def test_public_advisory_collector_allows_a_fresh_catalog_without_security_tables(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            database = Path(td) / "catalog.sqlite"
            with closing(sqlite3.connect(database)) as db:
                db.execute("CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY)")
                db.commit()
            self.assertEqual([], collect_public_advisories.observed_nuget_packages(database, 100))

    def test_public_advisory_collector_rejects_incomplete_querybatch_results(self) -> None:
        with mock.patch.object(collect_public_advisories, "post_json", return_value={"results": []}):
            with self.assertRaisesRegex(ValueError, "returned 0 results for 1 queries"):
                collect_public_advisories.osv_ids_for_packages([("Example.Package", "1.2.3")], 1.0)

    def test_builder_persists_readme_content_and_image_urls(self) -> None:
        with closing(sqlite3.connect(":memory:")) as db:
            db.row_factory = sqlite3.Row
            db.executescript(build_sqlite_catalog.SCHEMA_SQL)
            build_sqlite_catalog.import_websites(db, {"repos": {
                "https://github.com/example/fixture": {
                    "url": "https://github.com/example/fixture",
                    "ok": True,
                    "readmeExcerpt": "# Fixture\nProject documentation.",
                    "imageUrls": ["https://raw.githubusercontent.com/example/fixture/main/images/preview.png"],
                    "discordJoinImageUrls": ["https://discord.com/api/guilds/123456/widget.png"],
                },
            }}, "2026-08-16T00:00:00Z")
            row = db.execute("SELECT readme_excerpt,image_urls_json,metadata_json FROM websites").fetchone()
        self.assertEqual("# Fixture\nProject documentation.", row["readme_excerpt"])
        self.assertEqual(
            ["https://raw.githubusercontent.com/example/fixture/main/images/preview.png"],
            json.loads(row["image_urls_json"]),
        )
        self.assertEqual(["https://discord.com/api/guilds/123456/widget.png"], json.loads(row["metadata_json"])["discordJoinImageUrls"])

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

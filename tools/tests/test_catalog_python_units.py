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

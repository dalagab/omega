from __future__ import annotations

import base64
import io
import json
import datetime as dt
from collections import defaultdict
from contextlib import closing
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import common  # noqa: F401
import build_sqlite_catalog
import author_identity
import catalog_presentation
import collect_sources
import create_source_followup_issues
import collect_public_advisories
import compact_sqlite_catalog
import enrich_metadata
import scrape_websites
import scrape_websites_incremental
import security_endpoint_inventory
import sigmascope
import security_hash_consensus
import source_resolution
import source_stability
import sigmascope_source_followups
import process_source_submission


class CatalogPythonUnitTests(unittest.TestCase):
    def test_author_identity_normalization_splits_individual_contributors(self) -> None:
        self.assertEqual(
            ["Inf1", "Sl0nderman", "harbingerftw"],
            author_identity.split_authors("Inf1, Sl0nderman and harbingerftw & Contributors"),
        )
        self.assertEqual(["Kouzukii"], author_identity.split_authors("Kouzukii"))

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

    def test_validated_community_sources_join_discovery_without_becoming_curated(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            curated = root / "curated.json"
            community = root / "community.json"
            curated.write_text(json.dumps([{"id": "curated", "name": "Curated", "url": "https://curated.invalid/repo.json"}]), encoding="utf-8")
            community.write_text(json.dumps([{"id": "community", "name": "Community", "url": "https://community.invalid/repo.json", "enabledByDefault": False}]), encoding="utf-8")
            with mock.patch.object(collect_sources, "collect_punish_publisher_urls", return_value=[]), mock.patch.dict("os.environ", {}, clear=True):
                result = collect_sources.collect(False, str(curated), str(community))
        self.assertEqual(1, result["metadata"]["sourceCounts"]["curated"])
        self.assertEqual(1, result["metadata"]["sourceCounts"]["community"])
        by_url = {row["url"]: row for row in result["sources"]}
        self.assertEqual("community", by_url["https://community.invalid/repo.json"]["kind"])
        self.assertEqual("community-sources.json", by_url["https://community.invalid/repo.json"]["discoveredBy"])

    def test_builder_preserves_community_source_default_disabled_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = build_sqlite_catalog.reset_database(Path(td) / "catalog.sqlite")
            try:
                definitions = build_sqlite_catalog.source_definition_map([
                    {"id": "community-x", "name": "Community X", "url": "https://community.invalid/repo.json", "enabledByDefault": False, "integrateWithDalamudByDefault": False}
                ])
                build_sqlite_catalog.upsert_sources(
                    db,
                    {"sources": [{"url": "https://community.invalid/repo.json", "provider": "Community X", "kind": "community", "discoveredBy": "community-sources.json"}]},
                    definitions,
                    "2026-08-16T00:00:00Z",
                )
                row = db.execute("SELECT enabled_by_default,integrate_with_dalamud,kind,discovered_by FROM sources WHERE url=?", ("https://community.invalid/repo.json",)).fetchone()
            finally:
                db.close()
        self.assertEqual((0, 0, "community", "community-sources.json"), tuple(row))

    def test_source_resolution_derives_github_repository_and_stable_override_key(self) -> None:
        candidates = source_resolution.source_candidates(
            "",
            "https://github.com/example/Plugin/releases/download/v1.0.0/Plugin.zip",
            "https://raw.githubusercontent.com/example/Plugin/main/repo.json",
        )
        self.assertEqual(["https://github.com/example/Plugin"], candidates)
        self.assertEqual("", source_resolution.github_repository_url("https://downloads.example.invalid/Plugin.zip"))
        self.assertEqual(
            ["https://git.honse.farm/astraea/honse-farm"],
            source_resolution.source_candidates("https://git.honse.farm/astraea/honse-farm", "https://downloads.honse.farm/main/honsefarm.zip"),
        )
        auto_visor = source_resolution.source_candidate_records((
            ("repo-url", "https://github.com/Ottermandias/AutoVisor/tree/1.2.0.2"),
            ("artifact-install", "https://github.com/Ottermandias/AutoVisor/raw/master/AutoVisor.zip"),
        ))
        self.assertEqual(1, len(auto_visor))
        self.assertEqual("https://github.com/Ottermandias/AutoVisor", auto_visor[0]["repository"])
        self.assertEqual(["repo-url", "artifact-install"], auto_visor[0]["origins"])
        self.assertEqual(["1.2.0.2", "master"], auto_visor[0]["refHints"])
        self.assertEqual("1.2.0.2", source_resolution.github_ref_hint("https://github.com/Ottermandias/AutoVisor/tree/1.2.0.2"))
        first = source_resolution.source_override_key("Plugin", "https://example.invalid/feed.json")
        second = source_resolution.source_override_key("plugin", "https://example.invalid/feed.json")
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("src-"))

    def test_sigmascope_prefers_exact_version_source_refs_and_matches_dalamud_manifest(self) -> None:
        self.assertEqual(
            [("1.2.0.2", "version-tag"), ("v1.2.0.2", "version-tag"), ("master", "metadata-ref")],
            sigmascope._source_ref_candidates("1.2.0.2", ["master"], "master"),
        )
        files = {
            "AutoVisor.json": json.dumps({
                "InternalName": "AutoVisor",
                "AssemblyVersion": "1.2.0.2",
                "RepoUrl": "https://github.com/Ottermandias/AutoVisor",
            }).encode(),
            "other.json": b'{"name":"other"}',
        }
        match = sigmascope._source_manifest_match(
            files, lambda path: files[path], "AutoVisor", "AutoVisor", "1.2.0.2",
        )
        self.assertTrue(match["identityMatched"])
        self.assertTrue(match["versionMatched"])
        self.assertEqual("AutoVisor.json", match["manifestPath"])

    def test_source_followup_issue_keys_are_parseable_after_gap_resolution(self) -> None:
        self.assertEqual(
            "omega-source-followup:src-0123456789abcdefabcd",
            create_source_followup_issues.followup_key("<!-- omega-source-followup:src-0123456789abcdefabcd -->"),
        )
        self.assertEqual("", create_source_followup_issues.followup_key("ordinary issue"))

    def test_source_followups_exclude_404_and_mark_transient_failures_non_actionable(self) -> None:
        self.assertTrue(sigmascope_source_followups.is_not_found("HTTP Error 404: Not Found"))
        self.assertFalse(sigmascope_source_followups.is_not_found("HTTP Error 429: Too Many Requests"))
        self.assertFalse(sigmascope_source_followups.is_not_found("first: HTTP Error 404; second: HTTP Error 500"))
        self.assertTrue(sigmascope_source_followups.is_retryable("HTTP Error 429: Too Many Requests"))
        self.assertTrue(sigmascope_source_followups.is_retryable("The read operation timed out"))
        self.assertFalse(sigmascope_source_followups.is_retryable("No GitHub source candidate could be derived"))

    def test_source_followup_projection_deduplicates_plugin_source_pairs_and_retains_transient_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            database = Path(td) / "evidence.sqlite"
            with closing(sqlite3.connect(database)) as db:
                db.executescript("""
                    CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY, internal_name TEXT);
                    CREATE TABLE sources(source_id INTEGER PRIMARY KEY, name TEXT, url TEXT);
                    CREATE TABLE plugin_variants(variant_id INTEGER PRIMARY KEY, plugin_id INTEGER, source_id INTEGER, name TEXT, repo_url TEXT DEFAULT '', download_link_install TEXT DEFAULT '', download_link_update TEXT DEFAULT '', download_link_testing TEXT DEFAULT '');
                    CREATE TABLE plugin_security_current(variant_id INTEGER PRIMARY KEY, status TEXT, source_available INTEGER, assembly_version TEXT, artifact_url TEXT, report_json TEXT);
                """)
                db.execute("INSERT INTO plugins VALUES(1,'Example')")
                db.execute("INSERT INTO sources VALUES(1,'Repo','https://example.invalid/repo.json')")
                db.execute("INSERT INTO plugin_variants(variant_id,plugin_id,source_id,name) VALUES(10,1,1,'Example')")
                db.execute("INSERT INTO plugin_variants(variant_id,plugin_id,source_id,name) VALUES(11,1,1,'Example')")
                db.execute("INSERT INTO plugin_variants(variant_id,plugin_id,source_id,name) VALUES(12,1,1,'Example')")
                db.execute("INSERT INTO plugin_security_current VALUES(10,'complete',0,'1.0','https://example.invalid/a.zip',?)", (json.dumps({"source":{"error":"No GitHub source candidate could be derived","candidates":[]}}),))
                db.execute("INSERT INTO plugin_security_current VALUES(11,'complete',0,'1.0','https://example.invalid/b.zip',?)", (json.dumps({"source":{"error":"HTTP Error 429: Too Many Requests","candidates":["https://github.com/example/Example"]}}),))
                db.execute("INSERT INTO plugin_security_current VALUES(12,'complete',1,'1.0','https://example.invalid/c.zip',?)", (json.dumps({"source":{"available":True,"repository":"https://github.com/example/Example","commit":"abc123","error":"","candidates":["https://github.com/example/Example"]}}),))
                db.commit()
            document = sigmascope_source_followups.followups(database)
        self.assertEqual(1, document["count"])
        self.assertEqual(1, document["actionableCount"])
        self.assertTrue(document["followups"][0]["actionable"])
        self.assertTrue(document["followups"][0]["overrideKey"].startswith("src-"))
        self.assertEqual([document["followups"][0]["key"]], document["resolvedKeys"])
        self.assertEqual(1, len(document["resolved"]))

    def test_source_followup_does_not_open_human_issue_when_current_metadata_can_resolve_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            database = Path(td) / "evidence.sqlite"
            with closing(sqlite3.connect(database)) as db:
                db.executescript("""
                    CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY, internal_name TEXT);
                    CREATE TABLE sources(source_id INTEGER PRIMARY KEY, name TEXT, url TEXT);
                    CREATE TABLE plugin_variants(
                        variant_id INTEGER PRIMARY KEY, plugin_id INTEGER, source_id INTEGER, name TEXT, repo_url TEXT,
                        download_link_install TEXT, download_link_update TEXT, download_link_testing TEXT);
                    CREATE TABLE plugin_security_current(variant_id INTEGER PRIMARY KEY, status TEXT, source_available INTEGER, assembly_version TEXT, artifact_url TEXT, report_json TEXT);
                """)
                db.execute("INSERT INTO plugins VALUES(1,'AutoVisor')")
                db.execute("INSERT INTO sources VALUES(1,'Mirror','https://example.invalid/repo.json')")
                db.execute(
                    "INSERT INTO plugin_variants VALUES(10,1,1,'AutoVisor','',?,?,?)",
                    ('https://github.com/Ottermandias/AutoVisor/raw/master/AutoVisor.zip', '', ''),
                )
                db.execute(
                    "INSERT INTO plugin_security_current VALUES(10,'complete',0,'1.2.3.0',?,?)",
                    ('https://github.com/Ottermandias/AutoVisor/raw/master/AutoVisor.zip', json.dumps({
                        "source": {"error": "No GitHub source candidate could be derived from plugin metadata or download links", "candidates": []}
                    })),
                )
                db.commit()
            document = sigmascope_source_followups.followups(database)
        self.assertEqual(0, document["count"], "resolver-known GitHub origins should be rescanned automatically, not turned into source-needed issues")

    def test_source_followup_reconciliation_closes_only_confirmed_source_coverage(self) -> None:
        existing = [
            {"number": 10, "body": "<!-- omega-source-followup:src-resolved -->", "title": "Resolved"},
            {"number": 11, "body": "<!-- omega-source-followup:src-transient -->", "title": "Transient"},
        ]
        calls: list[tuple[str, ...]] = []

        def fake_gh(*args: str) -> str:
            calls.append(args)
            return json.dumps(existing) if args[:2] == ("issue", "list") else ""

        document = {
            "followups": [{"key": "omega-source-followup:src-transient", "actionable": False}],
            "resolvedKeys": ["omega-source-followup:src-resolved"],
        }
        with mock.patch.object(create_source_followup_issues, "gh", side_effect=fake_gh):
            result = create_source_followup_issues.reconcile_issues(document, "example/omega")
        self.assertEqual((0, 1), result)
        closed_numbers = [call[2] for call in calls if call[:2] == ("issue", "close")]
        self.assertEqual(["10"], closed_numbers)

    def test_source_followup_resolution_closes_all_mirror_issues_for_same_plugin(self) -> None:
        existing = [
            {"number": 20, "body": "<!-- omega-source-followup:src-one -->\n<!-- omega-source-internal:Cammy -->", "title": "Source needed: Cammy (mirror one)"},
            {"number": 21, "body": "<!-- omega-source-followup:src-two -->\n<!-- omega-source-internal:Cammy -->", "title": "Source needed: Cammy (mirror two)"},
        ]
        calls: list[tuple[str, ...]] = []

        def fake_gh(*args: str) -> str:
            calls.append(args)
            return json.dumps(existing) if args[:2] == ("issue", "list") else ""

        document = {
            "followups": [{"key": "omega-source-followup:src-two", "internalName": "Cammy", "actionable": True}],
            "resolved": [{
                "key": "omega-source-followup:src-one", "internalName": "Cammy",
                "repository": "https://github.com/UnknownX7/Cammy", "commit": "abcdef1234567890",
                "confidence": "high", "versionMatched": True,
            }],
            "resolvedKeys": ["omega-source-followup:src-one"],
        }
        with mock.patch.object(create_source_followup_issues, "gh", side_effect=fake_gh):
            result = create_source_followup_issues.reconcile_issues(document, "example/omega")
        self.assertEqual((0, 2), result)
        closed_numbers = [call[2] for call in calls if call[:2] == ("issue", "close")]
        self.assertEqual(["20", "21"], closed_numbers)
        self.assertFalse(any(call[:2] == ("issue", "create") for call in calls))

    def test_source_followup_reconciliation_consolidates_mirrors_and_refreshes_override_keys(self) -> None:
        existing = [
            {"number": 30, "body": "<!-- omega-source-followup:src-old-one -->\n<!-- omega-source-internal:Brio -->", "title": "Source needed: Brio (one)"},
            {"number": 31, "body": "<!-- omega-source-followup:src-old-two -->\n<!-- omega-source-internal:Brio -->", "title": "Source needed: Brio (two)"},
        ]
        calls: list[tuple[str, ...]] = []
        edited_body = {"text": ""}

        def fake_gh(*args: str) -> str:
            calls.append(args)
            if args[:2] == ("issue", "list"):
                return json.dumps(existing)
            if args[:2] == ("issue", "edit"):
                body_file = args[args.index("--body-file") + 1]
                edited_body["text"] = Path(body_file).read_text(encoding="utf-8")
            return ""

        document = {
            "followups": [
                {
                    "key": "omega-source-followup:src-feed-one", "overrideKey": "src-feed-one", "variantId": 1,
                    "internalName": "Brio", "pluginName": "Brio", "assemblyVersion": "0.8.0.11",
                    "catalogSource": "Mirror One", "catalogSourceUrl": "https://one.invalid/repo.json",
                    "artifactUrl": "https://one.invalid/brio.zip", "reason": "source missing",
                    "sourceCandidates": ["https://github.com/Etheirys/Brio"], "actionable": True,
                },
                {
                    "key": "omega-source-followup:src-feed-two", "overrideKey": "src-feed-two", "variantId": 2,
                    "internalName": "Brio", "pluginName": "Brio", "assemblyVersion": "0.8.0.11",
                    "catalogSource": "Mirror Two", "catalogSourceUrl": "https://two.invalid/repo.json",
                    "artifactUrl": "https://two.invalid/brio.zip", "reason": "source missing",
                    "sourceCandidates": ["https://github.com/Etheirys/Brio"], "actionable": True,
                },
            ],
            "resolved": [], "resolvedKeys": [],
        }
        with mock.patch.object(create_source_followup_issues, "gh", side_effect=fake_gh):
            result = create_source_followup_issues.reconcile_issues(document, "example/omega")
        self.assertEqual((0, 1), result)
        self.assertIn("omega-source-override:src-feed-one", edited_body["text"])
        self.assertIn("omega-source-override:src-feed-two", edited_body["text"])
        self.assertIn("Affected catalog mirrors:** 2", edited_body["text"])
        self.assertTrue(any(call[:3] == ("issue", "close", "31") for call in calls))
        self.assertTrue(any(call[:3] == ("issue", "edit", "30") for call in calls))

    def test_source_followup_creation_is_one_issue_per_plugin_across_mirrors(self) -> None:
        created_body = {"text": ""}
        calls: list[tuple[str, ...]] = []

        def fake_gh(*args: str) -> str:
            calls.append(args)
            if args[:2] == ("issue", "list"):
                return "[]"
            if args[:2] == ("issue", "create"):
                body_file = args[args.index("--body-file") + 1]
                created_body["text"] = Path(body_file).read_text(encoding="utf-8")
            return ""

        base = {
            "internalName": "BossMod", "pluginName": "Boss Mod", "assemblyVersion": "7.5.5.8",
            "artifactUrl": "https://example.invalid/boss.zip", "reason": "source missing",
            "sourceCandidates": ["https://github.com/awgil/ffxiv_bossmod"], "actionable": True,
        }
        document = {"followups": [
            dict(base, key="omega-source-followup:src-a", overrideKey="src-a", variantId=1, catalogSource="A", catalogSourceUrl="https://a.invalid/repo.json"),
            dict(base, key="omega-source-followup:src-b", overrideKey="src-b", variantId=2, catalogSource="B", catalogSourceUrl="https://b.invalid/repo.json"),
        ], "resolved": [], "resolvedKeys": []}
        with mock.patch.object(create_source_followup_issues, "gh", side_effect=fake_gh):
            result = create_source_followup_issues.reconcile_issues(document, "example/omega")
        self.assertEqual((1, 0), result)
        creates = [call for call in calls if call[:2] == ("issue", "create")]
        self.assertEqual(1, len(creates))
        self.assertIn("omega-source-override:src-a", created_body["text"])
        self.assertIn("omega-source-override:src-b", created_body["text"])

    def test_source_candidate_failover_does_not_mix_partial_evidence_from_failed_repository(self) -> None:
        calls = []
        def fake_fetch(url, _token, hits):
            calls.append(url)
            if len(calls) == 1:
                hits["network.http"].append("failed-candidate")
                return {"available": False, "error": "HTTP Error 500", "dependencyIntelligence": sigmascope.empty_dependency_intelligence("source")}
            hits["filesystem.write"].append("successful-candidate")
            return {"available": True, "error": "", "dependencyIntelligence": sigmascope.empty_dependency_intelligence("source")}
        hits = defaultdict(list)
        with mock.patch.object(sigmascope, "_fetch_source_candidate", side_effect=fake_fetch):
            result = sigmascope.fetch_source(["https://github.com/example/first", "https://github.com/example/second"], "", hits)
        self.assertTrue(result["available"])
        self.assertNotIn("failed-candidate", hits["network.http"])
        self.assertIn("successful-candidate", hits["filesystem.write"])

    def test_source_candidate_failover_skips_reachable_repository_with_wrong_plugin_identity(self) -> None:
        calls: list[str] = []

        def fake_fetch(url, _token, hits, *_args):
            calls.append(url)
            identity_matched = url.endswith("/correct")
            hits["network.http"].append("correct-evidence" if identity_matched else "wrong-evidence")
            return {
                "available": True,
                "repository": url,
                "commit": "abc",
                "error": "",
                "dependencyIntelligence": sigmascope.empty_dependency_intelligence("source"),
                "provenance": {"identityMatched": identity_matched, "versionMatched": identity_matched},
            }

        hits = defaultdict(list)
        records = [
            {"repository": "https://github.com/example/wrong", "origins": ["repo-url"], "refHints": [], "urls": []},
            {"repository": "https://github.com/example/correct", "origins": ["artifact-install"], "refHints": [], "urls": []},
        ]
        with mock.patch.object(sigmascope, "_fetch_source_candidate", side_effect=fake_fetch):
            result = sigmascope.fetch_source(records, "", hits, "Example", "Example", "1.0.0", "https://github.com/example/correct/raw/main/Plugin.zip")
        self.assertEqual(["https://github.com/example/wrong", "https://github.com/example/correct"], calls)
        self.assertEqual("https://github.com/example/correct", result["repository"])
        self.assertNotIn("wrong-evidence", hits["network.http"])
        self.assertIn("correct-evidence", hits["network.http"])
        self.assertTrue(result["provenance"]["artifactOriginMatched"])

    def test_self_hosted_public_git_source_is_scanned_without_github_api(self) -> None:
        class FakeRepository:
            repository = "https://git.example.test/team/plugin"
            commit = "abc123"
            branch = "main"
            tree_sha = "tree123"
            files = {"Plugin.csproj": 120, "Plugin.cs": 80}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read_file(self, path, _maximum_bytes):
                values = {
                    "Plugin.csproj": b'<Project Sdk="Dalamud.NET.Sdk"><PropertyGroup><AssemblyName>HonseFarm.Client</AssemblyName></PropertyGroup></Project>',
                    "Plugin.cs": b'System.Net.Http.HttpClient client;',
                }
                return values[path]

        hits = defaultdict(list)
        with mock.patch.object(sigmascope, "PublicGitSource", return_value=FakeRepository()):
            result = sigmascope.fetch_source(["https://git.example.test/team/plugin"], "", hits, "HonseFarm.Client", "HonseFarm.Client")
        self.assertTrue(result["available"])
        self.assertEqual("https://git.example.test/team/plugin", result["repository"])
        self.assertEqual("abc123", result["commit"])
        self.assertTrue(any("System.Net.Http.HttpClient" in item for item in hits["network.http"]))

    def test_source_scope_scans_only_plugin_build_graph_in_monorepo(self) -> None:
        paths = {
            "HonseFarm.sln",
            "src/HonseFarm.Client/HonseFarm.Client.csproj",
            "src/HonseFarm.Client/Plugin.cs",
            "src/HonseFarm.Server/HonseFarm.Server.csproj",
            "src/HonseFarm.Server/Server.cs",
            "src/HonseFarm.Shared/HonseFarm.Shared.csproj",
            "src/HonseFarm.Shared/Shared.cs",
            "src/Common/PluginBridge.cs",
            "Directory.Build.props",
            ".github/workflows/server.yml",
        }
        descriptors = {
            "HonseFarm.sln": '''
                Project("{A}") = "HonseFarm.Client", "src\\HonseFarm.Client\\HonseFarm.Client.csproj", "{B}"
                Project("{A}") = "HonseFarm.Server", "src\\HonseFarm.Server\\HonseFarm.Server.csproj", "{C}"
            ''',
            "src/HonseFarm.Client/HonseFarm.Client.csproj": '''
                <Project Sdk="Dalamud.NET.Sdk/14.0.2">
                  <ItemGroup>
                    <ProjectReference Include="..\\HonseFarm.Shared\\HonseFarm.Shared.csproj" />
                    <Compile Include="..\\Common\\PluginBridge.cs" Link="PluginBridge.cs" />
                  </ItemGroup>
                </Project>
            ''',
            "src/HonseFarm.Server/HonseFarm.Server.csproj": '''
                <Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup>
                  <ProjectReference Include="..\\HonseFarm.Shared\\HonseFarm.Shared.csproj" />
                </ItemGroup></Project>
            ''',
            "src/HonseFarm.Shared/HonseFarm.Shared.csproj": '<Project Sdk="Microsoft.NET.Sdk" />',
        }
        scope = sigmascope.select_plugin_source_scope(paths, descriptors, "HonseFarm", "Honse Farm")
        self.assertEqual("plugin-build-graph", scope["mode"])
        self.assertEqual("src/HonseFarm.Client/HonseFarm.Client.csproj", scope["primaryProject"])
        self.assertEqual(
            ["src/HonseFarm.Client/HonseFarm.Client.csproj", "src/HonseFarm.Shared/HonseFarm.Shared.csproj"],
            scope["projectFiles"],
        )
        self.assertIn("HonseFarm.sln", scope["solutionFiles"])
        self.assertIn("src/Common/PluginBridge.cs", scope["criticalPaths"])
        self.assertIn("Directory.Build.props", scope["criticalPaths"])
        self.assertNotIn("src/HonseFarm.Server/Server.cs", scope["criticalPaths"])
        self.assertNotIn("src/HonseFarm.Server/HonseFarm.Server.csproj", scope["criticalPaths"])
        self.assertIn("src/HonseFarm.Server/HonseFarm.Server.csproj", scope["contextProjects"])
        self.assertGreater(scope["excludedSourceFiles"], 0)

    def test_source_scope_does_not_promote_server_only_repository_to_plugin_code(self) -> None:
        paths = {"src/HonseFarm.Server/HonseFarm.Server.csproj", "src/HonseFarm.Server/Program.cs"}
        descriptors = {
            "src/HonseFarm.Server/HonseFarm.Server.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />',
        }
        scope = sigmascope.select_plugin_source_scope(paths, descriptors, "HonseFarm", "Honse Farm")
        self.assertEqual("repository-context-only", scope["mode"])
        self.assertEqual("", scope["primaryProject"])
        self.assertEqual([], scope["criticalPaths"])
        self.assertEqual(2, scope["excludedSourceFiles"])

    def test_scanner_loads_only_validated_stable_github_source_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "source-overrides.json"
            path.write_text(json.dumps({
                "schema": "omega.source-overrides.v1",
                "overrides": {
                    "src-0123456789abcdefabcd": "https://github.com/example/Plugin/releases/tag/v1",
                    "42": "https://github.com/example/WrongKey",
                    "src-bad": "https://example.invalid/repo",
                },
            }), encoding="utf-8")
            overrides = sigmascope.load_source_overrides(path)
        self.assertEqual({"src-0123456789abcdefabcd": "https://github.com/example/Plugin"}, overrides)

    def test_source_submission_accepts_only_public_https_urls_and_valid_pluginmaster_feeds(self) -> None:
        with mock.patch.object(process_source_submission.socket, "getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 443))]), tempfile.TemporaryDirectory() as td:
            path = Path(td) / "community-sources.json"
            overrides = Path(td) / "source-overrides.json"
            payload = {"issue": {"title": "Source submission: example", "body": "https://example.invalid/repo.json"}}
            with mock.patch.object(process_source_submission.enrich_metadata, "fetch_source", return_value={"ok": True, "pluginCount": 2}) as fetch:
                outcome = process_source_submission.process(payload, path, overrides)
                fetch.assert_called_once()
                self.assertEqual(16 * 1024 * 1024, fetch.call_args.kwargs["max_bytes"])
                self.assertIs(process_source_submission.public_https_url, fetch.call_args.kwargs["url_validator"])
            saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual("accepted", outcome["status"])
        self.assertEqual("https://example.invalid/repo.json", outcome["url"])
        self.assertFalse(saved[0]["enabledByDefault"])

    def test_source_submission_rejects_unbounded_plugin_counts(self) -> None:
        with mock.patch.object(process_source_submission.socket, "getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 443))]), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            payload = {"issue": {"title": "Source submission: oversized", "body": "https://example.invalid/repo.json"}}
            with mock.patch.object(process_source_submission.enrich_metadata, "fetch_source", return_value={"ok": True, "pluginCount": process_source_submission.MAX_SUBMITTED_PLUGINS + 1}):
                outcome = process_source_submission.process(payload, root / "community-sources.json", root / "source-overrides.json")
            self.assertEqual("rejected", outcome["status"])
            self.assertFalse((root / "community-sources.json").exists())

    def test_submission_url_policy_rejects_private_redirect_targets_before_following(self) -> None:
        handler = enrich_metadata._ValidatingRedirectHandler(lambda url: url == "https://public.example/repo.json")
        request = enrich_metadata.urllib.request.Request("https://public.example/repo.json")
        with self.assertRaises(enrich_metadata.urllib.error.HTTPError):
            handler.redirect_request(request, None, 302, "Found", {}, "https://127.0.0.1/private.json")

    def test_source_followup_reply_persists_stable_plugin_source_override(self) -> None:
        validation = {
            "ok": True, "repository": "https://github.com/example/Plugin", "commit": "abc123",
            "identityMatched": True, "versionMatched": True, "selectedRef": "1.2.3", "error": "",
        }
        with mock.patch.object(process_source_submission.socket, "getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 443))]), mock.patch.object(process_source_submission, "github_repository_is_public", return_value=True), mock.patch.object(process_source_submission, "validate_source_repository_identity", return_value=validation), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key = "src-0123456789abcdefabcd"
            outcome = process_source_submission.process(
                {"issue": {
                    "title": "Source needed: Example",
                    "labels": [{"name": "omega-source-followup"}],
                    "body": f"<!-- omega-source-submission -->\n<!-- omega-source-followup:{key} -->\n<!-- omega-source-internal:ExamplePlugin -->\n<!-- omega-source-version:1.2.3 -->",
                }, "comment": {"body": "https://github.com/example/Plugin"}},
                root / "community-sources.json",
                root / "source-overrides.json",
            )
            document = json.loads((root / "source-overrides.json").read_text(encoding="utf-8"))
        self.assertEqual("accepted-override", outcome["status"])
        self.assertEqual("ExamplePlugin", outcome["internalName"])
        self.assertTrue(outcome["validation"]["identityMatched"])
        self.assertEqual("https://github.com/example/Plugin", document["overrides"][key])

    def test_source_followup_reply_applies_validated_source_to_all_mirror_override_keys(self) -> None:
        validation = {
            "ok": True, "repository": "https://github.com/example/Plugin", "commit": "abc123",
            "identityMatched": True, "versionMatched": False, "selectedRef": "main", "error": "",
        }
        with mock.patch.object(process_source_submission.socket, "getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 443))]), mock.patch.object(process_source_submission, "github_repository_is_public", return_value=True), mock.patch.object(process_source_submission, "validate_source_repository_identity", return_value=validation), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outcome = process_source_submission.process(
                {"issue": {
                    "title": "Source needed: ExamplePlugin",
                    "labels": [{"name": "omega-source-followup"}],
                    "body": "\n".join((
                        "<!-- omega-source-submission -->",
                        "<!-- omega-source-followup:src-one -->",
                        "<!-- omega-source-override:src-one -->",
                        "<!-- omega-source-override:src-two -->",
                        "<!-- omega-source-internal:ExamplePlugin -->",
                        "<!-- omega-source-version: -->",
                    )),
                }, "comment": {"body": "https://github.com/example/Plugin"}},
                root / "community-sources.json", root / "source-overrides.json",
            )
            document = json.loads((root / "source-overrides.json").read_text(encoding="utf-8"))
        self.assertEqual("accepted-override", outcome["status"])
        self.assertEqual(["src-one", "src-two"], outcome["overrideKeys"])
        self.assertEqual("https://github.com/example/Plugin", document["overrides"]["src-one"])
        self.assertEqual("https://github.com/example/Plugin", document["overrides"]["src-two"])

    def test_forged_source_followup_marker_cannot_persist_override_without_managed_label(self) -> None:
        with mock.patch.object(process_source_submission.socket, "getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 443))]), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outcome = process_source_submission.process(
                {"issue": {
                    "title": "Source submission: forged",
                    "body": "<!-- omega-source-submission -->\n<!-- omega-source-followup:src-forged -->\n<!-- omega-source-internal:ExamplePlugin -->",
                }, "comment": {"body": "https://github.com/example/Plugin"}},
                root / "community-sources.json",
                root / "source-overrides.json",
            )
        self.assertEqual("rejected", outcome["status"])
        self.assertEqual("override", outcome["kind"])
        self.assertFalse((root / "source-overrides.json").exists())

    def test_pluginmaster_fetch_is_bounded(self) -> None:
        class FakeResponse:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, _count=-1): return b"x" * 9
        with mock.patch.object(enrich_metadata.urllib.request, "urlopen", return_value=FakeResponse()):
            with self.assertRaisesRegex(ValueError, "exceeds 8 bytes"):
                enrich_metadata.http_get("https://example.invalid/repo.json", max_bytes=8)

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

    def test_enrichment_accepts_bom_prefixed_single_plugin_manifests(self) -> None:
        source = {"url": "https://example.invalid/repo.json", "provider": "Community"}
        body = ("\ufeff" + json.dumps({
            "Author": "Omega",
            "Name": "Example",
            "InternalName": "Example",
            "AssemblyVersion": "1.2.3.4",
            "DalamudApiLevel": 15,
            "DownloadLinkInstall": "https://example.invalid/Example.zip",
        })).encode("utf-8")
        with mock.patch.object(enrich_metadata, "http_get", return_value=(200, body, {})):
            row = enrich_metadata.fetch_source(source)
        self.assertTrue(row["ok"])
        self.assertEqual(1, row["pluginCount"])
        self.assertEqual("Example", row["plugins"][0]["internalName"])

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

    def test_enrichment_records_successfully_followed_feed_redirect(self) -> None:
        source = {"url": "https://example.invalid/old.json", "provider": "Example"}
        resolved = "https://cdn.example.invalid/current.json"
        body = json.dumps([{
            "Author": "Omega", "Name": "Example", "InternalName": "Example",
            "AssemblyVersion": "1.0.0", "DalamudApiLevel": 15,
        }]).encode("utf-8")
        with mock.patch.object(
            enrich_metadata, "http_get",
            return_value=(200, body, {"x-omega-resolved-url": resolved}),
        ):
            row = enrich_metadata.fetch_source(source)
        self.assertTrue(row["ok"])
        self.assertEqual(resolved, row["resolvedUrl"])

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


    def test_scraper_classifies_safe_project_actions_and_hides_unknown_links(self) -> None:
        repo = "https://github.com/example/plugin"
        links = scrape_websites.classify_project_links([
            "https://discord.gg/example",
            "https://github.com/example/plugin/issues",
            "https://github.com/example/plugin/wiki",
            "https://github.com/example/plugin/releases",
            "https://example.invalid/random-tracker",
            "https://example.invalid/download/plugin.zip",
        ], repo, "https://plugin.example.invalid/")
        by_kind = {item["kind"]: item for item in links}
        self.assertEqual("Join Discord", by_kind["discord"]["label"])
        self.assertEqual("Source", by_kind["source"]["label"])
        self.assertEqual("Issues", by_kind["issues"]["label"])
        self.assertEqual("Documentation", by_kind["docs"]["label"])
        self.assertEqual("Releases", by_kind["releases"]["label"])
        self.assertEqual("Website", by_kind["website"]["label"])
        self.assertFalse(any(item["url"].endswith("plugin.zip") for item in links))
        self.assertFalse(any("random-tracker" in item["url"] for item in links))

    def test_github_scraper_captures_bounded_readme_and_project_image_urls(self) -> None:
        project = {"name": "Fixture", "default_branch": "main", "stargazers_count": 0, "forks_count": 0}
        readme = "# Fixture\n![Preview](images/preview.png)\n" + ("x" * 6000)
        encoded = base64.b64encode(readme.encode("utf-8")).decode("ascii")
        with mock.patch.object(scrape_websites, "fetch_github_omega_index", return_value={}), \
                mock.patch.object(scrape_websites, "github_get", side_effect=[project, {"encoding": "base64", "content": encoded}]):
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
        with mock.patch.object(scrape_websites, "fetch_github_omega_index", return_value={}), \
                mock.patch.object(scrape_websites, "github_get", side_effect=[project, {"encoding": "base64", "content": encoded}]):
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
        intel = sigmascope.empty_dependency_intelligence("source")
        sigmascope.scan_source_text("Plugin.cs", b"", 'File.ReadAllText(@"C:\\Users\\Example\\secret.txt");', intel, hits)
        self.assertIn("filesystem.external-path", hits)
        self.assertIn("C:\\Users\\Example\\secret.txt", hits["filesystem.external-path"][0])
        self.assertEqual([], sigmascope.external_hard_coded_paths('var path = @"C:\\Users\\Example\\secret.txt";'))

    def test_endpoint_inventory_classifies_hosts_and_redacts_url_queries(self) -> None:
        endpoints = security_endpoint_inventory.endpoint_candidates(
            'new HttpClient().GetStringAsync("https://api.github.com/repos/example?access_token=secret");',
            "source:Plugin.cs",
        )
        self.assertEqual("https://api.github.com/repos/example", endpoints[0]["url"])
        self.assertEqual("recognised-platform", endpoints[0]["classification"])
        self.assertEqual("source hosting", endpoints[0]["purpose"])
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

    def test_endpoint_inventory_marks_direct_ip_and_redacts_webhook_tokens(self) -> None:
        endpoints = security_endpoint_inventory.endpoint_candidates(
            'HttpClient.GetStringAsync("https://8.8.8.8/update"); HttpClient.PostAsync("https://discord.com/api/webhooks/12345678901234567890/this-is-a-long-secret-token-value", body);',
            "source:Plugin.cs",
        )
        self.assertEqual("public-ip-literal", endpoints[0]["classification"])
        self.assertEqual("direct public IP", endpoints[0]["purpose"])
        self.assertEqual("webhook-endpoint", endpoints[1]["classification"])
        self.assertEqual("https://discord.com/api/webhooks/<redacted>", endpoints[1]["url"])

    def test_endpoint_inventory_distinguishes_community_lodestone_and_source_links(self) -> None:
        endpoints = security_endpoint_inventory.endpoint_candidates(
            '"https://discord.gg/community" "https://na.finalfantasyxiv.com/lodestone/character/123/" "https://git.example.test/team/plugin/-/tree/main/Plugin.cs" "https://server.example.com/" "http://nonemptyuri/path"',
            "source:Plugin.cs",
        )
        self.assertEqual(["community-invite", "ffxiv-lodestone-link", "source-reference"], [item["classification"] for item in endpoints])
        findings, _ = security_endpoint_inventory.endpoint_findings(endpoints, True, ["https://git.example.test/team/plugin"])
        self.assertEqual(["Community invite: Discord", "Official FFXIV Lodestone page link"], [item["title"] for item in findings])
        self.assertTrue(all("server.example.com" not in str(item) and "nonemptyuri" not in str(item) for item in endpoints))

    def test_endpoint_inventory_reports_dynamic_destinations_when_network_target_is_not_literal(self) -> None:
        findings, capabilities = security_endpoint_inventory.endpoint_findings([], has_network_capability=True)
        self.assertEqual("network.endpoint.dynamic-or-undetermined", findings[0]["ruleId"])
        self.assertEqual(["Network destination undetermined"], capabilities)

    def test_bundled_binary_documentation_urls_are_not_plugin_endpoints(self) -> None:
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("Microsoft.IdentityModel.Logging.dll", b"MZ System.Net.Http.HttpClient https://aka.ms/IdentityModel/SecurityArtifactLogging")
            archive.writestr("Plugin.cs", 'System.Net.Http.HttpClient client; var endpoint = "https://api.example.test/plugin";')
        hits = defaultdict(list)
        intel = sigmascope.empty_dependency_intelligence("artifact")
        sigmascope.scan_archive(payload.getvalue(), hits, intel)
        endpoints = {item["url"]: item for item in intel["networkEndpoints"]}
        self.assertIn("https://api.example.test/plugin", endpoints)
        documentation = endpoints["https://aka.ms/IdentityModel/SecurityArtifactLogging"]
        self.assertEqual("artifact-binary-string", documentation["originType"])
        self.assertEqual("documentation-reference", documentation["classification"])
        self.assertFalse(documentation["concreteDestinationEvidence"])

    def test_cross_source_hash_consensus_uses_named_stable_baseline(self) -> None:
        with closing(sqlite3.connect(":memory:")) as db:
            db.row_factory = sqlite3.Row
            db.executescript(build_sqlite_catalog.SCHEMA_SQL)
            sigmascope.ensure_schema(db)
            db.execute("INSERT INTO plugins(plugin_id,internal_name,canonical_name,first_seen_utc,last_seen_utc,active) VALUES(1,'Fixture','Fixture','','',1)")
            sources = (
                (1, "https://puni.sh/Fixture", "Puni.sh Fixture"),
                (2, "https://mirror.invalid/repo.json", "Mirror"),
                (3, "https://outlier.invalid/repo.json", "Outlier"),
            )
            for source_id, source_url, source_name in sources:
                db.execute("INSERT INTO sources(source_id,url,name) VALUES(?,?,?)", (source_id, source_url, source_name))
                db.execute("INSERT INTO plugin_variants(variant_id,plugin_id,source_id,source_entry_key,assembly_version,first_seen_utc,last_seen_utc,active) VALUES(?,?,?,?,?,?,?,1)", (source_id, 1, source_id, f"Fixture-{source_id}", "1.0.0", "", ""))
            report = json.dumps({"findings": [], "capabilities": []})
            for variant_id, artifact_hash in ((1, "a" * 64), (2, "a" * 64), (3, "b" * 64)):
                db.execute("INSERT INTO plugin_security_scans(scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_sha256,status,report_json) VALUES(?,?,?,?,?,?,?,?)", (variant_id, 1, variant_id, variant_id, "1.0.0", artifact_hash, "complete", report))
                db.execute("INSERT INTO plugin_security_current(variant_id,scan_id,assembly_version,artifact_sha256,status,report_json) VALUES(?,?,?,?,?,?)", (variant_id, variant_id, "1.0.0", artifact_hash, "complete", report))
            summary = security_hash_consensus.refresh_cross_source_hash_findings(db)
            baseline = db.execute("SELECT highest_severity,findings_json FROM plugin_security_current WHERE variant_id=1").fetchone()
            mirror = db.execute("SELECT highest_severity,findings_json FROM plugin_security_current WHERE variant_id=2").fetchone()
            outlier = db.execute("SELECT highest_severity,findings_json FROM plugin_security_current WHERE variant_id=3").fetchone()
            db.execute("UPDATE plugin_security_current SET artifact_sha256=? WHERE variant_id=3", ("a" * 64,))
            security_hash_consensus.canonicalize_current_security_by_artifact(db)
            security_hash_consensus.refresh_cross_source_hash_findings(db)
            resolved = db.execute("SELECT findings_json,capabilities_json FROM plugin_security_current WHERE variant_id=3").fetchone()
        self.assertEqual(1, summary["groupsWithMismatches"])
        self.assertEqual(1, summary["stableBaselineGroups"])
        self.assertEqual("none", baseline["highest_severity"])
        self.assertEqual("none", mirror["highest_severity"])
        self.assertNotIn("artifact.cross-source-hash-mismatch", baseline["findings_json"])
        self.assertNotIn("artifact.cross-source-hash-mismatch", mirror["findings_json"])
        self.assertEqual("high", outlier["highest_severity"])
        self.assertIn("Artifact differs from stable package baseline", outlier["findings_json"])
        self.assertNotIn("artifact.cross-source-hash-mismatch", resolved["findings_json"])
        self.assertNotIn("Cross-source hash comparison", resolved["capabilities_json"])

    def test_exact_artifact_mirrors_inherit_resolved_original_source_provenance(self) -> None:
        with closing(sqlite3.connect(":memory:")) as db:
            db.row_factory = sqlite3.Row
            db.executescript(build_sqlite_catalog.SCHEMA_SQL)
            sigmascope.ensure_schema(db)
            db.execute("INSERT INTO plugins(plugin_id,internal_name,canonical_name,first_seen_utc,last_seen_utc,active) VALUES(1,'AutoVisor','AutoVisor','','',1)")
            db.execute("INSERT INTO sources(source_id,url,name) VALUES(1,'https://original.invalid/repo.json','Original feed')")
            db.execute("INSERT INTO sources(source_id,url,name) VALUES(2,'https://mirror.invalid/repo.json','Mirror feed')")
            for variant_id, source_id in ((1, 1), (2, 2)):
                db.execute("INSERT INTO plugin_variants(variant_id,plugin_id,source_id,source_entry_key,assembly_version,first_seen_utc,last_seen_utc,active) VALUES(?,?,?,?,?,?,?,1)", (variant_id, 1, source_id, f'AutoVisor-{variant_id}', '1.2.0.2', '', ''))
            donor_report = json.dumps({
                "source": {
                    "available": True,
                    "repository": "https://github.com/Ottermandias/AutoVisor",
                    "commit": "abc123",
                    "provenance": {"confidence": "very-high", "identityMatched": True, "versionMatched": True, "artifactOriginMatched": True},
                }
            }, separators=(",", ":"))
            missing_report = json.dumps({"source": {"available": False, "error": "No source"}}, separators=(",", ":"))
            db.execute("INSERT INTO plugin_security_scans(scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_sha256,status,report_json) VALUES(1,1,1,1,'1.2.0.2',?,'complete',?)", ('a' * 64, donor_report))
            db.execute("INSERT INTO plugin_security_scans(scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_sha256,status,report_json) VALUES(2,1,2,2,'1.2.0.2',?,'complete',?)", ('a' * 64, missing_report))
            db.execute("INSERT INTO plugin_security_current(variant_id,scan_id,assembly_version,artifact_sha256,status,source_available,source_repository,source_commit,report_json) VALUES(1,1,'1.2.0.2',?,'complete',1,?,?,?)", ('a' * 64, 'https://github.com/Ottermandias/AutoVisor', 'abc123', donor_report))
            db.execute("INSERT INTO plugin_security_current(variant_id,scan_id,assembly_version,artifact_sha256,status,source_available,source_repository,source_commit,report_json) VALUES(2,2,'1.2.0.2',?,'complete',0,'','',?)", ('a' * 64, missing_report))
            summary = security_hash_consensus.propagate_source_provenance_by_artifact(db)
            row = db.execute("SELECT source_available,source_repository,source_commit,source_to_binary_verified,report_json FROM plugin_security_current WHERE variant_id=2").fetchone()
        self.assertEqual(1, summary["variantsInheritedSource"])
        self.assertEqual(1, row["source_available"])
        self.assertEqual("https://github.com/Ottermandias/AutoVisor", row["source_repository"])
        self.assertEqual("abc123", row["source_commit"])
        self.assertEqual(0, row["source_to_binary_verified"])
        inherited = json.loads(row["report_json"])["source"]["provenance"]
        self.assertTrue(inherited["inheritedViaArtifact"])
        self.assertEqual(1, inherited["inheritedFromVariantId"])

    def test_stable_source_classification_is_explicit_not_catalog_size_based(self) -> None:
        self.assertEqual("Dalamud", source_stability.classify_stable_source("Dalamud official", "", True).label)
        self.assertEqual("Puni.sh", source_stability.classify_stable_source("Puni.sh", "https://puni.sh/repository", False).label)
        self.assertEqual("NightmareXIV", source_stability.classify_stable_source("NightmareXIV", "https://github.com/NightmareXIV/repo", False).label)
        self.assertEqual("Combat Reborn", source_stability.classify_stable_source("Combat Reborn", "https://github.com/FFXIV-CombatReborn/CombatRebornRepo", False).label)
        self.assertIsNone(source_stability.classify_stable_source("Huge community repo", "https://example.invalid/huge.json", False))

    def test_declared_but_unreviewed_source_does_not_make_artifact_scan_due(self) -> None:
        with sqlite3.connect(":memory:") as db:
            db.row_factory = sqlite3.Row
            db.executescript("""
                CREATE TABLE plugins(
                    plugin_id INTEGER PRIMARY KEY,
                    internal_name TEXT NOT NULL,
                    active INTEGER NOT NULL
                );
                CREATE TABLE sources(
                    source_id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    source_repo_url TEXT NOT NULL
                );
                CREATE TABLE plugin_variants(
                    variant_id INTEGER PRIMARY KEY,
                    plugin_id INTEGER NOT NULL,
                    source_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    author TEXT NOT NULL,
                    assembly_version TEXT NOT NULL,
                    testing_assembly_version TEXT,
                    download_link_install TEXT NOT NULL,
                    download_link_update TEXT NOT NULL,
                    download_link_testing TEXT NOT NULL,
                    repo_url TEXT NOT NULL,
                    active INTEGER NOT NULL
                );
                CREATE TABLE plugin_security_current(
                    variant_id INTEGER PRIMARY KEY,
                    scan_id INTEGER,
                    status TEXT,
                    source_available INTEGER,
                    source_repository TEXT,
                    scanned_at_utc TEXT,
                    scanner_version TEXT,
                    artifact_url TEXT,
                    assembly_version TEXT
                );

                INSERT INTO plugins VALUES(1,'ReviewedPlugin',1);
                INSERT INTO plugins VALUES(2,'NeedsSourceReview',1);
                INSERT INTO sources VALUES(1,'Reviewed repo','https://example.invalid/a.json','https://github.com/example/reviewed');
                INSERT INTO sources VALUES(2,'Pending repo','https://example.invalid/b.json','https://gitlab.example/pending');
                INSERT INTO plugin_variants VALUES(
                    1,1,1,'Reviewed Plugin','Tester','1.0.0',NULL,
                    'https://example.invalid/reviewed.zip','','','https://github.com/example/reviewed',1
                );
                INSERT INTO plugin_variants VALUES(
                    2,2,2,'Needs Source Review','Tester','1.0.0',NULL,
                    'https://example.invalid/pending.zip','','','https://gitlab.example/pending',1
                );
            """)
            now = sigmascope.utc_now()
            db.execute(
                """INSERT INTO plugin_security_current
                   VALUES(1,101,'complete',1,'https://github.com/example/reviewed',?,?,?,?)""",
                (now, sigmascope.SCANNER_VERSION, "https://example.invalid/reviewed.zip", "1.0.0"),
            )
            db.execute(
                """INSERT INTO plugin_security_current
                   VALUES(2,102,'complete',0,'',?,?,?,?)""",
                (now, sigmascope.SCANNER_VERSION, "https://example.invalid/pending.zip", "1.0.0"),
            )

            due = sigmascope.due_rows(db, 1, 0, set())
            self.assertEqual(
                [],
                due,
                "declared-but-unreviewed source is source-queue work and must not make artifact scanning due",
            )

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
                db.execute("INSERT INTO plugin_security_dependencies VALUES(1,'nuget-lock','Locked.Package','2.0.0','2.0.1')")
                db.execute("INSERT INTO plugin_security_dependencies VALUES(1,'nuget-resolved','Resolved.Package','','3.4.5')")
                db.commit()
            def query_batch(_url, payload, _timeout):
                return {"results": [
                    {"vulns": [{"id": "GHSA-test"}]} if q["package"]["name"] == "Example.Package" else {"vulns": []}
                    for q in payload["queries"]
                ]}
            with mock.patch.object(collect_public_advisories, "post_json", side_effect=query_batch), \
                 mock.patch.object(collect_public_advisories, "get_json", return_value={"id": "GHSA-test", "summary": "Example vulnerability", "aliases": ["CVE-2026-0001"], "database_specific": {"severity": "HIGH"}}):
                document = collect_public_advisories.collect(database, output)
        self.assertEqual(3, document["queriedPackages"])
        self.assertEqual(1, document["matchedPackages"])
        advisory = document["advisories"][0]
        self.assertEqual("Example.Package", advisory["name"])
        self.assertEqual(["1.2.3"], advisory["affectedVersions"])
        self.assertEqual("high", advisory["severity"])
        self.assertEqual("CVE-2026-0001", advisory["aliases"][0])

    def test_public_advisory_collector_reads_security_evidence_v2_nuget_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            index = root / "nuget.json"
            output = root / "public-advisories.json"
            index.write_text(json.dumps({
                "schema": "omega.security-evidence.nuget-index.v2",
                "ecosystem": "NuGet",
                "packageVersionPairs": 2,
                "packages": [
                    {"normalized_name": "example.package", "name": "Example.Package", "version": "1.2.3", "observations": 4},
                    {"normalized_name": "other.package", "name": "Other.Package", "version": "2.0.0", "observations": 1},
                ],
            }), encoding="utf-8")
            def query_batch(_url, payload, _timeout):
                self.assertEqual(["Example.Package", "Other.Package"], [q["package"]["name"] for q in payload["queries"]])
                return {"results": [{"vulns": []}, {"vulns": []}]}
            with mock.patch.object(collect_public_advisories, "post_json", side_effect=query_batch):
                document = collect_public_advisories.collect_from_nuget_index(index, output)
        self.assertEqual(2, document["queriedPackages"])
        self.assertEqual(0, document["matchedPackages"])

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
                    "links": [{"kind": "discord", "label": "Join Discord", "url": "https://discord.gg/fixture"}],
                },
            }}, "2026-08-16T00:00:00Z")
            row = db.execute("SELECT readme_excerpt,image_urls_json,links_json,metadata_json FROM websites").fetchone()
        self.assertEqual("# Fixture\nProject documentation.", row["readme_excerpt"])
        self.assertEqual(
            ["https://raw.githubusercontent.com/example/fixture/main/images/preview.png"],
            json.loads(row["image_urls_json"]),
        )
        self.assertEqual(["https://discord.com/api/guilds/123456/widget.png"], json.loads(row["metadata_json"])["discordJoinImageUrls"])
        self.assertEqual("discord", json.loads(row["links_json"])[0]["kind"])

    def test_http_diagnostics_are_rejected_from_presentation_text(self) -> None:
        poisoned = "404:\n- https://example.invalid/a at line 1\n- https://example.invalid/b at line 1\n\n500:\n- https://example.invalid/c"
        self.assertTrue(scrape_websites.looks_like_http_diagnostic(poisoned))
        self.assertIsNone(scrape_websites.sanitize_presentation_text(poisoned))
        self.assertEqual(
            "A normal project description.",
            scrape_websites.sanitize_presentation_text("A normal project description."),
        )

    def test_incremental_website_cache_reuses_current_generation_classified_links(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "seed.sqlite"
            now = dt.datetime.now(dt.timezone.utc).isoformat()
            with closing(sqlite3.connect(path)) as db:
                db.executescript("""
                    CREATE TABLE websites(
                        url TEXT, ok INTEGER, last_success_utc TEXT, metadata_json TEXT,
                        description TEXT, homepage TEXT, stars INTEGER, forks INTEGER, watchers INTEGER,
                        language TEXT, license TEXT, default_branch TEXT, last_commit_utc TEXT,
                        readme_excerpt TEXT, topics_json TEXT, image_urls_json TEXT, links_json TEXT
                    );
                """)
                db.execute(
                    "INSERT INTO websites VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "https://github.com/example/plugin", 1, now, json.dumps({"presentationSchemaVersion": scrape_websites.PRESENTATION_SCHEMA_VERSION}), "Fixture", "https://plugin.example/",
                        None, None, None, "C#", "MIT", "main", "",
                        "[Discord](https://discord.gg/example)\n[Issues](https://github.com/example/plugin/issues)",
                        "[]", "[]", json.dumps([
                            {"kind": "source", "label": "Source", "url": "https://github.com/example/plugin"},
                            {"kind": "website", "label": "Website", "url": "https://plugin.example/"},
                            {"kind": "discord", "label": "Join Discord", "url": "https://discord.gg/example"},
                            {"kind": "issues", "label": "Issues", "url": "https://github.com/example/plugin/issues"},
                        ]),
                    ),
                )
                db.commit()
            cache = scrape_websites_incremental.load_cache(path, 168.0)
        record = cache["https://github.com/example/plugin"]
        kinds = {item["kind"] for item in record["links"]}
        self.assertTrue({"source", "website", "discord", "issues"}.issubset(kinds))


    def test_incremental_website_cache_invalidates_old_presentation_generation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "seed.sqlite"
            now = dt.datetime.now(dt.timezone.utc).isoformat()
            with closing(sqlite3.connect(path)) as db:
                db.executescript("""
                    CREATE TABLE websites(
                        url TEXT, ok INTEGER, last_success_utc TEXT, metadata_json TEXT,
                        description TEXT, homepage TEXT, stars INTEGER, forks INTEGER, watchers INTEGER,
                        language TEXT, license TEXT, default_branch TEXT, last_commit_utc TEXT,
                        readme_excerpt TEXT, topics_json TEXT, image_urls_json TEXT, links_json TEXT
                    );
                """)
                db.execute(
                    "INSERT INTO websites VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "https://github.com/example/plugin", 1, now, json.dumps({"presentationSchemaVersion": scrape_websites.PRESENTATION_SCHEMA_VERSION - 1}),
                        "Old description", "", None, None, None, "C#", "MIT", "main", "",
                        "Old README", "[]", "[]", "[]",
                    ),
                )
                db.commit()
            cache = scrape_websites_incremental.load_cache(path, 168.0)
        self.assertEqual({}, cache)

    def test_failed_rescrape_preserves_server_history_but_invalidates_current_presentation(self) -> None:
        with closing(sqlite3.connect(":memory:")) as db:
            db.row_factory = sqlite3.Row
            db.executescript(build_sqlite_catalog.SCHEMA_SQL)
            build_sqlite_catalog.import_websites(db, {"repos": {
                "https://github.com/example/fixture": {
                    "url": "https://github.com/example/fixture", "ok": True,
                    "description": "Current description", "readmeExcerpt": "Current README",
                    "presentationSchemaVersion": scrape_websites.PRESENTATION_SCHEMA_VERSION,
                },
            }}, "2026-08-17T00:00:00Z")
            build_sqlite_catalog.import_websites(db, {"repos": {
                "https://github.com/example/fixture": {
                    "url": "https://github.com/example/fixture", "ok": False, "error": "timeout",
                    "presentationSchemaVersion": scrape_websites.PRESENTATION_SCHEMA_VERSION,
                },
            }}, "2026-08-17T01:00:00Z")
            row = db.execute("SELECT ok,description,readme_excerpt,last_error FROM websites").fetchone()
        self.assertEqual(0, row["ok"])
        self.assertEqual("Current description", row["description"])
        self.assertEqual("Current README", row["readme_excerpt"])
        self.assertEqual("timeout", row["last_error"])

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
        self.assertTrue(sigmascope.version_satisfies("2.5.0", ">=2.0 <3.0"))
        self.assertFalse(sigmascope.version_satisfies("3.0.0", ">=2.0 <3.0"))
        self.assertIsNone(sigmascope.version_satisfies("2.0.0", "banana"))

    def test_archive_path_normalization_rejects_escape(self) -> None:
        self.assertEqual("folder/plugin.dll", sigmascope.normalized_archive_member_name("folder\\plugin.dll"))
        self.assertFalse(sigmascope.safe_member_name("../escape.dll"))
        self.assertFalse(sigmascope.safe_member_name("C:\\escape.dll"))
        self.assertTrue(sigmascope.safe_member_name("folder/plugin.dll"))

    def test_security_resource_ceilings_cover_current_production_cases(self) -> None:
        self.assertGreaterEqual(sigmascope.MAX_ARTIFACT_BYTES, 156_649_087)
        self.assertGreaterEqual(sigmascope.MAX_ARCHIVE_ENTRIES, 2_342)
        self.assertGreater(sigmascope.MAX_ARCHIVE_UNCOMPRESSED, sigmascope.MAX_ARTIFACT_BYTES)


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
            "scannerVersion": "2.14.0",
            "lastValidatedAtUtc": "2026-08-15T11:00:00Z",
            "assemblyVersion": "1.2.3.4",
            "artifactUrl": "https://example.invalid/plugin.zip",
        }
        self.assertTrue(sigmascope.ledger_entry_is_fresh(entry, "1.2.3.4", "https://example.invalid/plugin.zip", now, 168))
        self.assertFalse(sigmascope.ledger_entry_is_fresh(entry, "1.2.3.5", "https://example.invalid/plugin.zip", now, 168))
        stale = dict(entry, lastValidatedAtUtc="2026-08-01T00:00:00Z")
        self.assertFalse(sigmascope.ledger_entry_is_fresh(stale, "1.2.3.4", "https://example.invalid/plugin.zip", now, 168))


if __name__ == "__main__":
    unittest.main()

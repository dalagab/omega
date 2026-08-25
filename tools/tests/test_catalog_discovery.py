from __future__ import annotations
import json, os, tempfile, unittest
from pathlib import Path
from unittest import mock

import common  # noqa: F401
import catalog_discovery
import collect_sources
import enrich_metadata


class CatalogDiscoveryTests(unittest.TestCase):
    def _catalog(self, root: Path) -> Path:
        catalog = root / "catalog"
        (catalog / "sources").mkdir(parents=True)
        (catalog / "plugins").mkdir(parents=True)
        (catalog / "sources" / "index.json").write_text(json.dumps({
            "sources": [{"sourceId": 1, "url": "https://known.example/repo.json"}]
        }), encoding="utf-8")
        (catalog / "plugins" / "index.json").write_text(json.dumps({
            "plugins": [{"internalName": "Existing", "path": "plugins/0001.json"}]
        }), encoding="utf-8")
        (catalog / "plugins" / "0001.json").write_text(json.dumps({
            "plugin": {"plugin_id": 1, "internal_name": "Existing"},
            "variants": [{"variant": {"source_id": 1, "assembly_version": "1.0.0"}}],
        }), encoding="utf-8")
        return catalog

    def test_known_source_is_skipped_and_novel_facts_are_classified(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            catalog = self._catalog(Path(td))
            calls = []
            def fetcher(source, **kwargs):
                calls.append(source["url"])
                return {
                    "ok": True, "url": source["url"], "provider": "Novel", "kind": "scanned",
                    "discoveredBy": "github-code-search", "sourceRepoUrl": "https://github.com/example/repo",
                    "resolvedUrl": source["url"], "contentSha256": "a" * 64, "etag": "etag", "lastModified": "",
                    "pluginCount": 2,
                    "plugins": [
                        {"internalName": "Existing", "name": "Existing", "assemblyVersion": "2.0.0", "dalamudApiLevel": 15},
                        {"internalName": "BrandNew", "name": "Brand New", "assemblyVersion": "1.0.0", "dalamudApiLevel": 15},
                    ],
                }
            candidates = {"sources": [
                {"url": "https://known.example/repo.json", "provider": "Known"},
                {"url": "https://novel.example/repo.json", "provider": "Novel"},
            ]}
            issues = {"schema": catalog_discovery.ISSUE_SCHEMA, "issues": [], "trackedUrls": ["https://novel.example/repo.json"]}
            with mock.patch.object(catalog_discovery, "public_https_url", return_value=True):
                result = catalog_discovery.discover(candidates, catalog, fetcher=fetcher, issue_hints=issues)
            self.assertEqual(["https://novel.example/repo.json"], calls, "known canonical sources must not be fetched again")
            self.assertEqual(1, result["knownSourcesSkipped"])
            self.assertEqual(1, result["validatedNovelSources"])
            self.assertEqual(1, result["newPluginFacts"])
            self.assertEqual(1, result["newVariantFacts"])
            self.assertTrue(result["sources"][0]["trackedByOpenIssue"])
            self.assertEqual({"new-plugin", "new-source-variant"}, {x["classification"] for x in result["pluginFacts"]})

    def test_snapshot_writes_reusable_normalized_source_shard(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            result = {
                "generatedAtUtc": catalog_discovery.utc_now(),
                "knownSourceCount": 0, "candidateSourceCount": 1, "knownSourcesSkipped": 0,
                "validatedNovelSources": 1, "invalidNovelSources": 0, "newPluginFacts": 1, "newVariantFacts": 0,
                "sources": [{
                    "url": "https://novel.example/repo.json", "provider": "Novel",
                    "enrichedPath": "enriched/novel.json",
                }],
                "enrichedSources": [{
                    "path": "enriched/novel.json",
                    "source": {
                        "ok": True, "url": "https://novel.example/repo.json", "provider": "Novel",
                        "plugins": [{"internalName": "BrandNew", "assemblyVersion": "1.0.0"}],
                    },
                }],
                "pluginFacts": [{"classification": "new-plugin", "internalName": "BrandNew"}],
                "issues": {"schema": catalog_discovery.ISSUE_SCHEMA, "issues": [], "trackedUrls": []},
            }
            catalog_discovery.write_snapshot(result, root)
            source_doc = json.loads((root / "source-candidates.json").read_text(encoding="utf-8"))
            shard_path = root / source_doc["sources"][0]["enrichedPath"]
            shard = json.loads(shard_path.read_text(encoding="utf-8"))
            self.assertEqual("omega.catalog-discovery.enriched-source.v1", shard["schema"])
            self.assertTrue(shard["source"]["ok"])
            self.assertEqual("BrandNew", shard["source"]["plugins"][0]["internalName"])

    def test_daily_enrichment_reuses_fresh_discovery_shard_without_refetch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "discovery"
            root.mkdir(parents=True)
            generated = catalog_discovery.utc_now()
            (root / "index.json").write_text(json.dumps({
                "schema": catalog_discovery.SCHEMA, "generatedAtUtc": generated,
            }), encoding="utf-8")
            (root / "source-candidates.json").write_text(json.dumps({
                "schema": catalog_discovery.SOURCE_SCHEMA, "generatedAtUtc": generated,
                "sources": [{
                    "url": "https://novel.example/repo.json",
                    "enrichedPath": "enriched/novel.json",
                }],
            }), encoding="utf-8")
            (root / "enriched").mkdir()
            reusable = {
                "ok": True, "url": "https://novel.example/repo.json", "provider": "Novel",
                "kind": "scanned", "plugins": [{
                    "internalName": "BrandNew", "name": "Brand New",
                    "assemblyVersion": "1.0.0", "dalamudApiLevel": 15, "metadataComplete": False,
                }],
            }
            (root / "enriched" / "novel.json").write_text(json.dumps({
                "schema": "omega.catalog-discovery.enriched-source.v1",
                "generatedAtUtc": generated, "source": reusable,
            }), encoding="utf-8")

            discovery = enrich_metadata.load_discovery_enrichment(str(root), 24)
            self.assertIn("https://novel.example/repo.json", discovery)
            with mock.patch.object(enrich_metadata, "fetch_sources_parallel", side_effect=AssertionError("fresh discovery source must not be fetched again")):
                records, reused = enrich_metadata.fetch_sources_with_discovery(
                    [{"url": "https://novel.example/repo.json", "provider": "Novel"}],
                    concurrency=2, timeout=5, cache={}, discovery=discovery,
                )
            self.assertEqual(1, reused)
            self.assertEqual(1, len(records))
            self.assertEqual("BrandNew", records[0]["plugins"][0]["internalName"])

    def test_canonical_source_index_keeps_previously_discovered_feeds_without_search(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            index = root / "sources-index.json"
            index.write_text(json.dumps({"sources": [
                {"sourceId": 99, "url": "https://historical.example/repo.json", "provider": "Historical"}
            ]}), encoding="utf-8")
            rows = collect_sources.collect_canonical_source_index(str(index))
            self.assertEqual(1, len(rows))
            self.assertEqual("https://historical.example/repo.json", rows[0]["url"])
            self.assertEqual("catalog-data/sources/index.json", rows[0]["discoveredBy"])

    def test_fresh_discovery_snapshot_replaces_duplicate_github_search(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            curated = root / "curated.json"; curated.write_text("[]", encoding="utf-8")
            community = root / "community.json"; community.write_text("[]", encoding="utf-8")
            snapshot = root / "source-candidates.json"
            snapshot.write_text(json.dumps({
                "schema": "omega.catalog-discovery.sources.v1",
                "generatedAtUtc": catalog_discovery.utc_now(),
                "sources": [{"url": "https://novel.example/repo.json", "provider": "Novel", "kind": "scanned"}],
            }), encoding="utf-8")
            with mock.patch.object(collect_sources, "collect_punish_publisher_urls", return_value=[]), \
                 mock.patch.object(collect_sources, "collect_curated_urls", return_value=[]), \
                 mock.patch.object(collect_sources, "collect_github_search_urls", side_effect=AssertionError("GitHub search should be skipped")), \
                 mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}):
                result = collect_sources.collect(
                    verbose=False, curated_path=str(curated), community_path=str(community), discovery_path=str(snapshot)
                )
            self.assertTrue(result["metadata"]["discoverySnapshotFresh"])
            self.assertEqual(1, result["metadata"]["sourceCounts"]["discoverySnapshot"])
            self.assertEqual(0, result["metadata"]["sourceCounts"]["githubSearch"])
            self.assertEqual("https://novel.example/repo.json", result["sources"][0]["url"])

    def test_project_page_collector_turns_canonical_readme_json_and_repo_links_into_candidates(self) -> None:
        import discovery_collectors
        with tempfile.TemporaryDirectory() as td:
            catalog = self._catalog(Path(td))
            (catalog / "websites").mkdir(parents=True)
            (catalog / "websites" / "index.json").write_text(json.dumps({
                "websites": [{"websiteId": 1, "url": "https://github.com/example/plugin", "ok": True, "path": "websites/000001.json"}]
            }), encoding="utf-8")
            (catalog / "websites" / "000001.json").write_text(json.dumps({
                "website": {
                    "url": "https://github.com/example/plugin", "ok": 1, "homepage": "",
                    "links_json": "[]",
                    "metadata_json": json.dumps({"rawLinks": [
                        "https://raw.githubusercontent.com/example/other/main/repo.json",
                        "https://github.com/example/related"
                    ]}),
                }
            }), encoding="utf-8")
            result = discovery_collectors.project_page_candidates(catalog)
            self.assertEqual(1, len(result["sources"]))
            self.assertEqual(discovery_collectors.COLLECTOR_PROJECT, result["sources"][0]["collectorId"])
            repos = {row["repositoryUrl"] for row in result["repositoryCandidates"]}
            self.assertIn("https://github.com/example/plugin", repos)
            self.assertIn("https://github.com/example/related", repos)

    def test_repository_tree_collector_is_bounded_and_emits_likely_manifest_json(self) -> None:
        import discovery_collectors
        calls = []
        def github_json(url, token, timeout):
            calls.append(url)
            if "/git/trees/" in url:
                return {"tree": [
                    {"type": "blob", "path": "repo.json"},
                    {"type": "blob", "path": "docs/random.json"},
                    {"type": "blob", "path": "manifests/pluginmaster.json"},
                ]}
            return {"default_branch": "main"}
        result = discovery_collectors.repository_tree_candidates(
            [{"repositoryUrl": "https://github.com/example/plugin"}], "token", github_json=github_json
        )
        self.assertEqual(1, result["repositoriesInspected"])
        self.assertEqual(2, len(result["sources"]))
        self.assertTrue(all(row["collectorId"] == discovery_collectors.COLLECTOR_TREE for row in result["sources"]))
        self.assertEqual(2, len(calls))

    def test_web_search_is_optional_and_query_provenance_is_retained(self) -> None:
        import discovery_collectors
        self.assertFalse(discovery_collectors.web_search_candidates("")["enabled"])
        calls = []
        def searcher(query, key, timeout):
            calls.append(query)
            return {"web": {"results": [{
                "url": "https://raw.githubusercontent.com/example/plugin/main/repo.json", "title": "Dalamud repo"
            }]}}
        result = discovery_collectors.web_search_candidates("key", searcher=searcher)
        self.assertTrue(result["enabled"])
        self.assertGreaterEqual(len(calls), 1)
        self.assertEqual(1, len(result["sources"]))
        self.assertEqual(discovery_collectors.COLLECTOR_WEB, result["sources"][0]["collectorId"])
        self.assertIn("query", result["sources"][0]["provenance"])

    def test_snapshot_contains_typed_collector_observations_and_registry(self) -> None:
        import collector_contracts
        import component_registry
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            result = {
                "generatedAtUtc": "2026-08-24T12:00:00Z",
                "knownSourceCount": 0, "candidateSourceCount": 1, "knownSourcesSkipped": 0,
                "validatedNovelSources": 1, "invalidNovelSources": 0, "newPluginFacts": 1, "newVariantFacts": 0,
                "sources": [{
                    "url": "https://novel.example/repo.json", "provider": "Novel", "kind": "scanned",
                    "pluginCount": 1, "contentSha256": "a" * 64, "discoveredBy": "github-code-search",
                    "sourceRepoUrl": "https://github.com/example/novel", "trackedByOpenIssue": False,
                    "enrichedPath": "enriched/novel.json",
                    "originCollectorId": "omega.collector.discovery.github-code-search",
                }],
                "enrichedSources": [],
                "pluginFacts": [{
                    "classification": "new-plugin", "internalName": "BrandNew", "name": "Brand New",
                    "assemblyVersion": "1.0.0", "testingAssemblyVersion": "", "dalamudApiLevel": 15,
                    "testingDalamudApiLevel": None, "sourceUrl": "https://novel.example/repo.json",
                    "sourceProvider": "Novel", "repoUrl": "https://github.com/example/novel",
                    "originCollectorId": "omega.collector.discovery.github-code-search",
                }],
                "issues": {"schema": catalog_discovery.ISSUE_SCHEMA, "issues": [], "trackedUrls": []},
                "projectLinks": [], "repositoryCandidateRows": [], "manifestCandidates": [],
            }
            catalog_discovery.write_snapshot(result, root)
            observations = json.loads((root / "observations.json").read_text(encoding="utf-8"))
            registry = json.loads((root / "collector-registry.json").read_text(encoding="utf-8"))
            components = json.loads((root / "component-registry.json").read_text(encoding="utf-8"))
            self.assertEqual(collector_contracts.BUNDLE_SCHEMA, observations["schema"])
            self.assertEqual(1, observations["collections"]["catalogPluginFacts"]["records"])
            row = observations["collections"]["catalogPluginFacts"]["rows"][0]
            self.assertEqual("omega.collector.discovery.pluginmaster-validator", row["_collector"]["id"])
            self.assertEqual(collector_contracts.registry_revision(), registry["revision"])
            self.assertEqual(component_registry.component_revision(), components["revision"])
            index = json.loads((root / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(component_registry.component_revision(), index["componentRegistryRevision"])


if __name__ == "__main__": unittest.main()

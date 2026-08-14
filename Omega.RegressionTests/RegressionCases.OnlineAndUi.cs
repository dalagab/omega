using System.Buffers.Binary;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dalagab.Omega;

namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestCatalogBuilderContract()
    {
        var workflowPath = Path.Combine(Root, ".github", "workflows", "catalog-builder.yml");
        True(File.Exists(workflowPath), "catalog-builder workflow exists");
        var workflow = File.ReadAllText(workflowPath);
        Contains(workflow, "schedule:", "scheduled discovery/update job");
        Contains(workflow, "discover_sources.py", "GitHub discovery stage");
        Contains(workflow, "build_catalog.py", "catalog validation/build stage");
        Contains(workflow, "test_catalog_pipeline.py", "catalog pipeline self-test runs before publication");
        Contains(workflow, "known-bad-hashes.json", "bad-content denylist is part of the workflow");
        Contains(workflow, "catalog-latest", "stable downloadable catalog release");
        Contains(workflow, "actions/upload-artifact", "catalog database is downloadable as an Actions artifact");
        Contains(workflow, "Download previous catalog database seed", "runner reuses the previous release database as a conditional-request seed");
        Contains(workflow, "--seed-bundle", "builder receives the previous database seed");
        Contains(workflow, "catalog/dist/catalog.json", "runner publishes tiny online catalog descriptor");
        Contains(workflow, "catalog/dist/catalog-endpoint.json", "runner emits the repository-specific client endpoint file");
        Contains(workflow, "omega-catalog-db.zip.sha256", "stable release publishes companion checksum");
        Contains(workflow, "Smoke-test published catalog download", "published release is tested through the public client download path");
        Contains(workflow, "test_live_catalog.py", "live release smoke tester runs after publication");

        var liveSmoke = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "test_live_catalog.py"));
        Contains(liveSmoke, "Omega live catalog smoke test passed", "live smoke tester validates downloadable catalog");
        Contains(liveSmoke, "bundle SHA mismatch", "live smoke tester verifies exact bundle bytes");
        Contains(liveSmoke, "record count mismatch", "live smoke tester verifies database completeness");

        var builder = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "build_catalog.py"));
        Contains(builder, "known_bad.get(raw_hash.lower())", "known content hashes are skipped before parsing");
        Contains(builder, "known-bad-git-blob", "known GitHub blob hashes are skipped before downloading unchanged bad candidates");
        Contains(builder, "merge_bad_entry", "new deterministic bad hashes are recorded");
        Contains(builder, "transient-error", "network failures do not poison the bad-hash list");
        Contains(builder, "omega-catalog-db.zip", "builder emits importable database ZIP");
        Contains(builder, "omega-catalog-db.zip.sha256", "builder emits downloadable database checksum");
        Contains(builder, "omega.catalog.v1", "builder emits hash-addressed catalog.json descriptor");
        Contains(builder, "catalogSha256", "descriptor contains stable semantic catalog hash");
        Contains(builder, "bundleSha256", "descriptor separately authenticates exact bundle bytes");
        Contains(builder, "fingerprint_records", "catalog hash ignores operational timestamp-only bundle changes");
        Contains(builder, "downloadUrl", "descriptor names the catalog database download");
        Contains(builder, "catalog-endpoint.json", "builder emits client endpoint configuration");
        Contains(builder, "If-None-Match", "runner uses ETag validators from the previous database");
        Contains(builder, "If-Modified-Since", "runner uses Last-Modified validators from the previous database");
        Contains(builder, "load_seed_bundle", "runner can seed from the previous downloadable database");
        Contains(builder, "retainedLastKnownGood", "runner preserves last-known-good metadata on repository failures");

        var pipelineTests = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "test_catalog_pipeline.py"));
        Contains(pipelineTests, "known-bad-git-blob", "pipeline self-test covers pre-download bad-blob skip");
        Contains(pipelineTests, "new-bad-hash", "pipeline self-test covers deterministic bad-content classification");
        Contains(pipelineTests, "seed bundle round-trip", "pipeline self-test covers previous-database reuse");

        using var knownBad = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "catalog", "known-bad-hashes.json")));
        Equal(1, knownBad.RootElement.GetProperty("schemaVersion").GetInt32(), "known-bad schema");

        using var candidates = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "catalog", "candidates.json")));
        True(candidates.RootElement.GetProperty("count").GetInt32() >= 470, "uploaded discovery batches seed the candidate queue");

        foreach (var file in new[] { "dalamud_batch1.json", "dalamud_batch2.json", "dalamud_batch3.json" })
            True(File.Exists(Path.Combine(Root, "sources", "discovery", file)), $"discovery seed retained: {file}");
    }

    internal static void TestOnlineCatalogFallbackContract()
    {
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CatalogUpdateCoordinator.cs"));
        Contains(coordinator, "TryApplyOnlineCatalogAsync", "online catalog is attempted first");
        Contains(coordinator, "await catalog.RefreshAsync(configuration.Repositories)", "complete local source list is the fallback");
        Contains(coordinator, "RefreshOverlayRepositoriesAsync", "successful central DB layers local marketplace overlays");
        Contains(coordinator, "source.IsOfficial || !source.IsCurated", "official/default and user-added repositories remain live overlays");
        Contains(coordinator, "stateStore.ClearAppliedCatalog", "fallback invalidates the central-hash shortcut after local records mutate");
        Contains(coordinator, "SeedIfEmpty", "fresh install can acquire a catalog without blocking plugin construction");

        var database = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CatalogDatabase.cs"));
        Contains(database, "ReplaceAll", "central bundle replaces the authoritative database snapshot");
        Contains(database, ".staging-", "central database replacement is staged before swap");
        Contains(database, "preservedLocalRecords", "user-added repository records survive central replacement");

        var temp = Path.Combine(Path.GetTempPath(), $"omega-regression-replace-{Guid.NewGuid():N}");
        try
        {
            var db = new CatalogDatabase(temp);
            var oldCurated = db.Store("https://example.invalid/old.json", "[{\"Name\":\"Old\",\"InternalName\":\"Old\"}]", null, null, DateTimeOffset.UtcNow.AddMinutes(-10));
            var local = db.Store("https://example.invalid/local.json", "[{\"Name\":\"Local\",\"InternalName\":\"Local\"}]", null, null, DateTimeOffset.UtcNow.AddMinutes(-5));
            var replacementManifest = "[{\"Name\":\"New\",\"InternalName\":\"New\"}]";
            var replacement = new CatalogDatabaseRecord
            {
                SchemaVersion = 1,
                Url = "https://example.invalid/new.json",
                ManifestJson = replacementManifest,
                ContentSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(replacementManifest))).ToLowerInvariant(),
                FetchedAtUtc = DateTimeOffset.UtcNow,
                CheckedAtUtc = DateTimeOffset.UtcNow,
            };
            db.ReplaceAll(new[] { replacement }, new[] { local });
            True(db.TryRead("https://example.invalid/new.json") is not null, "authoritative replacement record exists");
            True(db.TryRead("https://example.invalid/local.json") is not null, "preserved local record exists");
            True(db.TryRead("https://example.invalid/old.json") is null, "obsolete curated record is removed by authoritative replacement");
        }
        finally
        {
            try { Directory.Delete(temp, true); } catch { }
        }
    }

    internal static void TestDalamudDefaultCatalogContract()
    {
        var bridge = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudDefaultCatalogBridge.cs"));
        Contains(bridge, "AvailablePlugins", "default catalogue comes from Dalamud's already-loaded available plugins");
        Contains(bridge, "IsThirdParty", "bridge distinguishes the official repository from third-party repositories");
        Contains(bridge, "SourceIsOfficial = true", "default entries retain official provenance");
        False(bridge.Contains("HttpClient", StringComparison.Ordinal), "reading Dalamud defaults must not create startup network traffic");

        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(plugin, "RefreshDefaultCatalog()", "default catalogue is merged during construction and when Omega opens");
        Contains(plugin, "defaultCatalogBridge.ReadAvailable()", "Omega reads the current in-memory Dalamud defaults");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "SetDefaultPlugins", "marketplace accepts runtime default plugin metadata");
        Contains(catalog, "databaseVariants", "database variants remain separate from runtime defaults");
        Contains(catalog, "defaultPlugins", "runtime defaults participate in the storefront projection");
        Contains(catalog, "!x.SourceIsOfficial || !runtimeNames.Contains", "runtime official metadata replaces stale cached official duplicates only");

        Contains(catalog, "HasLoaded = CachedRepositoryCount > 0", "runtime defaults do not suppress fresh central-catalog seeding");
        False(catalog.Contains("CachedRepositoryCount > 0 || defaultPlugins.Count > 0", StringComparison.Ordinal), "runtime defaults must not masquerade as a complete database");

        using var curated = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "sources", "curated-sources.json")));
        True(curated.RootElement.EnumerateArray().Any(x =>
            x.GetProperty("id").GetString() == "dalamud-official" &&
            x.GetProperty("isOfficial").GetBoolean()), "official source remains bundled and identifiable");
    }

    internal static void TestOnlineCatalogDescriptorHelpers()
    {
        True(OnlineCatalogClient.IsValidSha256(new string('a', 64)), "64 hex characters form a valid SHA-256");
        False(OnlineCatalogClient.IsValidSha256(new string('g', 64)), "non-hex SHA-256 is rejected");
        False(OnlineCatalogClient.IsValidSha256("abc"), "short SHA-256 is rejected");

        var splitHashes = new OnlineCatalogDescriptor
        {
            CatalogSha256 = new string('a', 64),
            BundleSha256 = new string('b', 64),
            Sha256 = new string('c', 64),
        };
        Equal(new string('a', 64), OnlineCatalogClient.EffectiveCatalogSha256(splitHashes), "semantic catalog hash drives change detection");
        Equal(new string('b', 64), OnlineCatalogClient.EffectiveBundleSha256(splitHashes), "exact bundle hash drives downloaded ZIP verification");

        var legacyHashes = new OnlineCatalogDescriptor { Sha256 = new string('c', 64) };
        Equal(new string('c', 64), OnlineCatalogClient.EffectiveCatalogSha256(legacyHashes), "legacy descriptor hash remains accepted for catalog comparison");
        Equal(new string('c', 64), OnlineCatalogClient.EffectiveBundleSha256(legacyHashes), "legacy descriptor hash remains accepted for bundle verification");

        var descriptor = new Uri("https://example.invalid/releases/catalog.json");
        Equal("https://example.invalid/releases/omega-catalog-db.zip",
            OnlineCatalogClient.ResolveDownloadUri(descriptor, "omega-catalog-db.zip").ToString(),
            "relative database URL resolves against descriptor");
        Equal("https://cdn.example.invalid/omega-catalog-db.zip",
            OnlineCatalogClient.ResolveDownloadUri(descriptor, "https://cdn.example.invalid/omega-catalog-db.zip").ToString(),
            "absolute HTTPS database URL is accepted");
        Throws<InvalidDataException>(
            () => OnlineCatalogClient.ResolveDownloadUri(descriptor, "http://example.invalid/catalog.zip"),
            "non-HTTPS central catalog is rejected");

        var endpoint = File.ReadAllText(Path.Combine(Root, "catalog", "catalog-endpoint.json"));
        Contains(endpoint, "descriptorUrl", "source package carries endpoint configuration seeded by GitHub Actions");
        Contains(endpoint, "https://github.com/dalagab/omega/releases/download/catalog-latest/catalog.json", "source package ships the live production catalog endpoint");
        False(endpoint.Contains("\"descriptorUrl\": \"\"", StringComparison.Ordinal), "production catalog endpoint must not ship blank");
        var project = File.ReadAllText(Path.Combine(Root, "Omega", "DalagabOmega.csproj"));
        Contains(project, "catalog-endpoint.json", "catalog endpoint is packaged with Omega");
    }


    internal static void TestLiveCatalogEndpointContract()
    {
        using var endpoint = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "catalog", "catalog-endpoint.json")));
        Equal(1, endpoint.RootElement.GetProperty("schemaVersion").GetInt32(), "live endpoint schema");
        Equal(
            "https://github.com/dalagab/omega/releases/download/catalog-latest/catalog.json",
            endpoint.RootElement.GetProperty("descriptorUrl").GetString(),
            "live production descriptor URL");

        var workflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "catalog-builder.yml"));
        var publishIndex = workflow.IndexOf("Publish stable downloadable catalog release", StringComparison.Ordinal);
        var smokeIndex = workflow.IndexOf("Smoke-test published catalog download", StringComparison.Ordinal);
        True(publishIndex >= 0 && smokeIndex > publishIndex, "public download smoke test runs after release publication");
        Contains(workflow, "--expected-bundle catalog/dist/omega-catalog-db.zip", "published bytes must match the just-built database bundle");
    }

    internal static void TestStorefrontVirtualization()
    {
        var first = StorefrontVirtualization.Calculate(
            itemCount: 727,
            columns: 5,
            rowHeight: 210f,
            scrollY: 0f,
            viewportHeight: 700f,
            contentStartY: 60f,
            bufferRows: 1);
        Equal(146, first.TotalRows, "727 plugins at five columns produce 146 rows");
        Equal(0, first.FirstRow, "top of storefront starts at first row");
        True(first.LastRowExclusive <= 5, "top viewport submits only a bounded row window");

        var middle = StorefrontVirtualization.Calculate(
            itemCount: 727,
            columns: 5,
            rowHeight: 210f,
            scrollY: 8400f,
            viewportHeight: 700f,
            contentStartY: 60f,
            bufferRows: 1);
        True(middle.FirstRow > 30, "deep scroll skips preceding rows");
        True(middle.LastRowExclusive - middle.FirstRow <= 7, "deep scroll still submits only visible rows plus buffer");
    }

    internal static void TestOpenWindowPerformanceGuards()
    {
        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "DrawVirtualizedDiscoverGrid", "Discover must virtualize its fixed five-column rows");
        Contains(ui, "StorefrontVirtualization.Calculate", "virtualization helper must drive visible rows");
        Contains(ui, "stableIdCache", "ImGui IDs must not SHA-256 the same strings every frame");
        Contains(ui, "GetFilteredPlugins", "filter/sort results must be cached between UI frames");
        Contains(ui, "GetTopCategories", "category aggregation must be cached between UI frames");
        Contains(ui, "GetSidebarCounts", "sidebar catalog metrics must be cached between UI frames");
        Contains(ui, "configuredSourceByUrl", "source readiness must use an indexed configuration lookup");
        False(ui.Contains("appIconTexture", StringComparison.Ordinal), "removed header logo must not keep a cached UI texture");
        Contains(ui, "fallbackIconTexture", "fallback shared texture must be cached");
        False(ui.Contains("Plugin.TextureProvider.GetFromFile(fallbackIconPath).GetWrapOrDefault()", StringComparison.Ordinal),
            "fallback GetFromFile must not run for every tile on every frame");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "variantsByInternalName", "variant lookups must use an index");
        Contains(catalog, "repositoryStatusCache", "repository health must not be rebuilt every frame");
        Contains(catalog, "mainProjectionCache", "stale/source projection must be cached");
        Contains(catalog, "mainVariantIndexCache", "installability lookups must not rescan the marketplace");
        Contains(catalog, "loadedRepositoryUrlSet", "configured-source check must avoid sorting all sources every frame");
        Contains(catalog, "public long Revision", "UI caches need a deterministic catalog invalidation revision");

        var icons = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginIconCache.cs"));
        Contains(icons, "MaximumConcurrentIconLoads = 2", "image downloads/decodes must be bounded");
        Contains(icons, "loadGate.WaitAsync", "icon load concurrency gate must be active");
    }

    internal static void TestMarketplaceTagRules()
    {
        var variants = new[]
        {
            new MarketplacePlugin
            {
                Name = "Alpha",
                InternalName = "Alpha",
                Tags = ["utility", "combat", "UI"],
            },
            new MarketplacePlugin
            {
                Name = "Alpha mirror",
                InternalName = "Alpha",
                Tags = ["Utility", "chat", "ui"],
            },
            new MarketplacePlugin
            {
                Name = "Beta",
                InternalName = "Beta",
                Tags = ["UTILITY", "chat"],
            },
            new MarketplacePlugin
            {
                Name = "Gamma",
                InternalName = "Gamma",
                Tags = ["gpose"],
            },
        };

        var index = MarketplaceTagRules.Build(variants);
        Equal(5, index.Tags.Count, "case-insensitive tag count");

        var utility = index.Tags.Single(x => x.Name.Equals("utility", StringComparison.OrdinalIgnoreCase));
        Equal("utility", utility.Name, "lowercase spelling is preferred when present");
        Equal(2, utility.PluginCount, "duplicate repository variants count once per plugin");

        True(index.MatchesAll("Alpha", ["utility", "chat"]), "Alpha has both required tags across variants");
        False(index.MatchesAll("Beta", ["utility", "combat"]), "AND matching rejects a plugin missing one tag");
        True(index.MatchesAll("Gamma", []), "empty tag selection matches every plugin");
    }

    internal static void TestSearchableTagPickerContract()
    {
        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "Narrow by tag", "tag picker uses Steam-like narrowing language");
        Contains(ui, "##omega-tag-search", "tag picker has searchable input");
        Contains(ui, "all selected tags must match", "multi-tag semantics are explicit AND matching");
        Contains(ui, "Selected tags:", "selected tags remain visible as removable chips");
        Contains(ui, "Take(needle.Length == 0 ? 120 : 250)", "tag popup draw work is bounded");
        Contains(ui, "catalog.GetTagIndex(currentApi, selectedSource)", "tag index respects repository filtering");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "tagIndexCache", "tag aggregation is cached outside the draw loop");
        Contains(catalog, "MarketplaceTagRules.Build", "production catalog builds the shared tag index helper");

        var project = File.ReadAllText(Path.Combine(Root, "Omega.RegressionTests", "Omega.RegressionTests.csproj"));
        Contains(project, "MarketplaceTagRules.cs", "tag behavior helper is exercised by the build-time regression suite");
    }

}

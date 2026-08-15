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
        var workflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "catalog-builder.yml"));
        Contains(workflow, "collect_sources.py", "online source discovery stage");
        Contains(workflow, "enrich_metadata.py", "manifest normalization stage");
        Contains(workflow, "scrape_websites_incremental.py", "incremental website enrichment stage");
        Contains(workflow, "build_sqlite_catalog.py", "SQLite build stage");
        Contains(workflow, "test_sqlite_catalog.py", "SQLite builder self-test stage");
        Contains(workflow, "omega-security-evidence.sqlite.zip", "builder seeds authoritative server-side evidence state");
        Contains(workflow, "omega-marketplace.sqlite.zip", "builder reuses the small client database for presentation caches");
        Contains(workflow, "Download previous marketplace database", "small client database supplies presentation/enrichment cache");
        Contains(workflow, "Download previous security evidence database as authoritative seed", "full evidence database remains the authoritative server-side build seed");
        Contains(workflow, "--seed-database catalog/seed/omega-catalog.sqlite", "manifest fetches use prior ETag/Last-Modified state");
        Contains(workflow, "validate_base_catalog.py", "generated database and transport are validated by tested Python");
        Contains(workflow, "name: omega-sqlite-catalog", "validated base catalog is handed to the security workflow");
        False(workflow.Contains("gh release upload catalog-latest", StringComparison.Ordinal), "base catalog builder cannot publish an intermediate production database");

        var builder = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "build_sqlite_catalog.py"));
        Contains(builder, "CREATE TABLE IF NOT EXISTS plugins", "SQLite plugin table");
        Contains(builder, "CREATE TABLE IF NOT EXISTS plugin_variants", "SQLite variant table");
        Contains(builder, "CREATE TABLE IF NOT EXISTS websites", "SQLite website cache table");
        Contains(builder, "CREATE TABLE IF NOT EXISTS presentation", "presentation scoring table");
        Contains(builder, "CREATE TABLE IF NOT EXISTS plugin_search", "normalized search table");
        Contains(builder, "raw_manifest_json", "original source manifest fields remain auditable");
        Contains(builder, "VACUUM", "database is compacted before publication");
        Contains(builder, "omega.catalog.sqlite.v1", "strict SQLite descriptor schema");

        var scraper = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "scrape_websites_incremental.py"));
        Contains(scraper, "last_success_utc", "successful website enrichment is reusable");
        Contains(scraper, "max-age-hours", "fresh website data avoids unnecessary re-scraping");
        Contains(scraper, "seed-database", "previous SQLite database supplies enrichment cache");
        Contains(scraper, "load_seed_repo_urls", "304 manifests do not freeze stale website rechecks");
    }

    internal static void TestOnlineCatalogFallbackContract()
    {
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CatalogUpdateCoordinator.cs"));
        Contains(coordinator, "TryApplyOnlineCatalogAsync", "online SQLite catalog is checked first");
        Contains(coordinator, "retaining local database", "network failure retains last-known-good SQLite");
        False(coordinator.Contains("LocalFallback", StringComparison.Ordinal), "public catalog is not rebuilt by crawling repositories in-game");
        False(coordinator.Contains("await catalog.RefreshAsync(configuration.Repositories)", StringComparison.Ordinal), "central failure does not fan out across public sources");
        Contains(coordinator, "!x.IsCurated", "user-added sources can remain explicit temporary overlays");

        var store = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "SqliteCatalogStore.cs"));
        Contains(store, "ReplaceFromBundle", "SQLite update replaces one database");
        Contains(store, "omega-catalog.staged-", "replacement is staged before swap");
        Contains(store, "omega-catalog.backup-", "failed swap can restore previous database");
        Contains(store, "PRAGMA integrity_check", "candidate database is validated before activation");
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

        Contains(catalog, "HasLoaded = databaseVariants.Count > 0", "runtime defaults do not suppress fresh central-catalog seeding");
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
        True(OnlineCatalogClient.IsValidCatalogRevision("cat-v1-0123456789abcdef"), "semantic Catalog Revision format is accepted");
        False(OnlineCatalogClient.IsValidCatalogRevision("cat-v1-not-a-hash"), "malformed Catalog Revision is rejected");
        True(OnlineCatalogClient.IsValidSecurityRevision("sec-2.0.0-0123456789abcdef"), "semantic Security Revision format is accepted");
        False(OnlineCatalogClient.IsValidSecurityRevision("sec-2.0.0-short"), "malformed Security Revision is rejected");
        True(OnlineCatalogClient.IsValidEvidenceRevision("ev-v1-0123456789abcdef"), "semantic Evidence Revision format is accepted");
        False(OnlineCatalogClient.IsValidEvidenceRevision("ev-v1-short"), "malformed Evidence Revision is rejected");

        var hashes = new OnlineCatalogDescriptor
        {
            CatalogSha256 = new string('a', 64),
            BundleSha256 = new string('b', 64),
        };
        Equal(new string('a', 64), OnlineCatalogClient.EffectiveCatalogSha256(hashes), "database hash drives change detection");
        Equal(new string('b', 64), OnlineCatalogClient.EffectiveBundleSha256(hashes), "ZIP hash authenticates transport bytes");

        var descriptor = new Uri("https://example.invalid/releases/catalog.json");
        Equal("https://example.invalid/releases/omega-marketplace.sqlite.zip",
            OnlineCatalogClient.ResolveDownloadUri(descriptor, "omega-marketplace.sqlite.zip").ToString(),
            "relative SQLite URL resolves against descriptor");
        Throws<InvalidDataException>(
            () => OnlineCatalogClient.ResolveDownloadUri(descriptor, "http://example.invalid/catalog.zip"),
            "non-HTTPS central catalog is rejected");

        var client = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "OnlineCatalogClient.cs"));
        Contains(client, "omega.catalog.sqlite.v1", "client accepts only the SQLite catalog descriptor schema");
        False(client.Contains("omega.catalog.v1", StringComparison.Ordinal), "legacy JSON bundle schema removed");
    }

    internal static void TestLiveCatalogEndpointContract()
    {
        using var endpoint = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "catalog", "catalog-endpoint.json")));
        Equal(1, endpoint.RootElement.GetProperty("schemaVersion").GetInt32(), "live endpoint schema");
        Equal("https://github.com/dalagab/omega/releases/download/catalog-latest/catalog.json",
            endpoint.RootElement.GetProperty("descriptorUrl").GetString(), "live production descriptor URL");

        var builder = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "catalog-builder.yml"));
        False(builder.Contains("gh release upload catalog-latest", StringComparison.Ordinal), "base catalog builder never publishes an intermediate production database");
        Contains(builder, "name: omega-sqlite-catalog", "base catalog is handed to security analysis as an Actions artifact");

        var workflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "catalog-compaction.yml"));
        var publishIndex = workflow.IndexOf("Replace small client catalog assets only", StringComparison.Ordinal);
        var verifyIndex = workflow.IndexOf("Verify published marketplace database", StringComparison.Ordinal);
        True(publishIndex >= 0 && verifyIndex > publishIndex, "published marketplace SQLite bundle is verified after release upload");
        Contains(workflow, "omega-marketplace.sqlite.zip", "client release contains only the marketplace SQLite transport bundle");
        Contains(workflow, "omega-security-evidence.sqlite.zip", "detailed evidence is published to its separate release");
        Contains(workflow, "needs.compact.outputs.publish_marketplace == 'true'", "semantic no-op runs do not replace the client marketplace database");
        Contains(workflow, "security-scan-ledger.json", "timestamp-only scan freshness can advance without replacing the database");

        var validator = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "validate_marketplace_catalog.py"));
        Contains(validator, "catalogSha256", "published database bytes are hash verified");
        Contains(validator, "bundleSha256", "published ZIP bytes are hash verified");
        Contains(validator, "catalogRevision", "published semantic Catalog Revision is verified");
        Contains(validator, "securityRevision", "published semantic Security Revision is verified");
        Contains(validator, "evidenceRevision", "published Evidence Revision is verified without fetching detailed evidence");
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
        Contains(ui, "DrawDiscoverHybridResults", "Discover must keep the enhanced-card and fallback-list hybrid path");
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
        Contains(icons, "PluginImageCacheStore", "artwork must reuse persistent local image bytes between sessions");
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

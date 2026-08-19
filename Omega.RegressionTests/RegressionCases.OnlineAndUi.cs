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
        Contains(workflow, "name: Omega daily catalog snapshot and client database", "catalog builder owns the daily public snapshot boundary");
        Contains(workflow, "cron: \"17 2 * * *\"", "catalog and Definitions publish once per day");
        Contains(workflow, "workflow_dispatch:", "operators can deliberately request an out-of-cycle daily snapshot");
        False(Regex.IsMatch(workflow, @"(?m)^  push:\s*$"), "ordinary source pushes do not create client-visible catalog churn");
        Contains(workflow, "collect_sources.py", "online source discovery step");
        Contains(workflow, "enrich_metadata.py", "manifest normalization step");
        Contains(workflow, "scrape_websites_incremental.py", "incremental website enrichment step");
        Contains(workflow, "build_sqlite_catalog.py", "temporary relational normalization step remains available");
        Contains(workflow, "catalog_json_store.py export", "canonical public catalog is exported as sharded JSON");
        Contains(workflow, "definitions_snapshot.py build", "daily Definitions and OSV inputs are frozen once");
        Contains(workflow, "scan_queue.py build-seed", "daily snapshot includes a deterministic Sigmascope queue seed");
        Contains(workflow, "catalog_state.py assemble", "catalog JSON, Definitions and queue are assembled into one named state");
        Contains(workflow, "catalog_state.py validate", "named canonical state is validated before publication");
        Contains(workflow, "compile_marketplace_snapshot.py", "Omega's client SQLite is compiled from canonical JSON plus validated evidence");
        Contains(workflow, "validate_marketplace_catalog.py --root catalog/client-dist", "exact client database is validated before publication");
        Contains(workflow, "publish_catalog_state.py", "canonical JSON state is published to its dedicated branch");
        Contains(workflow, "--branch catalog-data", "generated catalog state stays off main");
        Contains(workflow, "Publish the once-daily client database", "client publication has one explicit daily boundary");
        Contains(workflow, "gh release upload catalog-latest", "daily compiler publishes the validated small client database");
        Contains(workflow, "database-build.json", "client publication includes auditable build metadata");
        False(workflow.Contains("omega-security-evidence.sqlite.zip", StringComparison.Ordinal), "catalog builder never downloads or publishes the archived giant v1 security evidence bundle");

        var validateIndex = workflow.IndexOf("Validate exact client publication", StringComparison.Ordinal);
        var statePublishIndex = workflow.IndexOf("Publish canonical JSON state atomically", StringComparison.Ordinal);
        var clientPublishIndex = workflow.IndexOf("Publish the once-daily client database", StringComparison.Ordinal);
        True(validateIndex >= 0 && statePublishIndex > validateIndex && clientPublishIndex > statePublishIndex,
            "daily publication validates the exact client DB before advancing canonical state and then the matching client release");

        var builder = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "build_sqlite_catalog.py"));
        Contains(builder, "CREATE TABLE IF NOT EXISTS plugins", "SQLite plugin table");
        Contains(builder, "CREATE TABLE IF NOT EXISTS plugin_variants", "SQLite variant table");
        Contains(builder, "CREATE TABLE IF NOT EXISTS websites", "SQLite website cache table");
        Contains(builder, "CREATE TABLE IF NOT EXISTS presentation", "presentation scoring table");
        Contains(builder, "CREATE TABLE IF NOT EXISTS plugin_search", "normalized search table");
        Contains(builder, "raw_manifest_json", "original source manifest fields remain auditable");
        Contains(builder, "VACUUM", "database is compacted before projection");
        Contains(builder, "omega.catalog.sqlite.v1", "strict normalization SQLite descriptor schema");

        var jsonStore = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "catalog_json_store.py"));
        Contains(jsonStore, "omega.catalog-json.v1", "canonical JSON catalog format has an explicit schema");
        var definitions = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "definitions_snapshot.py"));
        Contains(definitions, "ruleSetRevision", "Definitions distinguish scanner-rule changes from data-only changes");
        Contains(definitions, "queriedPackageVersionPairs", "Definitions freeze the exact OSV query universe");

        var scraper = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "scrape_websites_incremental.py"));
        Contains(scraper, "last_success_utc", "successful website enrichment is reusable");
        Contains(scraper, "max-age-hours", "fresh website data avoids unnecessary re-scraping");
        Contains(scraper, "seed-database", "previous compiled database can supply enrichment cache");
        Contains(scraper, "load_seed_repo_urls", "304 manifests do not freeze stale website rechecks");
    }

    internal static void TestOnlineCatalogFallbackContract()
    {
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CatalogUpdateCoordinator.cs"));
        Contains(coordinator, "TryApplyOnlineCatalogAsync", "online SQLite catalog is checked first");
        Contains(coordinator, "retaining local Definitions", "network failure retains last-known-good SQLite Definitions");
        False(coordinator.Contains("LocalFallback", StringComparison.Ordinal), "public catalog is not rebuilt by crawling repositories in-game");
        False(coordinator.Contains("await catalog.RefreshAsync(configuration.Repositories)", StringComparison.Ordinal), "central failure does not fan out across public sources");
        Contains(coordinator, "!x.IsCurated", "unmanaged Dalamud sources can remain explicit temporary overlays");

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
        True(OnlineCatalogClient.IsValidDefinitionsRevision("defs-v1-0123456789abcdef"), "semantic Definitions Revision format is accepted");
        False(OnlineCatalogClient.IsValidDefinitionsRevision("defs-v1-not-a-hash"), "malformed Definitions Revision is rejected");
        True(OnlineCatalogClient.IsValidSecurityRevision("sec-2.0.0-0123456789abcdef"), "semantic Security Revision format is accepted");
        False(OnlineCatalogClient.IsValidSecurityRevision("sec-2.0.0-short"), "malformed Security Revision is rejected");
        True(OnlineCatalogClient.IsValidEvidenceRevision("ev-v1-0123456789abcdef"), "legacy Evidence Revision format remains accepted");
        True(OnlineCatalogClient.IsValidEvidenceRevision("ev-v2-0123456789abcdef"), "Sigmascope Evidence v2 Revision format is accepted");
        False(OnlineCatalogClient.IsValidEvidenceRevision("ev-v1-short"), "malformed Evidence Revision is rejected");
        False(OnlineCatalogClient.IsValidEvidenceRevision("ev-v3-0123456789abcdef"), "unknown Evidence Revision generation is rejected");

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
        Contains(client, "ProbeAsync", "descriptor-only checks can detect a pending Definitions update without downloading it");
        Contains(client, "OnlineCatalogCheckStatus.UpdateAvailable", "descriptor probe distinguishes pending Definitions from current state");
        Contains(client, "omega.catalog.sqlite.v1", "client accepts only the SQLite catalog descriptor schema");
        False(client.Contains("omega.catalog.v1", StringComparison.Ordinal), "legacy JSON bundle schema removed");
    }

    internal static void TestDefinitionsUpdateUiContract()
    {
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CatalogUpdateCoordinator.cs"));
        Contains(coordinator, "DefinitionsUpdateAvailable", "coordinator exposes a pending Definitions update state");
        Contains(coordinator, "AvailableCatalogSha256", "pending Definitions identity is persisted separately from the applied hash");
        Contains(coordinator, "CheckForUpdatesAsync", "Definitions can be checked without applying them");
        Contains(coordinator, "ApplyDefinitionsUpdateAsync", "pending Definitions can be explicitly applied");
        Contains(coordinator, "onlineClient.ProbeAsync", "normal update checks only fetch the descriptor");

        var temp = Path.Combine(Path.GetTempPath(), "omega-definitions-state-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var store = new OnlineCatalogStateStore(temp);
            store.Save(new OnlineCatalogState
            {
                DescriptorUrl = "https://example.invalid/catalog.json",
                CatalogSha256 = new string('a', 64),
                AvailableCatalogSha256 = new string('b', 64),
                AvailableCatalogRevision = "cat-v1-0123456789abcdef",
                AvailableDefinitionsRevision = "defs-v1-fedcba9876543210",
            });
            var loaded = store.Load();
            Equal(new string('b', 64), loaded.AvailableCatalogSha256, "pending Definitions hash survives restart state round-trip");
            Equal("cat-v1-0123456789abcdef", loaded.AvailableCatalogRevision, "pending Catalog revision survives restart state round-trip");
            Equal("defs-v1-fedcba9876543210", loaded.AvailableDefinitionsRevision, "pending Definitions revision survives restart state round-trip");
        }
        finally
        {
            if (Directory.Exists(temp)) Directory.Delete(temp, true);
        }

        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "definitions-update-row", "Updates page advertises pending Definitions inside the update list");
        Contains(ui, "Update Omega Definitions", "Updates page exposes the explicit Definitions apply action");
        Contains(ui, "##omega-about-version", "version footer is the About entry point");
        Contains(ui, "(versionAvailable - versionButtonSize.X) * 0.5f", "version footer is centered in the application rail");
        Contains(ui, "About Omega", "version footer opens the product-focused About popup");
        Contains(ui, "Every plugin. One orbit.", "About uses the Omega product tagline");
        Contains(ui, "DrawAboutVersionAndDefinitions", "About shows a concise Version row and explanatory Definitions information");
        Contains(ui, "catalog.DefinitionsRevision", "About and Downloads prefer the actual frozen Definitions revision over the catalog revision");
        Contains(ui, "catalog.DatabaseSizeBytes", "About shows the loaded Definitions database size beside its revision");
        Contains(ui, "FormatDefinitionsDatabaseSize", "Definitions database size uses a bounded human-readable formatter");
        Contains(ui, "Check for updates", "Settings starts with an update check action");
        Contains(ui, "View EULA", "Settings labels the agreement simply as EULA");
        False(ui.Contains("View EULA / Risk Disclosure", StringComparison.Ordinal), "Settings does not relabel EULA as a risk disclosure");
        False(ui.Contains("Catalog identity", StringComparison.Ordinal), "catalog identity is removed from Settings");
        False(ui.Contains("[Curated (", StringComparison.Ordinal), "Curated source tab has no decorative brackets");
    }

    internal static void TestLiveCatalogEndpointContract()
    {
        using var endpoint = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "catalog", "catalog-endpoint.json")));
        Equal(1, endpoint.RootElement.GetProperty("schemaVersion").GetInt32(), "live endpoint schema");
        Equal("https://github.com/dalagab/omega/releases/download/catalog-latest/catalog.json",
            endpoint.RootElement.GetProperty("descriptorUrl").GetString(), "live production descriptor URL");

        var builder = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "catalog-builder.yml"));
        Contains(builder, "source_inventory_guard.py", "daily catalog job fail-closes if discovery or normalization silently loses known source URLs");
        Contains(builder, "source-inventory.json", "validated source coverage is published with catalog-data for developer inspection");
        Contains(builder, "compile_marketplace_snapshot.py", "daily catalog job compiles the client database from canonical state");
        Contains(builder, "validate_marketplace_catalog.py --root catalog/client-dist", "daily catalog job validates the exact client database before publication");
        Contains(builder, "Publish the once-daily client database", "client publication belongs to the daily/manual catalog boundary");
        Contains(builder, "gh release upload catalog-latest", "validated daily client database updates the stable runtime endpoint");
        Contains(builder, "omega-marketplace.sqlite.zip", "client release remains the bounded marketplace SQLite transport bundle");

        var workflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "sigmascope.yml"));
        Contains(workflow, "name: Omega Sigmascope continuous worker", "Sigmascope is the independent continuous evidence worker");
        Contains(workflow, "--skip-marketplace", "continuous evidence scanning cannot compile or publish the client DB");
        Contains(workflow, "Publish validated Security Evidence v2 snapshot atomically", "continuous worker can advance validated detailed evidence");
        False(workflow.Contains("gh release upload catalog-latest", StringComparison.Ordinal), "continuous scanner never publishes the client database");
        False(workflow.Contains("omega-marketplace.sqlite.zip", StringComparison.Ordinal), "continuous scanner never transports a client database");
        False(workflow.Contains("omega-security-evidence.sqlite.zip", StringComparison.Ordinal), "live pipeline no longer publishes a giant detailed evidence SQLite bundle");

        var validator = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "validate_marketplace_catalog.py"));
        Contains(validator, "catalogSha256", "published database bytes are hash verified");
        Contains(validator, "bundleSha256", "published ZIP bytes are hash verified");
        Contains(validator, "catalogRevision", "published semantic Catalog Revision is verified");
        Contains(validator, "definitionsRevision", "published frozen Definitions Revision is verified");
        Contains(validator, "securityRevision", "published compiled Security Revision is verified");
        Contains(validator, "evidenceRevision", "published source Evidence Revision is verified without fetching detailed evidence");
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
        Contains(ui, "Multiple authors use AND matching", "multi-author filters use AND matching too");
        Contains(ui, "OmegaWebsiteReadmeExcerpt", "global search includes README enrichment text");
        Contains(ui, "selected-filter-", "selected filters remain visible as removable pills");
        Contains(ui, "Take(needle.Length == 0 ? 120 : 250)", "tag popup draw work is bounded");
        Contains(ui, "catalog.GetTagIndex(currentApi, selectedSource)", "tag index respects repository filtering");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "tagIndexCache", "tag aggregation is cached outside the draw loop");
        Contains(catalog, "MarketplaceTagRules.Build", "production catalog builds the shared tag index helper");

        var project = File.ReadAllText(Path.Combine(Root, "Omega.RegressionTests", "Omega.RegressionTests.csproj"));
        Contains(project, "MarketplaceTagRules.cs", "tag behavior helper is exercised by the build-time regression suite");
    }


    internal static void TestReadmeMarkupRenderingContract()
    {
        var blocks = MarketplaceReadmeMarkup.Parse("# Heading\n<p>Hello <strong>world</strong></p>\n- One\n<blockquote>Quoted</blockquote>\n<pre><code>DoThing();</code></pre><script>evil()</script>");
        True(blocks.Any(x => x.Kind == MarketplaceReadmeBlockKind.Heading && x.Text == "Heading"), "Markdown heading becomes a heading block");
        True(blocks.Any(x => x.Kind == MarketplaceReadmeBlockKind.Bullet && x.Text == "One"), "Markdown list becomes a bullet block");
        True(blocks.Any(x => x.Kind == MarketplaceReadmeBlockKind.Quote && x.Text.Contains("Quoted", StringComparison.Ordinal)), "HTML blockquote becomes a quote block");
        True(blocks.Any(x => x.Kind == MarketplaceReadmeBlockKind.Code && x.Text.Contains("DoThing();", StringComparison.Ordinal)), "HTML pre/code becomes a code block");
        False(blocks.Any(x => x.Text.Contains("evil()", StringComparison.Ordinal)), "script contents are removed rather than rendered");
    }

}

using System.Buffers.Binary;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dalagab.Omega;

var root = args.Length > 0
    ? Path.GetFullPath(args[0])
    : FindRepositoryRoot(AppContext.BaseDirectory);

var tests = new (string Name, Action Body)[]
{
    ("manifest parser accepts community JSON variants", TestManifestParserCommunityTolerance),
    ("manifest parser accepts wrapper objects", TestManifestParserWrappers),
    ("manifest parser rejects unsupported root shapes", TestManifestParserRejectsInvalidShape),
    ("manifest parser skips entries without plugin identity", TestManifestParserSkipsInvalidEntries),
    ("stable API compatibility is preserved", TestStableApiCompatibility),
    ("testing API compatibility is opt-in", TestTestingApiCompatibility),
    ("Omega API range compatibility is preserved", TestOmegaApiRangeCompatibility),
    ("unmaintained threshold is three API levels", TestUnmaintainedThreshold),
    ("repository stale rule hides only fully unmaintained repositories", TestRepositoryStaleRule),
    ("duplicate repository variants remain available", TestDuplicateVariantRetention),
    ("stable API badge aggregates repository variants", TestStableApiVariantAggregation),
    ("official source wins storefront projection", TestOfficialVariantWinsProjection),
    ("highest community version wins without official source", TestHighestCommunityVersionWinsProjection),
    ("hidden variants stay out of the storefront", TestHiddenVariantFiltering),
    ("curated source catalog invariants", TestCuratedSources),
    ("catalog database round-trips repository manifests", TestCatalogDatabaseRoundTrip),
    ("prebuilt catalog bundle imports records and source definitions", TestCatalogBundleImport),
    ("persistent catalog and conditional refresh contract", TestPersistentCatalogContract),
    ("daily update job remains conditional and cache-first", TestDailyUpdateJobContract),
    ("curated all-enabled migration remains one-time", TestCuratedEnableMigration),
    ("version and build stamp stay synchronized", TestVersionAndBuildStampSynchronization),
    ("pre-login manifest requirements stay enabled", TestPreLoginManifest),
    ("title icon remains 64x64 PNG", TestTitleIcon),
    ("API-15 native menu hook typing stays explicit", TestSystemMenuHookTyping),
    ("startup network access remains user-triggered", TestManualReloadContract),
    ("storefront regression guards stay intact", TestStorefrontContract),
    ("spotlight and repository filtering remain visible", TestSpotlightAndRepositoryFilter),
    ("source manager remains a checkbox table with stale status", TestSourceTableContract),
    ("GitHub catalog builder remains reproducible and hash-gated", TestCatalogBuilderContract),
    ("online catalog hash path and local repository fallback remain available", TestOnlineCatalogFallbackContract),
    ("online catalog descriptor helpers remain strict", TestOnlineCatalogDescriptorHelpers),
    ("regression runner remains wired into Omega.sln", TestRegressionBuildWiring),
};

var failures = new List<string>();
Console.WriteLine($"Omega regression suite: {tests.Length} tests");
Console.WriteLine($"Repository root: {root}");

foreach (var (name, body) in tests)
{
    try
    {
        body();
        Console.WriteLine($"PASS  {name}");
    }
    catch (Exception ex)
    {
        failures.Add($"{name}: {ex.Message}");
        Console.Error.WriteLine($"FAIL  {name}: {ex.Message}");
    }
}

if (failures.Count == 0)
{
    Console.WriteLine($"Omega regression suite passed: {tests.Length}/{tests.Length}");
    return 0;
}

Console.Error.WriteLine($"Omega regression suite FAILED: {failures.Count}/{tests.Length}");
foreach (var failure in failures)
    Console.Error.WriteLine($" - {failure}");
return 1;

void TestManifestParserCommunityTolerance()
{
    const string json = """
    [
      // community feeds commonly contain comments/trailing commas
      {
        "Author": "Tester",
        "Name": "Test Plugin",
        "InternalName": "TestPlugin",
        "AssemblyVersion": "1.2.3.4",
        "DalamudApiLevel": "15",
        "IsHide": "False",
        "LastUpdated": "123456789",
        "CategoryTags": ["Utility"],
        "DownloadLinkInstall": "https://example.invalid/test.zip",
      },
    ]
    """;

    var parsed = RepositoryManifestParser.Parse(json, Source("Community"));
    Equal(1, parsed.Count, "entry count");
    var plugin = parsed[0];
    Equal("Test Plugin", plugin.Name, "name");
    Equal(15, plugin.DalamudApiLevel, "string API level");
    Equal(123456789L, plugin.LastUpdate, "LastUpdated alias");
    False(plugin.IsHide, "string boolean");
    True(plugin.EffectiveCategories.Contains("Utility"), "category parsing");
}

void TestManifestParserWrappers()
{
    const string pluginsWrapper = """{"plugins":[{"Name":"One","InternalName":"One"}]}""";
    const string masterWrapper = """{"PluginMaster":[{"Name":"Two","InternalName":"Two"}]}""";
    Equal(1, RepositoryManifestParser.Parse(pluginsWrapper, Source("A")).Count, "plugins wrapper");
    Equal(1, RepositoryManifestParser.Parse(masterWrapper, Source("B")).Count, "pluginmaster wrapper");
}

void TestManifestParserRejectsInvalidShape()
{
    Throws<InvalidDataException>(
        () => RepositoryManifestParser.Parse("{\"Name\":\"not a repository\"}", Source("Invalid")),
        "single object must not become an install repository");
}

void TestManifestParserSkipsInvalidEntries()
{
    const string json = """
    [
      {"Name":"Missing internal name"},
      {"InternalName":"MissingName"},
      {"Name":"Valid","InternalName":"Valid"}
    ]
    """;
    var parsed = RepositoryManifestParser.Parse(json, Source("Validation"));
    Equal(1, parsed.Count, "only complete identities survive");
    Equal("Valid", parsed[0].InternalName, "valid identity");
}

void TestStableApiCompatibility()
{
    var plugin = Plugin("Stable", "1.0.0.0", 15, install: "https://example.invalid/stable.zip");
    True(plugin.SupportsApiLevel(15, false), "API 15 stable should be supported");
    Equal(15, plugin.DisplayApiLevel(15, false), "display current supported API");
    False(plugin.SupportsApiLevel(16, false), "future API should not be inferred compatible");
}

void TestTestingApiCompatibility()
{
    var plugin = new MarketplacePlugin
    {
        Name = "Testing",
        InternalName = "Testing",
        AssemblyVersionText = "1.0.0.0",
        DalamudApiLevel = 14,
        DownloadLinkInstall = "https://example.invalid/stable.zip",
        TestingAssemblyVersionText = "2.0.0.0",
        TestingDalamudApiLevel = 15,
        DownloadLinkTesting = "https://example.invalid/testing.zip",
    };

    False(plugin.SupportsApiLevel(15, false), "testing build must remain opt-in");
    True(plugin.SupportsApiLevel(15, true), "testing build should satisfy API when enabled");
    True(plugin.HasCurrentApiBuild(15, true, out var testing) && testing, "testing selection flag");
}

void TestOmegaApiRangeCompatibility()
{
    var plugin = new MarketplacePlugin
    {
        Name = "Range",
        InternalName = "Range",
        DalamudApiLevel = 13,
        OmegaMinimumApiLevel = 14,
        OmegaMaximumApiLevel = 16,
    };
    True(plugin.SupportsApiLevel(15, false), "declared Omega range");
    False(plugin.SupportsApiLevel(17, false), "outside declared Omega range");
}

void TestUnmaintainedThreshold()
{
    False(Plugin("Api14", "1.0.0.0", 14).IsUnmaintained(15), "one API behind is only outdated");
    False(Plugin("Api13", "1.0.0.0", 13).IsUnmaintained(15), "two APIs behind is only outdated");
    True(Plugin("Api12", "1.0.0.0", 12).IsUnmaintained(15), "three APIs behind is unmaintained");
    False(Plugin("Unknown", "1.0.0.0", 0).IsUnmaintained(15), "unknown API is not mislabeled unmaintained");
}

void TestRepositoryStaleRule()
{
    var stale = new[]
    {
        Plugin("OldA", "1.0.0.0", 12, sourceName: "Old Repo"),
        Plugin("OldB", "1.0.0.0", 11, sourceName: "Old Repo"),
    };
    True(RepositoryHealthRules.IsStale(stale, 15), "all plugins three or more APIs behind");

    var mixed = stale.Concat(new[] { Plugin("Recent", "1.0.0.0", 14, sourceName: "Old Repo") });
    False(RepositoryHealthRules.IsStale(mixed, 15), "one recent plugin keeps repository active");

    var unknown = new[] { Plugin("Unknown", "1.0.0.0", 0, sourceName: "Unknown Repo") };
    False(RepositoryHealthRules.IsStale(unknown, 15), "unknown API never marks a repository stale");
}

void TestDuplicateVariantRetention()
{
    var projection = MarketplaceCatalogRules.Project(new[]
    {
        Plugin("Same", "1.0.0.0", 15, sourceName: "Repo A"),
        Plugin("Same", "2.0.0.0", 15, sourceName: "Repo B"),
    });

    Equal(1, projection.Plugins.Count, "one storefront presentation entry");
    Equal(2, projection.Variants.Count, "all repository variants retained");
    Equal(2, MarketplaceCatalogRules.GetVariants(projection.Variants, "Same").Count, "source chooser sees both variants");
}

void TestStableApiVariantAggregation()
{
    var variants = new[]
    {
        Plugin("Same", "9.0.0.0", 0, sourceName: "Presentation Repo"),
        Plugin("Same", "1.0.0.0", 15, sourceName: "Stable API Repo"),
        Plugin("Same", "2.0.0.0", 14, sourceName: "Older Repo"),
        Plugin("Same", "3.0.0.0", 16, sourceName: "Future Repo"),
    };

    var projection = MarketplaceCatalogRules.Project(variants);
    Equal("Presentation Repo", projection.Plugins[0].SourceName, "presentation may come from variant without API metadata");
    Equal(16, MarketplaceCatalogRules.GetStableApiLevel(projection.Variants, "Same"), "highest stable API remains discoverable");
    Equal(15, MarketplaceCatalogRules.GetStableApiLevel(projection.Variants, "Same", 15), "current supported stable API is preferred for the badge");
}

void TestOfficialVariantWinsProjection()
{
    var official = Plugin("Same", "1.0.0.0", 15, sourceName: "Dalamud official", official: true);
    var newerCommunity = Plugin("Same", "99.0.0.0", 15, sourceName: "Community");
    var projection = MarketplaceCatalogRules.Project(new[] { newerCommunity, official });
    Equal("Dalamud official", projection.Plugins[0].SourceName, "official source precedence");
}

void TestHighestCommunityVersionWinsProjection()
{
    var projection = MarketplaceCatalogRules.Project(new[]
    {
        Plugin("Same", "1.0.0.0", 15, sourceName: "Repo A"),
        Plugin("Same", "3.0.0.0", 15, sourceName: "Repo B"),
        Plugin("Same", "2.0.0.0", 15, sourceName: "Repo C"),
    });
    Equal("Repo B", projection.Plugins[0].SourceName, "highest stable community version");
}

void TestHiddenVariantFiltering()
{
    var hidden = new MarketplacePlugin
    {
        Name = "Hidden",
        InternalName = "Hidden",
        IsHide = true,
        SourceName = "Hidden Repo",
    };
    var visible = Plugin("Visible", "1.0.0.0", 15, sourceName: "Visible Repo");
    var projection = MarketplaceCatalogRules.Project(new[] { hidden, visible });
    Equal(1, projection.Plugins.Count, "hidden storefront entry removed");
    Equal(1, projection.Variants.Count, "hidden source variant removed");
    Equal("Visible", projection.Plugins[0].InternalName, "visible plugin remains");
}

void TestCuratedSources()
{
    var path = Path.Combine(root, "sources", "curated-sources.json");
    using var doc = JsonDocument.Parse(File.ReadAllText(path));
    var entries = doc.RootElement.EnumerateArray().ToArray();
    True(entries.Length >= 136, "reviewed curated + discovered source floor");

    var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var officialCount = 0;
    var enabledCount = 0;
    foreach (var entry in entries)
    {
        var id = RequiredString(entry, "id");
        var url = RequiredString(entry, "url");
        True(ids.Add(id), $"duplicate curated id: {id}");
        True(urls.Add(url.TrimEnd('/')), $"duplicate curated URL: {url}");
        True(Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps, $"HTTPS source required: {id}");
        False(url.Contains("github.com/", StringComparison.OrdinalIgnoreCase) && url.Contains("/blob/", StringComparison.OrdinalIgnoreCase), $"GitHub blob URL must be normalized: {id}");
        if (entry.TryGetProperty("isOfficial", out var official) && official.ValueKind == JsonValueKind.True)
            officialCount++;
        if (entry.TryGetProperty("enabledByDefault", out var enabled) && enabled.ValueKind == JsonValueKind.True)
            enabledCount++;
    }

    Equal(1, officialCount, "exactly one official source");
    Equal(entries.Length, enabledCount, "all curated sources default enabled");

    foreach (var requiredId in new[]
    {
        "dalamud-official", "unknownx7", "nightmarexiv", "combat-reborn", "sea-of-stars",
        "eisenhuth-trustworthy", "sphene-dev", "ktisis-direct", "lmeter-direct",
        "karlin-main", "autovisor-direct", "ookura-risona",
        "williamw1979-ffxiv", "movemexiv", "automarket-pro", "aethergel-plugins",
        "lightless-sync", "playersync", "xivsync", "aetherlove-aetheros",
    })
        True(ids.Contains(requiredId), $"required curated source missing: {requiredId}");

    var defaults = entries.ToDictionary(
        entry => RequiredString(entry, "id"),
        entry => entry.TryGetProperty("enabledByDefault", out var enabled) && enabled.ValueKind == JsonValueKind.True,
        StringComparer.OrdinalIgnoreCase);
    foreach (var pair in defaults)
        True(pair.Value, $"curated source should default enabled: {pair.Key}");

    var discoveredCount = entries.Count(entry =>
        entry.TryGetProperty("description", out var description) &&
        description.GetString()?.Contains("user-provided Dalamud source batches", StringComparison.OrdinalIgnoreCase) == true);
    True(discoveredCount >= 90, "uploaded source batches should contribute reviewed repository-index candidates");
}

void TestCatalogDatabaseRoundTrip()
{
    var temp = Path.Combine(Path.GetTempPath(), "omega-regression-" + Guid.NewGuid().ToString("N"));
    try
    {
        var database = new CatalogDatabase(temp);
        const string url = "https://example.invalid/repository.json";
        const string manifest = "[{\"Name\":\"Cached\",\"InternalName\":\"Cached\"}]";
        var stored = database.Store(url, manifest, "\"etag-1\"", "Wed, 13 Aug 2026 10:00:00 GMT", DateTimeOffset.UtcNow);
        True(stored.ContentSha256.Length == 64, "content hash stored");

        var loaded = database.TryRead(url);
        True(loaded is not null, "database record readable");
        Equal(manifest, loaded!.ManifestJson, "manifest round-trip");
        Equal("\"etag-1\"", loaded.ETag, "etag round-trip");

        var later = DateTimeOffset.UtcNow.AddMinutes(1);
        database.MarkChecked(loaded, "\"etag-2\"", null, later);
        var checkedRecord = database.TryRead(url);
        Equal("\"etag-2\"", checkedRecord!.ETag, "etag update");
        Equal(later, checkedRecord.CheckedAtUtc, "checked timestamp update");
    }
    finally
    {
        if (Directory.Exists(temp))
            Directory.Delete(temp, true);
    }
}

void TestCatalogBundleImport()
{
    var temp = Path.Combine(Path.GetTempPath(), "omega-bundle-regression-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(temp);
    try
    {
        var database = new CatalogDatabase(Path.Combine(temp, "db"));
        const string url = "https://example.invalid/prebuilt.json";
        const string manifest = "[{\"Name\":\"Prebuilt\",\"InternalName\":\"Prebuilt\",\"DalamudApiLevel\":15}]";
        var checkedAt = DateTimeOffset.UtcNow.AddMinutes(-5);
        var record = new CatalogDatabaseRecord
        {
            SchemaVersion = 1,
            Url = url,
            ContentSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(manifest))).ToLowerInvariant(),
            FetchedAtUtc = checkedAt,
            CheckedAtUtc = checkedAt,
            ManifestJson = manifest,
        };

        var zipPath = Path.Combine(temp, "omega-catalog-db.zip");
        using (var archive = System.IO.Compression.ZipFile.Open(zipPath, System.IO.Compression.ZipArchiveMode.Create))
        {
            var recordEntry = archive.CreateEntry("catalog-db/test.json");
            using (var writer = new StreamWriter(recordEntry.Open()))
                writer.Write(JsonSerializer.Serialize(record));

            var sourcesEntry = archive.CreateEntry("sources.json");
            using (var writer = new StreamWriter(sourcesEntry.Open()))
            {
                writer.Write("[{\"id\":\"prebuilt\",\"name\":\"Prebuilt source\",\"url\":\"https://example.invalid/prebuilt.json\",\"enabledByDefault\":true}]");
            }
        }

        var imported = CatalogBundleImporter.Import(zipPath, database);
        Equal(1, imported.ImportedRecords, "bundle record import count");
        Equal(1, imported.SourceDefinitions.Count, "bundle source definition count");
        Equal("prebuilt", imported.SourceDefinitions[0].Id, "bundle source id");
        True(database.TryRead(url) is not null, "bundle record becomes readable");

        // Reimporting the same timestamp must not overwrite equally-new local state.
        var second = CatalogBundleImporter.Import(zipPath, database);
        Equal(0, second.ImportedRecords, "equal/older bundle does not overwrite local record");
    }
    finally
    {
        if (Directory.Exists(temp))
            Directory.Delete(temp, true);
    }
}

void TestPersistentCatalogContract()
{
    var plugin = File.ReadAllText(Path.Combine(root, "Omega", "Plugin.cs"));
    Contains(plugin, "catalog-db", "persistent catalog directory");
    Contains(plugin, "catalog.LoadCached", "startup database load");
    Contains(plugin, "omega-catalog-db.zip", "optional prebuilt catalog bundle");
    Contains(plugin, "catalog.ImportBundle", "prebuilt catalog is imported locally before projection");
    False(plugin.Contains("catalog.RefreshAsync(Configuration.Repositories)", StringComparison.Ordinal), "startup must not contact repositories");

    var client = File.ReadAllText(Path.Combine(root, "Omega", "Services", "RepositoryClient.cs"));
    Contains(client, "IfNoneMatch", "ETag conditional request");
    Contains(client, "IfModifiedSince", "Last-Modified conditional request");
    Contains(client, "HttpStatusCode.NotModified", "304 support");
    Contains(client, "ResponseHeadersRead", "do not eagerly buffer unchanged responses");
    Contains(client, "MaxResponseBytes", "bounded repository response");

    var catalog = File.ReadAllText(Path.Combine(root, "Omega", "Services", "MarketplaceCatalogService.cs"));
    Contains(catalog, "RefreshPluginSourcesAsync", "per-plugin source freshness check");
    Contains(catalog, "RebuildFromDatabase", "local database projection");

    var ui = File.ReadAllText(Path.Combine(root, "Omega", "UI", "MarketplaceWindow.cs"));
    Contains(ui, "updates.RefreshPluginSourcesAsync", "opening plugin details goes through the online/fallback policy");
    Contains(ui, "published catalog database", "preferred central database is explained to the user");
    Contains(ui, "local database", "local fallback database is explained to the user");
    Contains(ui, "Reload Sources", "explicit catalog check remains available");
}

void TestDailyUpdateJobContract()
{
    var service = File.ReadAllText(Path.Combine(root, "Omega", "Services", "DailyCatalogUpdateService.cs"));
    Contains(service, "TimeSpan.FromDays(1)", "daily cadence");
    Contains(service, "updates.RefreshAsync", "daily job uses the preferred central hash path with local fallback");
    Contains(service, "LastDailyUpdateCheckUtc", "daily completion is persisted");

    var plugin = File.ReadAllText(Path.Combine(root, "Omega", "Plugin.cs"));
    Contains(plugin, "catalog.LoadCached", "startup loads the local catalog once");
    Contains(plugin, "DailyCatalogUpdateService", "daily job is wired into plugin lifetime");
    Contains(plugin, "dailyCatalogUpdate.TriggerIfDue", "opening Omega can trigger an overdue daily check");
}

void TestCuratedEnableMigration()
{
    var configuration = File.ReadAllText(Path.Combine(root, "Omega", "Configuration.cs"));
    Contains(configuration, "Version { get; set; } = 7", "configuration schema 7");

    var curated = File.ReadAllText(Path.Combine(root, "Omega", "Services", "CuratedSourceCatalog.cs"));
    Contains(curated, "enableAllCuratedMigration", "one-time all-enabled migration");
    Contains(curated, "configuration.Version < 5", "all-enabled migration gate");
    Contains(curated, "configuration.Version < 7", "schema upgrade gate");
    Contains(curated, "source.Enabled = true", "migration enables existing curated sources");
}

void TestVersionAndBuildStampSynchronization()
{
    var zr = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "omega.zr"))).RootElement;
    var zrVersion = RequiredString(zr, "version");
    var zrStamp = RequiredString(zr, "expected_build_stamp");

    var project = XDocument.Load(Path.Combine(root, "Omega", "DalagabOmega.csproj"));
    var projectVersion = project.Descendants("Version").Single().Value.Trim();
    Equal(zrVersion, projectVersion, "omega.zr vs csproj version");

    var buildStampFile = File.ReadAllText(Path.Combine(root, "BUILD_STAMP.txt")).Trim();
    Equal(zrStamp, buildStampFile, "omega.zr vs BUILD_STAMP.txt");

    var buildInfo = File.ReadAllText(Path.Combine(root, "Omega", "BuildInfo.cs"));
    Equal(zrVersion, Capture(buildInfo, "Version\\s*=\\s*\"([^\"]+)\""), "BuildInfo version");
    Equal(zrStamp, Capture(buildInfo, "BuildStamp\\s*=\\s*\"([^\"]+)\""), "BuildInfo stamp");
}

void TestPreLoginManifest()
{
    using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "Omega", "DalagabOmega.json")));
    var manifest = doc.RootElement;
    Equal("Omega", RequiredString(manifest, "Name"), "manifest product name");
    Equal("Dalagab Group", RequiredString(manifest, "Author"), "manifest author");
    Equal(2, manifest.GetProperty("LoadRequiredState").GetInt32(), "pre-login load state");

    var pluginSource = File.ReadAllText(Path.Combine(root, "Omega", "Plugin.cs"));
    Contains(pluginSource, "ITitleScreenMenu", "title-screen service");
    Contains(pluginSource, "AddEntry(1000, \"Omega\"", "title-screen Omega entry");
}

void TestTitleIcon()
{
    var path = Path.Combine(root, "images", "title-icon.png");
    var bytes = File.ReadAllBytes(path);
    True(bytes.Length >= 24, "PNG header length");
    var signature = new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 };
    True(bytes.AsSpan(0, 8).SequenceEqual(signature), "PNG signature");
    var width = BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(16, 4));
    var height = BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(20, 4));
    Equal(64, width, "title icon width");
    Equal(64, height, "title icon height");
}

void TestSystemMenuHookTyping()
{
    var source = File.ReadAllText(Path.Combine(root, "Omega", "Services", "DalamudSystemMenuBridge.cs"));
    Contains(source, "HookFromAddress<AgentHUD.Delegates.OpenSystemMenu>", "OpenSystemMenu explicit delegate");
    Contains(source, "HookFromAddress<UIModule.Delegates.ExecuteMainCommand>", "ExecuteMainCommand explicit delegate");
}

void TestManualReloadContract()
{
    var plugin = File.ReadAllText(Path.Combine(root, "Omega", "Plugin.cs"));
    Contains(plugin, "catalog.LoadCached(Configuration.Repositories)", "startup projects the existing local database first");
    Contains(plugin, "catalogUpdates.SeedIfEmpty()", "only an empty catalog triggers asynchronous preferred/fallback seeding");
    False(plugin.Contains("catalog.RefreshAsync", StringComparison.Ordinal), "plugin constructor must not directly fan out across repositories");

    var ui = File.ReadAllText(Path.Combine(root, "Omega", "UI", "MarketplaceWindow.cs"));
    Contains(ui, "Reload Sources", "explicit catalog update control");
    Contains(ui, "updates.RefreshAsync()", "manual reload uses the preferred-online/fallback coordinator");
    Contains(ui, "catalog.LoadCached", "source configuration applies locally without network");

    var catalog = File.ReadAllText(Path.Combine(root, "Omega", "Services", "MarketplaceCatalogService.cs"));
    Contains(catalog, "Deliberately sequential", "fallback repository checks remain sequential");
}

void TestStorefrontContract()
{
    var ui = File.ReadAllText(Path.Combine(root, "Omega", "UI", "MarketplaceWindow.cs"));
    Contains(ui, "DrawApiBadge", "API artwork badge");
    Contains(ui, "DrawArtworkOverlayActions", "Info/install actions stay over artwork");
    Contains(ui, "Selected", "selected plugin is visibly marked in the shelf");
    Contains(ui, "Unmaintained", "unmaintained badge is visible");
    Contains(ui, "omega-author-filter", "author filter is directly available on storefront");
    Contains(ui, "selectedVariantSource", "duplicate source selection");
    Contains(ui, "fallbackIconPath", "company fallback artwork path");
    True(File.Exists(Path.Combine(root, "images", "company-fallback.png")), "company fallback artwork file");
    Contains(ui, "ImGui.IsRectVisible", "lazy visible icon loading");
    False(ui.Contains("storefrontPage", StringComparison.Ordinal), "pagination must not return");
    False(ui.Contains("rowsPerPage", StringComparison.Ordinal), "fixed-page rows must not return");
    False(ui.Contains("ImGui.BeginTable(\"market\"", StringComparison.Ordinal), "legacy giant marketplace table must not return");
}

void TestSpotlightAndRepositoryFilter()
{
    var ui = File.ReadAllText(Path.Combine(root, "Omega", "UI", "MarketplaceWindow.cs"));
    Contains(ui, "MarketplaceView.Spotlight", "Spotlight is a dedicated marketplace page");
    Contains(ui, "★  Spotlight", "Spotlight has its own sidebar icon");
    Contains(ui, "DrawSpotlightPage", "Spotlight has a dedicated renderer");
    Contains(ui, "HonseFarm.Client", "Honse promotion remains configured");
    Contains(ui, "AetherLovePlugin", "AetherLove/AetherOS promotion remains configured");
    Contains(ui, "InventoryTools", "Allagan Tools promotion remains configured");
    Contains(ui, "GatherBuddyReborn", "GatherBuddy promotion remains configured");
    Contains(ui, "ChatTwo", "Chat 2 promotion remains configured");
    False(ui.Contains("promoted.Add(fallback)", StringComparison.Ordinal), "Spotlight must not substitute unrelated plugins when a fixed promotion is missing");
    Contains(ui, "Take(5)", "Spotlight is capped at exactly five highlighted plugins");
    False(ui.Contains("DrawSpotlight(mainProjection.Plugins", StringComparison.Ordinal), "Discover must not contain the old inline Spotlight area");
    Contains(ui, "omega-repository-filter", "repository filter remains directly available");
    Contains(ui, "activeView == MarketplaceView.Spotlight ? \"All sources\" : selectedSource", "repository filter remains source-aware outside Spotlight");
    Contains(ui, "catalog.GetStableApiLevel(plugin.InternalName, currentApi)", "tile API badge resolves stable API across repository variants and prefers current support");

    var catalog = File.ReadAllText(Path.Combine(root, "Omega", "Services", "MarketplaceCatalogService.cs"));
    Contains(catalog, "GetMainProjection", "stale-aware marketplace projection");
    Contains(catalog, "GetStableApiLevel", "catalog exposes aggregate stable API metadata");
    Contains(catalog, "RepositoryHealthRules.BuildStatuses", "repository health is applied before main projection");
}

void TestSourceTableContract()
{
    var ui = File.ReadAllText(Path.Combine(root, "Omega", "UI", "MarketplaceWindow.cs"));
    Contains(ui, "omega-source-table", "source manager table");
    Contains(ui, "source-enabled-", "repository enable checkbox");
    Contains(ui, "\"Stale\"", "stale repository status");
    Contains(ui, "catalog.LoadCached(configuration.Repositories)", "deselecting a repository immediately rebuilds local catalog");
    Contains(ui, "ImGui.BeginTable(\"omega-source-table\", 5, ImGuiTableFlags.None, new Vector2(860f, 360f), 0f)", "API-15 BeginTable overload must include the flags argument before outer size");
    False(ui.Contains("selectedSourceIndex", StringComparison.Ordinal), "removed selection-list index state must not return after source table migration");

    var health = File.ReadAllText(Path.Combine(root, "Omega", "Services", "RepositoryHealthRules.cs"));
    Contains(health, "entries.All", "stale requires every cached plugin to be unmaintained");
    Contains(health, "IsUnmaintained(currentApi)", "repository stale threshold reuses plugin rule");
}

void TestCatalogBuilderContract()
{
    var workflowPath = Path.Combine(root, ".github", "workflows", "catalog-builder.yml");
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

    var builder = File.ReadAllText(Path.Combine(root, "tools", "catalog", "build_catalog.py"));
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

    var pipelineTests = File.ReadAllText(Path.Combine(root, "tools", "catalog", "test_catalog_pipeline.py"));
    Contains(pipelineTests, "known-bad-git-blob", "pipeline self-test covers pre-download bad-blob skip");
    Contains(pipelineTests, "new-bad-hash", "pipeline self-test covers deterministic bad-content classification");
    Contains(pipelineTests, "seed bundle round-trip", "pipeline self-test covers previous-database reuse");

    using var knownBad = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "catalog", "known-bad-hashes.json")));
    Equal(1, knownBad.RootElement.GetProperty("schemaVersion").GetInt32(), "known-bad schema");

    using var candidates = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "catalog", "candidates.json")));
    True(candidates.RootElement.GetProperty("count").GetInt32() >= 470, "uploaded discovery batches seed the candidate queue");

    foreach (var file in new[] { "dalamud_batch1.json", "dalamud_batch2.json", "dalamud_batch3.json" })
        True(File.Exists(Path.Combine(root, "sources", "discovery", file)), $"discovery seed retained: {file}");
}

void TestOnlineCatalogFallbackContract()
{
    var coordinator = File.ReadAllText(Path.Combine(root, "Omega", "Services", "CatalogUpdateCoordinator.cs"));
    Contains(coordinator, "TryApplyOnlineCatalogAsync", "online catalog is attempted first");
    Contains(coordinator, "await catalog.RefreshAsync(configuration.Repositories)", "complete local source list is the fallback");
    Contains(coordinator, "userRepositories.Length == 0", "successful central DB avoids curated repository fan-out when no user repositories exist");
    Contains(coordinator, "!x.IsCurated", "only user-added repositories are layered over a valid central catalog");
    Contains(coordinator, "stateStore.ClearAppliedCatalog", "fallback invalidates the central-hash shortcut after local records mutate");
    Contains(coordinator, "SeedIfEmpty", "fresh install can acquire a catalog without blocking plugin construction");

    var database = File.ReadAllText(Path.Combine(root, "Omega", "Services", "CatalogDatabase.cs"));
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

void TestOnlineCatalogDescriptorHelpers()
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

    var endpoint = File.ReadAllText(Path.Combine(root, "catalog", "catalog-endpoint.json"));
    Contains(endpoint, "descriptorUrl", "source package carries endpoint configuration seeded by GitHub Actions");
    var project = File.ReadAllText(Path.Combine(root, "Omega", "DalagabOmega.csproj"));
    Contains(project, "catalog-endpoint.json", "catalog endpoint is packaged with Omega");
}

void TestRegressionBuildWiring()
{
    var solution = File.ReadAllText(Path.Combine(root, "Omega.sln"));
    Contains(solution, "Omega.RegressionTests", "regression project in solution");

    var project = File.ReadAllText(Path.Combine(root, "Omega.RegressionTests", "Omega.RegressionTests.csproj"));
    Contains(project, "RunOmegaRegressionTests", "after-build regression target");
    Contains(project, "AfterTargets=\"Build\"", "regression target runs after build");
    Contains(project, "ReferenceOutputAssembly=\"false\"", "build ordering without loading Dalamud runtime");
}

RepositorySource Source(string name) => new()
{
    Name = name,
    Url = $"https://example.invalid/{Uri.EscapeDataString(name)}.json",
};

MarketplacePlugin Plugin(
    string internalName,
    string version,
    int api,
    string install = "https://example.invalid/plugin.zip",
    string sourceName = "Community",
    bool official = false)
    => new()
    {
        Name = internalName,
        InternalName = internalName,
        AssemblyVersionText = version,
        DalamudApiLevel = api,
        DownloadLinkInstall = install,
        SourceName = sourceName,
        SourceUrl = $"https://example.invalid/{Uri.EscapeDataString(sourceName)}.json",
        SourceIsOfficial = official,
    };

static string FindRepositoryRoot(string start)
{
    var current = new DirectoryInfo(start);
    while (current is not null)
    {
        if (File.Exists(Path.Combine(current.FullName, "omega.zr")))
            return current.FullName;
        current = current.Parent;
    }

    throw new DirectoryNotFoundException("Could not locate Omega repository root.");
}

static string RequiredString(JsonElement element, string name)
{
    if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
        throw new InvalidDataException($"Missing string property '{name}'.");
    return value.GetString() ?? string.Empty;
}

static string Capture(string input, string pattern)
{
    var match = Regex.Match(input, pattern);
    if (!match.Success)
        throw new InvalidDataException($"Pattern not found: {pattern}");
    return match.Groups[1].Value;
}

static void Contains(string input, string expected, string message)
{
    if (!input.Contains(expected, StringComparison.Ordinal))
        throw new InvalidOperationException($"{message}: missing '{expected}'");
}

static void True(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}

static void False(bool condition, string message) => True(!condition, message);

static void Equal<T>(T expected, T actual, string message)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new InvalidOperationException($"{message}: expected '{expected}', got '{actual}'");
}

static void Throws<TException>(Action action, string message) where TException : Exception
{
    try
    {
        action();
    }
    catch (TException)
    {
        return;
    }

    throw new InvalidOperationException(message);
}

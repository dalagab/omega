using System.Buffers.Binary;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dalagab.Omega;

namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestCatalogDatabaseRoundTrip()
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

    internal static void TestCatalogBundleImport()
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

    internal static void TestPersistentCatalogContract()
    {
        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(plugin, "catalog-db", "persistent catalog directory");
        Contains(plugin, "catalog.LoadCached", "startup database load");
        Contains(plugin, "omega-catalog-db.zip", "optional prebuilt catalog bundle");
        Contains(plugin, "catalog.ImportBundle", "prebuilt catalog is imported locally before projection");
        False(plugin.Contains("catalog.RefreshAsync(Configuration.Repositories)", StringComparison.Ordinal), "startup must not contact repositories");

        var client = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "RepositoryClient.cs"));
        Contains(client, "IfNoneMatch", "ETag conditional request");
        Contains(client, "IfModifiedSince", "Last-Modified conditional request");
        Contains(client, "HttpStatusCode.NotModified", "304 support");
        Contains(client, "ResponseHeadersRead", "do not eagerly buffer unchanged responses");
        Contains(client, "MaxResponseBytes", "bounded repository response");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "RefreshPluginSourcesAsync", "per-plugin source freshness check");
        Contains(catalog, "RebuildFromDatabase", "local database projection");

        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "updates.RefreshPluginSourcesAsync", "opening plugin details goes through the online/fallback policy");
        Contains(ui, "published catalog database", "preferred central database is explained to the user");
        Contains(ui, "local database", "local fallback database is explained to the user");
        Contains(ui, "Refresh catalog sources", "explicit catalog check remains available inside Settings");
    }

    internal static void TestDailyUpdateJobContract()
    {
        var service = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DailyCatalogUpdateService.cs"));
        Contains(service, "TimeSpan.FromDays(1)", "daily cadence");
        Contains(service, "updates.RefreshAsync", "daily job uses the preferred central hash path with local fallback");
        Contains(service, "LastDailyUpdateCheckUtc", "daily completion is persisted");

        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(plugin, "catalog.LoadCached", "startup loads the local catalog once");
        Contains(plugin, "DailyCatalogUpdateService", "daily job is wired into plugin lifetime");
        Contains(plugin, "dailyCatalogUpdate.TriggerIfDue", "opening Omega can trigger an overdue daily check");
    }

    internal static void TestCuratedEnableMigration()
    {
        var configuration = File.ReadAllText(Path.Combine(Root, "Omega", "Configuration.cs"));
        Contains(configuration, "Version { get; set; } = 7", "configuration schema 7");

        var curated = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CuratedSourceCatalog.cs"));
        Contains(curated, "enableAllCuratedMigration", "one-time all-enabled migration");
        Contains(curated, "configuration.Version < 5", "all-enabled migration gate");
        Contains(curated, "configuration.Version < 7", "schema upgrade gate");
        Contains(curated, "source.Enabled = true", "migration enables existing curated sources");
    }

    internal static void TestVersionMetadataSynchronization()
    {
        var project = XDocument.Load(Path.Combine(Root, "Omega", "DalagabOmega.csproj"));
        var projectVersion = project.Descendants("Version").Single().Value.Trim();

        var buildInfo = File.ReadAllText(Path.Combine(Root, "Omega", "BuildInfo.cs"));
        Equal(projectVersion, Capture(buildInfo, "Version\\s*=\\s*\"([^\"]+)\""), "BuildInfo version");
        True(!string.IsNullOrWhiteSpace(Capture(buildInfo, "BuildStamp\\s*=\\s*\"([^\"]+)\"")), "BuildInfo stamp remains populated for diagnostics");

        using var repository = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "repository", "pluginmaster.json")));
        var omega = repository.RootElement.EnumerateArray().Single();
        Equal(projectVersion, RequiredString(omega, "AssemblyVersion"), "public repository manifest version");
    }

    internal static void TestPreLoginManifest()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "Omega", "DalagabOmega.json")));
        var manifest = doc.RootElement;
        Equal("Omega", RequiredString(manifest, "Name"), "manifest product name");
        Equal("Dalagab Group", RequiredString(manifest, "Author"), "manifest author");
        Equal(2, manifest.GetProperty("LoadRequiredState").GetInt32(), "pre-login load state");

        var pluginSource = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(pluginSource, "ITitleScreenMenu", "title-screen service");
        Contains(pluginSource, "AddEntry(1000, \"Omega\"", "title-screen Omega entry");
    }

    internal static void TestTitleIcon()
    {
        var path = Path.Combine(Root, "images", "title-icon.png");
        var bytes = File.ReadAllBytes(path);
        True(bytes.Length >= 24, "PNG header length");
        var signature = new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 };
        True(bytes.AsSpan(0, 8).SequenceEqual(signature), "PNG signature");
        var width = BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(16, 4));
        var height = BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(20, 4));
        Equal(64, width, "title icon width");
        Equal(64, height, "title icon height");
    }

    internal static void TestSystemMenuHookTyping()
    {
        var source = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudSystemMenuBridge.cs"));
        Contains(source, "HookFromAddress<AgentHUD.Delegates.OpenSystemMenu>", "OpenSystemMenu explicit delegate");
        Contains(source, "HookFromAddress<UIModule.Delegates.ExecuteMainCommand>", "ExecuteMainCommand explicit delegate");
    }

    internal static void TestManualReloadContract()
    {
        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(plugin, "catalog.LoadCached(Configuration.Repositories)", "startup projects the existing local database first");
        Contains(plugin, "catalogUpdates.SeedIfEmpty()", "only an empty catalog triggers asynchronous preferred/fallback seeding");
        False(plugin.Contains("catalog.RefreshAsync", StringComparison.Ordinal), "plugin constructor must not directly fan out across repositories");

        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "Refresh catalog sources", "explicit catalog update control remains inside Settings");
        Contains(ui, "updates.RefreshAsync()", "manual source refresh uses the preferred-online/fallback coordinator");
        Contains(ui, "catalog.LoadCached", "source configuration applies locally without network");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "Deliberately sequential", "fallback repository checks remain sequential");
    }

    internal static void TestStorefrontContract()
    {
        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "DrawApiBadge", "API artwork badge");
        Contains(ui, "DrawArtworkOverlayActions", "Info/install actions stay over artwork");
        Contains(ui, "Selected", "selected plugin is visibly marked in the shelf");
        Contains(ui, "Unmaintained", "unmaintained badge is visible");
        Contains(ui, "omega-author-filter", "author filter is directly available on storefront");
        Contains(ui, "selectedVariantSource", "duplicate source selection");
        Contains(ui, "fallbackIconPath", "company fallback artwork path");
        True(File.Exists(Path.Combine(Root, "images", "company-fallback.png")), "company fallback artwork file");
        Contains(ui, "ImGui.IsRectVisible", "lazy visible icon loading");
        False(ui.Contains("storefrontPage", StringComparison.Ordinal), "pagination must not return");
        False(ui.Contains("rowsPerPage", StringComparison.Ordinal), "fixed-page rows must not return");
        False(ui.Contains("ImGui.BeginTable(\"market\"", StringComparison.Ordinal), "legacy giant marketplace table must not return");
    }

    internal static void TestSpotlightAndRepositoryFilter()
    {
        var ui = ReadMarketplaceWindowSource();
        var spotlight = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Spotlight.cs"));
        Contains(ui, "MarketplaceView.Spotlight", "Spotlight is a dedicated marketplace page");
        Contains(ui, "DrawSidebarViewIcon(MarketplaceView.Spotlight, FontAwesomeIcon.Star, \"Spotlight\"", "Spotlight has its own icon-rail entry");
        Contains(spotlight, "DrawSpotlightPage", "Spotlight has a dedicated renderer");
        Contains(spotlight, "DrawSpotlightCard", "Spotlight uses self-contained information cards");
        Contains(spotlight, "SpotlightCardCount = 5", "Spotlight is laid out as five fixed columns");
        Contains(spotlight, "SpotlightCardMaxWidth", "Spotlight cards remain compact rather than becoming wide cells");
        Contains(spotlight, "DrawSpotlightPitch", "Spotlight cards carry a short promotional pitch");
        Contains(spotlight, "DrawSpotlightActionRow", "Spotlight cards carry compact install state plus information action");
        Contains(spotlight, "OpenSpotlightPluginInDiscover", "Spotlight information action opens Discover with the plugin selected");
        Contains(spotlight, "DrawSpotlightInstalledPill", "installed Spotlight state is rendered as a subdued grey status");
        Contains(spotlight, "NoScrollWithMouse", "Spotlight cards cannot be scrolled independently");
        False(spotlight.Contains("AssemblyVersionText", StringComparison.Ordinal), "Spotlight must not show plugin version metadata");
        False(spotlight.Contains("Five Omega picks.", StringComparison.Ordinal), "Spotlight must not add explanatory copy above the cards");
        False(spotlight.Contains("DrawDetailsDescription(plugin", StringComparison.Ordinal), "Spotlight must not embed the verbose details panel metadata");
        False(spotlight.Contains("DrawDetailsLinks(plugin", StringComparison.Ordinal), "Spotlight must not embed source/project link rows");
        False(spotlight.Contains("DrawSpotlightVariantSelector", StringComparison.Ordinal), "Spotlight must not spend card space on repository selectors");
        Contains(spotlight, "showOverlays: false", "Spotlight artwork stays free of API/action overlays");
        Contains(spotlight, "RefreshCuratedSourcesAsync([\"aetherlove-aetheros\"])", "missing AetherLove is rescued from its curated source");
        False(spotlight.Contains("OMEGA SPOTLIGHT", StringComparison.Ordinal), "Spotlight does not add a redundant promotional banner above the five plugins");
        Contains(ui, "HonseFarm.Client", "Honse promotion remains configured");
        Contains(ui, "AetherLovePlugin", "AetherLove/AetherOS promotion remains configured");
        Contains(ui, "InventoryTools", "Allagan Tools promotion remains configured");
        Contains(ui, "\"GatherBuddy\"", "official GatherBuddy promotion remains configured");
        False(ui.Contains("GatherBuddyReborn", StringComparison.Ordinal), "automation-oriented GatherBuddy Reborn must not occupy the Spotlight slot");
        Contains(ui, "ChatTwo", "Chat 2 promotion remains configured");
        Contains(ui, "GetOfficialDalamudIconUrl", "official Dalamud artwork has a D17 icon fallback");
        Contains(ui, "DalamudPluginsD17/refs/heads/main/stable", "official icon fallback resolves D17 stable artwork");
        Contains(ui, "DrawApplicationBar", "Spotlight uses the shared application bar rather than page-owned window controls");
        False(ui.Contains("DrawSpotlightWindowControls", StringComparison.Ordinal), "Spotlight must not own a second minimize/close row");
        False(spotlight.Contains("promoted.Add(fallback)", StringComparison.Ordinal), "Spotlight must not substitute unrelated plugins when a fixed promotion is missing");
        Contains(spotlight, "Take(SpotlightCardCount)", "Spotlight is capped at exactly five highlighted plugins");
        False(ui.Contains("DrawSpotlight(mainProjection.Plugins", StringComparison.Ordinal), "Discover must not contain the old inline Spotlight area");
        Contains(ui, "omega-repository-filter", "repository filter remains directly available");
        Contains(ui, "activeView == MarketplaceView.Spotlight ? \"All sources\" : selectedSource", "repository filter remains source-aware outside Spotlight");
        Contains(ui, "catalog.GetStableApiLevel(plugin.InternalName, currentApi)", "tile API badge resolves stable API across repository variants and prefers current support");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "GetMainProjection", "stale-aware marketplace projection");
        Contains(catalog, "GetStableApiLevel", "catalog exposes aggregate stable API metadata");
        Contains(catalog, "RepositoryHealthRules.BuildStatuses", "repository health is applied before main projection");
    }

    internal static void TestSourceTableContract()
    {
        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "omega-source-table", "source manager table");
        Contains(ui, "source-enabled-", "repository enable checkbox");
        Contains(ui, "\"Stale\"", "stale repository status");
        Contains(ui, "catalog.LoadCached(configuration.Repositories)", "deselecting a repository immediately rebuilds local catalog");
        Contains(ui, "ImGui.BeginTable(\"omega-source-table\", 5, ImGuiTableFlags.None, new Vector2(860f, 360f), 0f)", "API-15 BeginTable overload must include the flags argument before outer size");
        False(ui.Contains("selectedSourceIndex", StringComparison.Ordinal), "removed selection-list index state must not return after source table migration");

        var health = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "RepositoryHealthRules.cs"));
        Contains(health, "entries.All", "stale requires every cached plugin to be unmaintained");
        Contains(health, "IsUnmaintained(currentApi)", "repository stale threshold reuses plugin rule");
    }

}

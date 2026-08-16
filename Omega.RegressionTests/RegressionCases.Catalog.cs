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
        var bootstrap = Path.Combine(Root, "catalog", "bootstrap", "omega-catalog.sqlite.zip");
        True(File.Exists(bootstrap), "packaged SQLite bootstrap exists");
        var temp = Path.Combine(Path.GetTempPath(), "omega-sqlite-regression-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var dbPath = Path.Combine(temp, SqliteCatalogStore.DatabaseFileName);
            var store = new SqliteCatalogStore(dbPath);
            True(store.ImportBootstrapBundle(bootstrap), "bootstrap imports into empty catalog");
            var snapshot = store.ReadSnapshot();
            True(snapshot.Variants.Count > 0, "SQLite snapshot exposes variants");
            True(snapshot.SourceDefinitions.Count > 0, "SQLite snapshot exposes source definitions");
            True(snapshot.Variants.Any(x => x.InternalName.Equals("AetherLovePlugin", StringComparison.OrdinalIgnoreCase)), "bootstrap contains AetherLove");
            True(snapshot.CatalogRevision is not null, "catalog snapshot always exposes a troubleshooting Catalog Revision field");
            True(snapshot.SecurityRevision is not null, "catalog snapshot always exposes a troubleshooting Security Revision field");
            True(snapshot.EvidenceRevision is not null, "catalog snapshot always exposes a troubleshooting Evidence Revision field");
        }
        finally
        {
            if (Directory.Exists(temp)) Directory.Delete(temp, true);
        }
    }


    internal static void TestLegacyCatalogWithoutSecurityProjection()
    {
        var temp = Path.Combine(Path.GetTempPath(), "omega-legacy-sqlite-regression-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var dbPath = Path.Combine(temp, SqliteCatalogStore.DatabaseFileName);
            var store = new SqliteCatalogStore(dbPath);
            using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={dbPath}"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    INSERT INTO catalog_meta VALUES('schema_version','1');
                    INSERT INTO catalog_meta VALUES('schema_name','omega.catalog.sqlite.v1');
                    INSERT INTO catalog_meta VALUES('generated_at_utc','2026-08-15T00:00:00Z');
                    CREATE TABLE sources(
                        source_id INTEGER PRIMARY KEY,curated_id TEXT,name TEXT,url TEXT,description TEXT,
                        is_official INTEGER,enabled_by_default INTEGER,integrate_with_dalamud INTEGER);
                    INSERT INTO sources VALUES(1,'legacy','Legacy source','https://example.invalid/plugins.json','',0,1,1);
                    CREATE VIEW runtime_plugin_variants AS SELECT
                        'LegacyPlugin' AS internal_name,'Tester' AS author,'Legacy Plugin' AS name,'' AS punchline,'' AS description,'' AS changelog,
                        '1.0.0.0' AS assembly_version,NULL AS testing_assembly_version,15 AS dalamud_api_level,NULL AS testing_dalamud_api_level,
                        'any' AS applicable_version,NULL AS minimum_dalamud_version,'' AS repo_url,'https://example.invalid/plugin.zip' AS download_link_install,
                        '' AS download_link_update,'' AS download_link_testing,'' AS icon_url,'[]' AS image_urls_json,'[]' AS tags_json,'[]' AS category_tags_json,
                        0 AS download_count,0 AS last_update,0 AS is_hide,0 AS is_testing_exclusive,'' AS dip17_channel,
                        'Legacy source' AS source_name,'https://example.invalid/plugins.json' AS source_url,0 AS source_is_official,
                        '' AS website_url,'' AS website_title,'' AS website_description,'[]' AS website_image_urls_json,0 AS website_enriched;
                    """;
                command.ExecuteNonQuery();
            }

            var snapshot = store.ReadSnapshot();
            Equal(1, snapshot.Variants.Count, "legacy catalog remains readable");
            Equal("LegacyPlugin", snapshot.Variants[0].InternalName, "legacy variant identity is preserved");
            Equal(string.Empty, snapshot.Variants[0].SecurityStatus, "legacy variant is treated as not yet scanned");
            Equal("none", snapshot.Variants[0].SecurityHighestSeverity, "legacy variant receives neutral security defaults");
            Equal(string.Empty, snapshot.CatalogRevision, "legacy catalog without revision metadata remains readable");
            Equal(string.Empty, snapshot.SecurityRevision, "legacy catalog without security revision metadata remains readable");
            Equal(string.Empty, snapshot.EvidenceRevision, "legacy catalog without evidence revision metadata remains readable");
            Equal(0, snapshot.ChangelogEntryCount, "legacy catalog without changelog table remains readable");
        }
        finally
        {
            if (Directory.Exists(temp)) Directory.Delete(temp, true);
        }
    }

    internal static void TestCatalogBundleImport()
    {
        var source = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "SqliteCatalogStore.cs"));
        Contains(source, "omega-catalog.sqlite", "one production catalog filename");
        Contains(source, "PRAGMA integrity_check", "database integrity validation");
        Contains(source, "ReplaceFromBundle", "online bundle atomically replaces database");
        Contains(source, "Pooling = false", "read-only validation connections cannot retain Windows file handles");
        Contains(source, "runtime_plugin_variants", "runtime reads normalized SQLite view");
        Contains(source, "ValidateRuntimeSnapshot(candidate)", "downloaded database is fully readable before it can replace the last-known-good catalog");
        Contains(source, "ReadChangelogEntryCount", "runtime reads embedded catalog changelog identity without requiring a second format");
        Contains(source, "128L * 1024 * 1024", "runtime extracted marketplace database ceiling remains bounded well below the detailed evidence database size");
        var runtimeValidation = source.IndexOf("ValidateRuntimeSnapshot(candidate)", StringComparison.Ordinal);
        var backupMove = source.IndexOf("File.Move(DatabasePath, backup", StringComparison.Ordinal);
        True(runtimeValidation >= 0 && backupMove > runtimeValidation, "candidate runtime projection is validated before the existing database is moved");
        False(source.Contains("ManifestJson", StringComparison.Ordinal), "runtime SQLite store does not persist per-source manifest JSON files");
    }

    internal static void TestPersistentCatalogContract()
    {
        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(plugin, "omega-catalog.sqlite", "single persistent SQLite catalog");
        Contains(plugin, "catalog.LoadCached", "startup database load");
        Contains(plugin, "omega-catalog.sqlite.zip", "optional packaged bootstrap database");
        False(plugin.Contains("omega-catalog-db.zip", StringComparison.Ordinal), "legacy JSON-record bundle removed");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "SqliteCatalogStore", "marketplace is backed by SQLite");
        Contains(catalog, "liveOverlayByUrl", "explicit custom source reads remain temporary overlays");
        False(catalog.Contains("CatalogDatabaseRecord", StringComparison.Ordinal), "legacy per-source JSON database types removed");

        var updater = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CatalogUpdateCoordinator.cs"));
        Contains(updater, "retaining local Definitions", "online failure keeps last-known-good SQLite Definitions");
        False(updater.Contains("LocalFallback", StringComparison.Ordinal), "client-side public repository crawl fallback removed");

        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "Check for updates", "manual Definitions/plugin update check remains available at the top of Settings");
        Contains(ui, "Every plugin. One orbit.", "About uses the product tagline instead of database identity");
        Contains(ui, "/omega   /omg", "About advertises both marketplace commands");
        False(ui.Contains("Definitions Revision", StringComparison.Ordinal), "About does not expose Definitions revision internals");
    }

    internal static void TestDailyUpdateJobContract()
    {
        var service = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DailyCatalogUpdateService.cs"));
        Contains(service, "TimeSpan.FromDays(1)", "daily cadence");
        Contains(service, "updates.CheckForUpdatesAsync", "daily job probes for pending Definitions updates without silently applying them");
        Contains(service, "DefinitionsUpdateAvailable", "daily check records whether Definitions are pending");
        Contains(service, "LastDailyUpdateCheckUtc", "daily completion is persisted");

        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(plugin, "catalog.LoadCached", "startup loads the local catalog once");
        Contains(plugin, "DailyCatalogUpdateService", "daily job is wired into plugin lifetime");
        Contains(plugin, "dailyCatalogUpdate.TriggerIfDue", "opening Omega can trigger an overdue daily check");
    }

    internal static void TestCuratedEnableMigration()
    {
        var configuration = File.ReadAllText(Path.Combine(Root, "Omega", "Configuration.cs"));
        Contains(configuration, "Version { get; set; } = 8", "configuration schema 8");

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

        using var master = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "repository", "pluginmaster.json")));
        var manifestVersion = RequiredString(master.RootElement.EnumerateArray().Single(), "AssemblyVersion");
        Equal(projectVersion + ".0", manifestVersion, "three-part product version maps to four-part Dalamud AssemblyVersion");

        var buildInfo = File.ReadAllText(Path.Combine(Root, "Omega", "BuildInfo.cs"));
        Equal(projectVersion, Capture(buildInfo, "Version\\s*=\\s*\"([^\"]+)\""), "BuildInfo version");
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
        Contains(ui, "Check for updates", "explicit update check remains inside Settings");
        Contains(ui, "updates.CheckForUpdatesAsync()", "manual check probes Definitions and refreshes explicit user sources");
        Contains(ui, "ApplyDefinitionsUpdateAsync", "Updates page can explicitly apply a pending Definitions package");
        Contains(ui, "catalog.LoadCached", "source configuration applies locally without network");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "x.Enabled && !x.IsCurated", "automatic direct refresh is limited to explicit user-added sources");
    }

    internal static void TestStorefrontContract()
    {
        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "DrawApiBadge", "API artwork badge");
        Contains(ui, "DrawArtworkOverlayActions", "Info/install actions stay over artwork");
        Contains(ui, "Selected", "selected plugin is visibly marked in the shelf");
        Contains(ui, "Unmaintained", "unmaintained badge is visible");
        Contains(ui, "omega-author-filter", "author filter is available inside the expanded storefront filter panel");
        Contains(ui, "selectedVariantSource", "duplicate source selection");
        Contains(ui, "fallbackIconPath", "company fallback artwork path");
        True(File.Exists(Path.Combine(Root, "images", "company-fallback.png")), "company fallback artwork file");
        var artwork = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Artwork.cs"));
        Contains(artwork, "fallbackIconTexture.GetWrapOrDefault()", "all plugin artwork surfaces share the packaged fallback texture");
        False(artwork.Contains("useFallbackTexture", StringComparison.Ordinal), "plugin artwork surfaces may not opt out of the fallback image");
        False(File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductPage.cs")).Contains("useFallbackTexture", StringComparison.Ordinal),
            "product hero must show fallback artwork when the plugin has no usable icon");
        False(File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.SpotlightShelves.cs")).Contains("useFallbackTexture", StringComparison.Ordinal),
            "Spotlight shelves must show fallback artwork when the plugin has no usable icon");
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
        Contains(spotlight, "contentStartY + 112f", "Spotlight artwork/title layout uses fixed vertical anchors");
        Contains(spotlight, "contentStartY + 166f", "Spotlight separators align across all five promoted cards");
        Contains(spotlight, "OpenSpotlightPluginInDiscover", "selecting a Spotlight card opens Discover with the plugin selected");
        False(spotlight.Contains("DrawSpotlightActionRow", StringComparison.Ordinal), "Spotlight must not carry install/status action rows");
        False(spotlight.Contains("spotlight-install-", StringComparison.Ordinal), "Spotlight must not expose direct install controls");
        False(spotlight.Contains("DrawSpotlightInfoButton", StringComparison.Ordinal), "Spotlight must not expose a redundant info button");
        Contains(spotlight, "NoScrollWithMouse", "Spotlight cards cannot be scrolled independently");
        False(spotlight.Contains("AssemblyVersionText", StringComparison.Ordinal), "Spotlight must not show plugin version metadata");
        False(spotlight.Contains("Five Omega picks.", StringComparison.Ordinal), "Spotlight must not add explanatory copy above the cards");
        False(spotlight.Contains("DrawDetailsDescription(plugin", StringComparison.Ordinal), "Spotlight must not embed the verbose details panel metadata");
        False(spotlight.Contains("DrawDetailsLinks(plugin", StringComparison.Ordinal), "Spotlight must not embed source/project link rows");
        False(spotlight.Contains("DrawSpotlightVariantSelector", StringComparison.Ordinal), "Spotlight must not spend card space on repository selectors");
        Contains(spotlight, "showOverlays: false", "Spotlight artwork stays free of API/action overlays");
        Contains(spotlight, "(InternalName: \"AetherLovePlugin\", CuratedId: \"aetherlove-aetheros\")", "AetherLove remains a curated Spotlight recovery target");
        Contains(spotlight, "(InternalName: \"HonseFarm.Client\", CuratedId: \"honse-farm\")", "HonseFarm remains a curated Spotlight recovery target");
        Contains(spotlight, "RefreshCuratedSourcesAsync(curatedIds)", "missing Spotlight plugins are rescued through the generalized curated-source recovery path");
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
        Contains(spotlight, "SpotlightCardCount = 5", "Spotlight is capped at exactly five highlighted plugins");
        False(ui.Contains("DrawSpotlight(mainProjection.Plugins", StringComparison.Ordinal), "Discover must not contain the old inline Spotlight area");
        Contains(ui, "omega-repository-filter", "repository filter remains available inside the expanded filter panel");
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
        Contains(ui, "ImGui.BeginTable(\"omega-source-table\", 5, ImGuiTableFlags.None, new Vector2(860f, addSourceOpen ? 230f : 360f), 0f)", "API-15 BeginTable overload includes flags and shrinks while add-source tools are open");
        False(ui.Contains("[Curated (", StringComparison.Ordinal), "selected Curated tab must not use decorative brackets");
        var addTools = ui.IndexOf("DrawAddSourceTools();", StringComparison.Ordinal);
        var sourceTable = ui.IndexOf("DrawSourcesTable(shownSources, statuses);", StringComparison.Ordinal);
        True(addTools >= 0 && sourceTable > addTools, "add-source tools render above the scrolling source table");
        False(ui.Contains("selectedSourceIndex", StringComparison.Ordinal), "removed selection-list index state must not return after source table migration");

        var health = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "RepositoryHealthRules.cs"));
        Contains(health, "entries.All", "stale requires every cached plugin to be unmaintained");
        Contains(health, "IsUnmaintained(currentApi)", "repository stale threshold reuses plugin rule");
    }

}

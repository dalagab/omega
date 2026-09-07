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
        var bootstrap = Path.Combine(Root, "catalog", "bootstrap", "omega-marketplace.sqlite.zip");
        if (!File.Exists(bootstrap))
        {
            // The lean source tree intentionally does not commit generated catalog bytes.
            // GitHub regression/release jobs stage the authoritative catalog-builder artifact
            // before dotnet build, so those gates execute the full round-trip below. A clean
            // local/ZipRunner source build instead verifies that the project keeps the bootstrap
            // as an optional packaged asset rather than failing because CI state is absent.
            var project = File.ReadAllText(Path.Combine(Root, "Omega", "DalagabOmega.csproj"));
            Contains(project, @"catalog\bootstrap\omega-marketplace.sqlite.zip", "project consumes the published marketplace bootstrap asset");
            Contains(project, @"Condition=""Exists('..\catalog\bootstrap\omega-marketplace.sqlite.zip')""", "bootstrap remains optional for lean source builds");
            Contains(project, "<Link>omega-catalog.sqlite.zip</Link>", "staged bootstrap is packaged under the runtime filename");
            return;
        }

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
            True(snapshot.DefinitionsRevision is not null, "catalog snapshot always exposes a frozen Definitions Revision field");
            True(snapshot.SecurityRevision is not null, "catalog snapshot always exposes a troubleshooting Security Revision field");
            True(snapshot.EvidenceRevision is not null, "catalog snapshot always exposes a troubleshooting Evidence Revision field");
            True(snapshot.DependencyGraphRevision is not null, "catalog snapshot always exposes a dependency graph revision field");
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
            Equal(string.Empty, snapshot.DefinitionsRevision, "legacy catalog without Definitions revision metadata remains readable");
            Equal(string.Empty, snapshot.SecurityRevision, "legacy catalog without security revision metadata remains readable");
            Equal(string.Empty, snapshot.EvidenceRevision, "legacy catalog without evidence revision metadata remains readable");
            Equal(string.Empty, snapshot.DependencyGraphRevision, "legacy catalog without dependency graph metadata remains readable");
            Equal(0, store.ReadDependenciesForVariant(1).Count, "legacy catalog without dependency tables has an empty variant dependency graph");
            Equal(0, store.ReadDependentsForProvider(1).Count, "legacy catalog without dependency tables has an empty reverse dependency graph");
            True(store.ReadDependencyProvider("LegacyPlugin") is null, "legacy catalog without provider summaries remains readable");
            Equal(0, snapshot.ChangelogEntryCount, "legacy catalog without changelog table remains readable");
        }
        finally
        {
            if (Directory.Exists(temp)) Directory.Delete(temp, true);
        }
    }


    internal static void TestNormalizedPluginDependencyGraphContract()
    {
        var temp = Path.Combine(Path.GetTempPath(), "omega-plugin-dependencies-regression-" + Guid.NewGuid().ToString("N"));
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
                    INSERT INTO catalog_meta VALUES('dependency_graph_revision','plugin-deps-v1-test');
                    CREATE TABLE plugin_dependencies (
                        consumer_variant_id INTEGER NOT NULL,
                        consumer_plugin_id INTEGER NOT NULL,
                        consumer_internal_name TEXT NOT NULL,
                        consumer_version TEXT NOT NULL,
                        provider_plugin_id INTEGER NOT NULL,
                        provider_internal_name TEXT NOT NULL,
                        relationship TEXT NOT NULL,
                        version_constraint TEXT NOT NULL,
                        resolved_version TEXT NOT NULL,
                        resolution_status TEXT NOT NULL,
                        version_status TEXT NOT NULL,
                        confidence TEXT NOT NULL,
                        source_kind TEXT NOT NULL,
                        origins_json TEXT NOT NULL,
                        install_eligible INTEGER NOT NULL,
                        PRIMARY KEY(consumer_variant_id,provider_internal_name,relationship,version_constraint)
                    );
                    CREATE TABLE plugin_dependency_providers (
                        provider_plugin_id INTEGER NOT NULL,
                        provider_internal_name TEXT PRIMARY KEY,
                        required_by_count INTEGER NOT NULL,
                        recommended_by_count INTEGER NOT NULL,
                        optional_by_count INTEGER NOT NULL,
                        total_dependent_plugins INTEGER NOT NULL
                    );
                    INSERT INTO plugin_dependencies VALUES
                        (101,11,'ConsumerA','1.0.0.0',22,'ProviderB','required','>=2.0','2.4.0','resolved','compatible','High','external-plugin','["manifest","source"]',1),
                        (102,12,'ConsumerC','3.0.0.0',22,'ProviderB','recommended','','2.4.0','resolved','compatible','Medium','plugin','["manifest"]',1),
                        (103,13,'ConsumerIPC','1.0.0.0',22,'ProviderB','required','','','resolved','compatible','High','ipc','["ipc"]',1);
                    INSERT INTO plugin_dependency_providers VALUES(22,'ProviderB',1,1,0,2);
                    """;
                command.ExecuteNonQuery();
            }

            var variant = store.ReadDependenciesForVariant(101);
            Equal(1, variant.Count, "normalized variant dependency is readable");
            Equal("ProviderB", variant[0].ProviderInternalName, "normalized provider identity is preserved");
            Equal(PluginDependencyRelationship.Required, variant[0].Relationship, "required relationship is parsed");
            True(variant[0].InstallEligible, "install eligibility is preserved");
            Equal(2, variant[0].Origins.Count, "dependency origins are parsed");

            var consumer = store.ReadDependenciesForPlugin(11);
            Equal(1, consumer.Count, "consumer plugin dependency lookup is readable");

            var reverse = store.ReadDependentsForProvider(22);
            Equal(2, reverse.Count, "reverse dependency lookup excludes IPC authority rows");
            True(reverse.All(x => !x.SourceKind.Equals("ipc", StringComparison.OrdinalIgnoreCase)),
                "IPC never enters normalized package-manager dependency reads");

            var provider = store.ReadDependencyProvider("ProviderB");
            True(provider is not null, "provider summary is readable by stable internal name");
            Equal(1, provider!.RequiredByCount, "provider required-by count is preserved");
            Equal(2, provider.TotalDependentPlugins, "provider total dependent count is preserved");
        }
        finally
        {
            if (Directory.Exists(temp)) Directory.Delete(temp, true);
        }

        var ui = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Dependencies.cs"));
        Contains(ui, "catalog.GetDependenciesForVariant", "Requires UI uses normalized consumer-variant package authority");
        Contains(ui, "catalog.GetDependentsForProvider", "Required by UI uses normalized reverse dependency authority");
        Contains(ui, "IPC relationships are security/integration observations, not package-install dependencies.",
            "IPC remains explicitly separate from package dependencies");
        DoesNotContain(ui, "Required IPC provider. Install separately.", "IPC is no longer presented as package-install authority");

        var install = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Install.cs"));
        DoesNotContain(install, "DrawRequiredProviderInstallWarning", "single-plugin install no longer blocks on inferred IPC providers");
        Contains(install, "SecurityDependencies (including IPC observations) remain presentation-only",
            "install flow documents the package-authority boundary");
    }


    internal static void TestCatalogBundleImport()
    {
        var source = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "SqliteCatalogStore.cs"));
        Contains(source, "omega-catalog.sqlite", "one production catalog filename");
        Contains(source, "PRAGMA integrity_check", "database integrity validation");
        Contains(source, "ReplaceFromBundle", "online bundle atomically replaces database");
        Contains(source, "Pooling = false", "read-only validation connections cannot retain Windows file handles");
        Contains(source, "runtime_plugin_variants", "runtime reads normalized SQLite view");
        Contains(source, "catalogPluginIdProjection", "runtime imports stable SQLite plugin identity for cross-repository Discover counting");
        Contains(source, "CatalogPluginId = GetLong(reader, 61)", "runtime variants retain their canonical database plugin id");
        Contains(source, "catalogVariantIdProjection", "runtime imports exact SQLite variant identity for dependency authority");
        Contains(source, "CatalogVariantId = GetLong(reader, 66)", "runtime variants retain their exact database variant id");
        Contains(source, "dependency_graph_revision", "runtime reads the normalized dependency graph revision");
        Contains(source, "plugin_dependencies", "runtime can query normalized package dependency edges");
        Contains(source, "plugin_dependency_providers", "runtime can query normalized reverse dependency summaries");
        Contains(source, "IsNormalizedPluginDependencySourceKind", "runtime excludes IPC and non-plugin components from package authority");
        Contains(source, "ValidateRuntimeSnapshot(candidate)", "downloaded database is fully readable before it can replace the last-known-good catalog");
        Contains(source, "ReadChangelogEntryCount", "runtime reads embedded catalog changelog identity without requiring a second format");
        Contains(source, "TableExists(connection, \"plugin_search\")", "new Definitions can use the compact logical search projection while older databases retain runtime fallback");
        Contains(source, "QueryDiscoverInternalNames", "catalog-native Discover predicates are evaluated in SQLite before managed filtering");
        Contains(source, "json_each(tags_json)", "multi-tag AND filtering can be reduced in SQLite without building a RAM inverted index");
        Contains(source, "128L * 1024 * 1024", "runtime extracted marketplace database ceiling remains bounded well below the detailed evidence database size");
        var runtimeValidation = source.IndexOf("ValidateRuntimeSnapshot(candidate)", StringComparison.Ordinal);
        var backupMove = source.IndexOf("File.Move(DatabasePath, backup", StringComparison.Ordinal);
        True(runtimeValidation >= 0 && backupMove > runtimeValidation, "candidate runtime projection is validated before the existing database is moved");
        False(source.Contains("ManifestJson", StringComparison.Ordinal), "runtime SQLite store does not persist per-source manifest JSON files");
    }

    internal static void TestLazyDefinitionsReadModelContract()
    {
        var store = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "SqliteCatalogStore.cs"));
        var catalog = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "MarketplaceCatalogService.cs"));
        var refresh = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "MarketplaceCatalogService.Refresh.cs"));
        var artwork = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Artwork.cs"));

        Contains(store, "ReadVariants(connection, includeDetails: false)", "startup materializes lightweight marketplace summaries instead of full detail rows");
        Contains(store, "ReadSecurityFindingSummaries", "startup keeps finding identity/severity without retaining verbose evidence bodies");
        Contains(store, "website_license", "client reads optional enriched license metadata without requiring newer Definitions");
        Contains(store, "includeDetails ? GetString(reader, 31) : string.Empty", "README excerpts stay on disk until a selected plugin is hydrated");
        Contains(store, "includeDetails ? ReadProjectLinks", "project-link arrays stay on disk until detail hydration");
        Contains(store, "ReadPluginChangelogHistory(connection, internalName)", "historical changelog text is queried for one plugin on demand");
        Contains(store, "SearchInternalNames", "README-backed marketplace search can query Definitions without retaining every README");
        Contains(catalog, "DetailedVariantCacheLimit = 64", "full detail hydration is bounded");
        Contains(catalog, "ChangelogCacheLimit = 32", "historical changelog hydration is bounded");
        Contains(catalog, "HydrateVariant", "selected products can hydrate their exact full SQLite row");
        Contains(catalog, "summary.OmegaWebsiteLicense = detailed.OmegaWebsiteLicense", "runtime manifest hydration retains enriched license metadata without replacing live package links");
        Contains(artwork, "catalog.HydrateVariant", "opening a product page hydrates detail data instead of relying on the startup summary");
        DoesNotContain(refresh, "snapshot.PluginChangelogHistory", "startup no longer retains all historical changelogs");
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
        Contains(service, "AutomaticCheckCadence = TimeSpan.FromHours(1)", "Definitions descriptor is checked hourly");
        Contains(service, "PollInterval = TimeSpan.FromMinutes(15)", "scheduler notices the next hourly due time promptly");
        Contains(service, "updates.CheckDefinitionsForUpdatesAsync", "automatic polling probes only the tiny Definitions descriptor without refreshing every user repository");
        Contains(service, "LastDefinitionsUpdateCheckUtc", "automatic completion is persisted separately from the legacy daily field");
        Contains(service, "LastNotifiedDefinitionsRevision", "each Definitions revision is announced only once");
        Contains(service, "Omega Definitions update available", "new Definitions revisions produce a visible Dalamud notification");
        Contains(service, "INotificationManager", "notification delivery uses Dalamud's notification service");
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CatalogUpdateCoordinator.cs"));
        Contains(coordinator, "CheckDefinitionsForUpdatesAsync", "coordinator exposes a descriptor-only automatic probe");
        Contains(coordinator, "refreshUnmanagedDalamudSources: false", "automatic Definitions probes do not fan out to unmanaged Dalamud repositories");

        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(plugin, "catalog.LoadCached", "startup loads the local catalog once");
        Contains(plugin, "INotificationManager Notifications", "Dalamud notification manager is injected");
        Contains(plugin, "DailyCatalogUpdateService", "Definitions polling job is wired into plugin lifetime");
        Contains(plugin, "DalamudUpdateNotificationBridge", "Dalamud plugin-update notification routing is wired into plugin lifetime");
        Contains(plugin, "OpenUpdatesUi", "notification routing has a direct Omega Updates navigation target");
        Contains(plugin, "dailyCatalogUpdate.TriggerIfDue", "opening Omega can trigger an overdue hourly check");
    }

    internal static void TestCuratedEnableMigration()
    {
        var configuration = File.ReadAllText(Path.Combine(Root, "Omega", "Configuration.cs"));
        Contains(configuration, "Version { get; set; } = 24", "configuration schema 24");

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
        Contains(catalog, "x.Enabled && !x.IsCurated", "automatic direct refresh is limited to unmanaged Dalamud overlays");
    }

    internal static void TestStorefrontContract()
    {
        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "DrawApiBadge", "API artwork badge");
        Contains(ui, "DrawArtworkOverlayActions", "Info/install actions stay over artwork");
        Contains(ui, "Selected", "selected plugin is visibly marked in the shelf");
        Contains(ui, "Unmaintained", "unmaintained badge is visible");
        Contains(ui, "omega-author-filter", "author filter is available inside the expanded storefront filter panel");
        Contains(ui, "selectedAuthors", "author filtering supports multiple removable identities");
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
        Contains(spotlight, "contentStartY + Ui(112f)", "Spotlight artwork/title layout uses fixed vertical anchors");
        Contains(spotlight, "contentStartY + Ui(166f)", "Spotlight separators align across all five promoted cards");
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
        Contains(ui, "ImGuiTableFlags.ScrollY", "repository table owns its own vertical scrolling");
        Contains(ui, "ImGui.TableSetupScrollFreeze(0, 1)", "repository table keeps its header visible while scrolling");
        Contains(ui, "ImGui.ImGuiListClipper()", "repository table virtualizes off-screen rows");
        Contains(ui, "clipper.Begin(shownSources.Count", "repository clipper is bounded to the filtered row count");
        False(ui.Contains("foreach (var source in shownSources)\n        {\n            var normalized = NormalizeUrl(source.Url);", StringComparison.Ordinal), "repository table no longer performs its former full-row render loop each frame");
        Contains(ui, "RepositoryApiLevelsCustomized", "repository manager persists API-version filter customization");
        Contains(ui, "repository-api-selector", "repository API versions stay collapsed until the selector is opened");
        Contains(ui, "Current only (API", "repository API selector keeps the current-API shortcut inside its popup");
        Contains(ui, "All APIs##repository-api-all", "repository API selector keeps the All shortcut inside its popup");
        Contains(ui, "ImGuiSelectableFlags.DontClosePopups", "repository API selector stays open while multi-selecting");
        Contains(ui, "io.KeyShift", "repository API list supports Shift range selection");
        Contains(ui, "io.KeyCtrl", "repository API list supports Ctrl toggling");
        Contains(ui, "repositoryApiSelectionAnchor", "repository API range selection remembers its anchor");
        DoesNotContain(ui, "repository-api-multiselect", "repository API list is no longer permanently expanded in Settings");
        Contains(ui, "Don't use shown##repository-disable-shown", "repository manager exposes bulk deselection for the filtered list");
        Contains(ui, "protectedByDalamud", "repository manager protects existing Dalamud registrations from disable actions");
        Contains(ui, "settings-tab-repositories", "Repositories is a fixed top-level Settings tab");
        Contains(ui, "ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse", "Settings modal itself does not scroll its close control out of view");
        False(ui.Contains("[Curated (", StringComparison.Ordinal), "selected Curated tab must not use decorative brackets");
        var repositoriesTab = ui.IndexOf("private void DrawSettingsRepositoriesTab", StringComparison.Ordinal);
        var addTools = repositoriesTab >= 0
            ? ui.IndexOf("DrawAddSourceTools();", repositoriesTab, StringComparison.Ordinal)
            : -1;
        var sourceTable = repositoriesTab >= 0
            ? ui.IndexOf("DrawSourcesTable(shownSources", repositoriesTab, StringComparison.Ordinal)
            : -1;
        True(repositoriesTab >= 0 && addTools > repositoriesTab && sourceTable > addTools,
            "add-source tools render above the scrolling source table");
        False(ui.Contains("selectedSourceIndex", StringComparison.Ordinal), "removed selection-list index state must not return after source table migration");

        var health = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "RepositoryHealthRules.cs"));
        Contains(health, "entries.All", "stale requires every cached plugin to be unmaintained");
        Contains(health, "IsUnmaintained(currentApi)", "repository stale threshold reuses plugin rule");
    }

}

using System.IO.Compression;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Dalagab.Omega;

internal sealed record SqliteCatalogSnapshot(
    IReadOnlyList<MarketplacePlugin> Variants,
    IReadOnlyList<CuratedSourceDefinition> SourceDefinitions,
    DateTimeOffset? GeneratedAtUtc,
    string CatalogRevision,
    string DefinitionsRevision,
    string SecurityRevision,
    string EvidenceRevision,
    string DependencyGraphRevision,
    DateTimeOffset? RevisionUpdatedAtUtc,
    int ChangelogEntryCount);

/// <summary>
/// Owns Omega's single client marketplace database. Detailed security evidence remains server-side.
/// JSON is never a runtime catalog format: the client validates and reads one SQLite file, and
/// online marketplace updates atomically replace it.
/// </summary>
internal sealed class SqliteCatalogStore
{
    internal const int SchemaVersion = 1;
    internal const string DatabaseFileName = "omega-catalog.sqlite";
    private const string SchemaName = "omega.catalog.sqlite.v1";

    private static int sqliteInitialized;
    private readonly object sync = new();

    public SqliteCatalogStore(string databasePath)
    {
        DatabasePath = databasePath;
        Directory.CreateDirectory(Path.GetDirectoryName(databasePath) ?? ".");
        EnsureSqliteInitialized();
    }

    public string DatabasePath { get; }

    public bool Exists => File.Exists(DatabasePath);

    public long DatabaseSizeBytes
    {
        get
        {
            try
            {
                return Exists ? new FileInfo(DatabasePath).Length : 0L;
            }
            catch
            {
                return 0L;
            }
        }
    }

    public SqliteCatalogSnapshot ReadSnapshot()
    {
        lock (sync)
        {
            // Native SQLite can retain a read handle briefly after a managed connection is
            // disposed. Read from a disposable copy so the authoritative catalog can always be
            // moved/replaced/deleted immediately by updates and Windows regression cleanup.
            return WithDisposableDatabaseCopy(DatabasePath, copyPath =>
            {
                using var connection = OpenReadOnly(copyPath);
                ValidateConnection(connection);
                return new SqliteCatalogSnapshot(
                    ReadVariants(connection, includeDetails: false),
                    ReadSourceDefinitions(connection),
                    ReadGeneratedAt(connection),
                    ReadMeta(connection, "catalog_revision"),
                    ReadMeta(connection, "definitions_revision"),
                    ReadMeta(connection, "security_revision"),
                    ReadMeta(connection, "evidence_revision"),
                    ReadMeta(connection, "dependency_graph_revision"),
                    ReadRevisionUpdatedAt(connection),
                    ReadChangelogEntryCount(connection));
            });
        }
    }

    public IReadOnlyList<MarketplacePlugin> ReadVariantDetails(string internalName)
    {
        if (string.IsNullOrWhiteSpace(internalName) || !Exists)
            return [];

        lock (sync)
        {
            using var connection = OpenReadOnly(DatabasePath);
            return ReadVariants(connection, includeDetails: true, internalName);
        }
    }

    public IReadOnlyList<MarketplaceChangelogEntry> ReadChangelogHistory(string internalName)
    {
        if (string.IsNullOrWhiteSpace(internalName) || !Exists)
            return [];

        lock (sync)
        {
            using var connection = OpenReadOnly(DatabasePath);
            return ReadPluginChangelogHistory(connection, internalName);
        }
    }

    public IReadOnlyList<CuratedSourceDefinition> ReadSourceDefinitions()
    {
        if (!Exists)
            return [];

        lock (sync)
        {
            using var connection = OpenReadOnly(DatabasePath);
            return ReadSourceDefinitions(connection);
        }
    }

    public IReadOnlyList<PluginDependencyEdge> ReadDependenciesForVariant(long variantId)
    {
        if (variantId <= 0 || !Exists)
            return [];

        lock (sync)
        {
            return WithDisposableDatabaseCopy(DatabasePath, copyPath =>
            {
                using var connection = OpenReadOnly(copyPath);
                return ReadDependencyEdges(connection, "consumer_variant_id", variantId);
            });
        }
    }

    public IReadOnlyList<PluginDependencyEdge> ReadDependenciesForPlugin(long pluginId)
    {
        if (pluginId <= 0 || !Exists)
            return [];

        lock (sync)
        {
            return WithDisposableDatabaseCopy(DatabasePath, copyPath =>
            {
                using var connection = OpenReadOnly(copyPath);
                return ReadDependencyEdges(connection, "consumer_plugin_id", pluginId);
            });
        }
    }

    public IReadOnlyList<PluginDependencyEdge> ReadDependentsForProvider(long providerPluginId)
    {
        if (providerPluginId <= 0 || !Exists)
            return [];

        lock (sync)
        {
            return WithDisposableDatabaseCopy(DatabasePath, copyPath =>
            {
                using var connection = OpenReadOnly(copyPath);
                return ReadDependencyEdges(connection, "provider_plugin_id", providerPluginId);
            });
        }
    }

    public IReadOnlyList<PluginDependencyEdge> ReadDependentsForProvider(string internalName)
    {
        if (string.IsNullOrWhiteSpace(internalName) || !Exists)
            return [];

        lock (sync)
        {
            return WithDisposableDatabaseCopy(DatabasePath, copyPath =>
            {
                using var connection = OpenReadOnly(copyPath);
                return ReadDependencyEdges(connection, internalName.Trim());
            });
        }
    }

    public PluginDependencyProvider? ReadDependencyProvider(long providerPluginId)
    {
        if (providerPluginId <= 0 || !Exists)
            return null;

        lock (sync)
        {
            return WithDisposableDatabaseCopy(DatabasePath, copyPath =>
            {
                using var connection = OpenReadOnly(copyPath);
                return ReadDependencyProvider(connection, "provider_plugin_id", providerPluginId);
            });
        }
    }

    public PluginDependencyProvider? ReadDependencyProvider(string internalName)
    {
        if (string.IsNullOrWhiteSpace(internalName) || !Exists)
            return null;

        lock (sync)
        {
            return WithDisposableDatabaseCopy(DatabasePath, copyPath =>
            {
                using var connection = OpenReadOnly(copyPath);
                return ReadDependencyProvider(connection, internalName.Trim());
            });
        }
    }

    public IReadOnlySet<string> SearchInternalNames(string search, string? sourceName = null)
    {
        var needle = (search ?? string.Empty).Trim();
        if (needle.Length == 0 || !Exists)
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        lock (sync)
        {
            using var connection = OpenReadOnly(DatabasePath);
            return SearchInternalNames(connection, needle, sourceName);
        }
    }

    public IReadOnlySet<string> QueryDiscoverInternalNames(
        string search,
        string? sourceName,
        IReadOnlyCollection<string>? enabledSourceUrls,
        int apiLevel,
        bool requireInstallableApiBuild,
        bool preferTesting,
        string? category,
        IReadOnlyCollection<string> tags,
        bool? adultOnly,
        int securityFilter)
    {
        if (!Exists)
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        lock (sync)
        {
            using var connection = OpenReadOnly(DatabasePath);
            var runtimeColumns = RuntimeViewColumns(connection);
            var predicates = new List<string> { "is_hide=0" };
            using var command = connection.CreateCommand();

            var normalizedSource = string.IsNullOrWhiteSpace(sourceName) ||
                                   sourceName.Equals("All sources", StringComparison.OrdinalIgnoreCase)
                ? string.Empty
                : sourceName.Trim();
            if (normalizedSource.Length > 0)
            {
                predicates.Add("source_name COLLATE NOCASE=$source");
                command.Parameters.AddWithValue("$source", normalizedSource);
            }

            var enabledUrls = (enabledSourceUrls ?? [])
                .Where(url => !string.IsNullOrWhiteSpace(url))
                .Select(url => url.Trim().TrimEnd('/'))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (enabledUrls.Length > 0)
            {
                var parameters = new List<string>(enabledUrls.Length);
                for (var index = 0; index < enabledUrls.Length; index++)
                {
                    var parameter = $"$sourceUrl{index}";
                    parameters.Add(parameter);
                    command.Parameters.AddWithValue(parameter, enabledUrls[index]);
                }
                predicates.Add($"RTRIM(source_url,'/') COLLATE NOCASE IN ({string.Join(",", parameters)})");
            }

            if (apiLevel > 0)
            {
                predicates.Add(requireInstallableApiBuild
                    ? """
                      ((is_testing_exclusive=0 AND dalamud_api_level=$api AND TRIM(download_link_install)<>'') OR
                       (((is_testing_exclusive<>0) OR $preferTesting=1) AND testing_dalamud_api_level=$api AND TRIM(download_link_testing)<>''))
                      """
                    : "(dalamud_api_level=$api OR testing_dalamud_api_level=$api)");
                command.Parameters.AddWithValue("$api", apiLevel);
                command.Parameters.AddWithValue("$preferTesting", preferTesting ? 1 : 0);
            }

            var normalizedCategory = (category ?? string.Empty).Trim();
            if (normalizedCategory.Length > 0 &&
                !normalizedCategory.Equals("All categories", StringComparison.OrdinalIgnoreCase))
            {
                predicates.Add("EXISTS (SELECT 1 FROM json_each(category_tags_json) WHERE value COLLATE NOCASE=$category)");
                command.Parameters.AddWithValue("$category", normalizedCategory);
            }

            var normalizedTags = tags
                .Where(tag => !string.IsNullOrWhiteSpace(tag))
                .Select(tag => tag.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            for (var index = 0; index < normalizedTags.Length; index++)
            {
                var parameter = $"$tag{index}";
                predicates.Add($"EXISTS (SELECT 1 FROM json_each(tags_json) WHERE value COLLATE NOCASE={parameter})");
                command.Parameters.AddWithValue(parameter, normalizedTags[index]);
            }

            if (adultOnly is not null)
            {
                var adultTagPredicate = """
                    EXISTS (
                        SELECT 1 FROM json_each(tags_json)
                         WHERE LOWER(value) IN ('nsfw','adult','18+','18plus','explicit','sexual-content','mature')
                    ) OR
                    EXISTS (
                        SELECT 1 FROM json_each(category_tags_json)
                         WHERE LOWER(value) IN ('nsfw','adult','18+','18plus','explicit','sexual-content','mature')
                    )
                    """;
                var adultPredicate = runtimeColumns.Contains("plugin_nsfw")
                    ? $"(plugin_nsfw<>0 OR {adultTagPredicate})"
                    : $"({adultTagPredicate})";
                predicates.Add(adultOnly.Value ? adultPredicate : $"NOT {adultPredicate}");
            }

            if (runtimeColumns.Contains("security_status") && securityFilter != 0)
            {
                predicates.Add(securityFilter switch
                {
                    1 => "LOWER(security_status)='complete'",
                    2 => "LOWER(security_status)<>'complete'",
                    3 => "LOWER(security_highest_severity) IN ('caution','high','critical')",
                    4 => "LOWER(security_highest_severity) IN ('high','critical')",
                    _ => "1=1",
                });
            }

            var needle = (search ?? string.Empty).Trim();
            if (needle.Length > 0)
            {
                command.Parameters.AddWithValue("$pattern", $"%{needle}%");
                if (TableExists(connection, "plugin_search") && normalizedSource.Length == 0)
                {
                    predicates.Add("""
                        internal_name COLLATE NOCASE IN (
                            SELECT internal_name
                              FROM plugin_search
                             WHERE internal_name LIKE $pattern COLLATE NOCASE OR
                                   name LIKE $pattern COLLATE NOCASE OR
                                   author LIKE $pattern COLLATE NOCASE OR
                                   punchline LIKE $pattern COLLATE NOCASE OR
                                   description LIKE $pattern COLLATE NOCASE OR
                                   tags LIKE $pattern COLLATE NOCASE OR
                                   website_text LIKE $pattern COLLATE NOCASE
                        )
                        """);
                }
                else
                {
                    var readmePredicate = runtimeColumns.Contains("website_readme_excerpt")
                        ? " OR website_readme_excerpt LIKE $pattern COLLATE NOCASE"
                        : string.Empty;
                    predicates.Add($"""
                        (internal_name LIKE $pattern COLLATE NOCASE OR
                         name LIKE $pattern COLLATE NOCASE OR
                         author LIKE $pattern COLLATE NOCASE OR
                         punchline LIKE $pattern COLLATE NOCASE OR
                         description LIKE $pattern COLLATE NOCASE OR
                         website_description LIKE $pattern COLLATE NOCASE OR
                         tags_json LIKE $pattern COLLATE NOCASE OR
                         category_tags_json LIKE $pattern COLLATE NOCASE
                         {readmePredicate})
                        """);
                }
            }

            command.CommandText = $"""
                SELECT DISTINCT internal_name
                  FROM runtime_plugin_variants
                 WHERE {(predicates.Count == 0 ? "1=1" : string.Join(" AND ", predicates))};
                """;
            return ReadInternalNameSet(command);
        }
    }

    private static IReadOnlySet<string> SearchInternalNames(
        SqliteConnection connection,
        string needle,
        string? sourceName)
    {
        var normalizedSource = string.IsNullOrWhiteSpace(sourceName) ||
                               sourceName.Equals("All sources", StringComparison.OrdinalIgnoreCase)
            ? string.Empty
            : sourceName.Trim();
        using var command = connection.CreateCommand();
        command.Parameters.AddWithValue("$pattern", $"%{needle}%");
        command.Parameters.AddWithValue("$source", normalizedSource);

        if (TableExists(connection, "plugin_search") && normalizedSource.Length == 0)
        {
            command.CommandText = """
                SELECT DISTINCT internal_name
                  FROM plugin_search
                 WHERE internal_name LIKE $pattern COLLATE NOCASE OR
                       name LIKE $pattern COLLATE NOCASE OR
                       author LIKE $pattern COLLATE NOCASE OR
                       punchline LIKE $pattern COLLATE NOCASE OR
                       description LIKE $pattern COLLATE NOCASE OR
                       tags LIKE $pattern COLLATE NOCASE OR
                       website_text LIKE $pattern COLLATE NOCASE;
                """;
            return ReadInternalNameSet(command);
        }

        var columns = RuntimeViewColumns(connection);
        var readmePredicate = columns.Contains("website_readme_excerpt")
            ? " OR website_readme_excerpt LIKE $pattern COLLATE NOCASE"
            : string.Empty;
        command.CommandText = $"""
            SELECT DISTINCT internal_name
              FROM runtime_plugin_variants
             WHERE ($source='' OR source_name COLLATE NOCASE=$source)
               AND (
                    internal_name LIKE $pattern COLLATE NOCASE OR
                    name LIKE $pattern COLLATE NOCASE OR
                    author LIKE $pattern COLLATE NOCASE OR
                    punchline LIKE $pattern COLLATE NOCASE OR
                    description LIKE $pattern COLLATE NOCASE OR
                    website_description LIKE $pattern COLLATE NOCASE OR
                    tags_json LIKE $pattern COLLATE NOCASE OR
                    category_tags_json LIKE $pattern COLLATE NOCASE
                    {readmePredicate}
               );
            """;
        return ReadInternalNameSet(command);
    }

    private static IReadOnlySet<string> ReadInternalNameSet(SqliteCommand command)
    {
        using var reader = command.ExecuteReader();
        var matches = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (reader.Read())
        {
            var internalName = GetString(reader, 0);
            if (!string.IsNullOrWhiteSpace(internalName))
                matches.Add(internalName);
        }
        return matches;
    }

    private static bool TableExists(SqliteConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$name LIMIT 1;";
        command.Parameters.AddWithValue("$name", tableName);
        return command.ExecuteScalar() is not null;
    }

    private static IReadOnlyList<PluginDependencyEdge> ReadDependencyEdges(
        SqliteConnection connection,
        string numericColumn,
        long numericValue)
    {
        if (!TableExists(connection, "plugin_dependencies"))
            return [];
        if (numericColumn is not ("consumer_variant_id" or "consumer_plugin_id" or "provider_plugin_id"))
            throw new ArgumentOutOfRangeException(nameof(numericColumn));

        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT consumer_variant_id,consumer_plugin_id,consumer_internal_name,consumer_version,
                   provider_plugin_id,provider_internal_name,relationship,version_constraint,
                   resolved_version,resolution_status,version_status,confidence,source_kind,
                   origins_json,install_eligible
              FROM plugin_dependencies
             WHERE {numericColumn}=$value
             ORDER BY consumer_plugin_id,consumer_variant_id,provider_internal_name COLLATE NOCASE,
                      relationship,version_constraint;
            """;
        command.Parameters.AddWithValue("$value", numericValue);
        return ReadDependencyEdges(command);
    }

    private static IReadOnlyList<PluginDependencyEdge> ReadDependencyEdges(
        SqliteConnection connection,
        string providerInternalName)
    {
        if (!TableExists(connection, "plugin_dependencies"))
            return [];

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT consumer_variant_id,consumer_plugin_id,consumer_internal_name,consumer_version,
                   provider_plugin_id,provider_internal_name,relationship,version_constraint,
                   resolved_version,resolution_status,version_status,confidence,source_kind,
                   origins_json,install_eligible
              FROM plugin_dependencies
             WHERE provider_internal_name=$internalName COLLATE NOCASE
             ORDER BY consumer_plugin_id,consumer_variant_id,provider_internal_name COLLATE NOCASE,
                      relationship,version_constraint;
            """;
        command.Parameters.AddWithValue("$internalName", providerInternalName);
        return ReadDependencyEdges(command);
    }

    private static IReadOnlyList<PluginDependencyEdge> ReadDependencyEdges(SqliteCommand command)
    {
        using var reader = command.ExecuteReader();
        var result = new List<PluginDependencyEdge>();
        while (reader.Read())
        {
            var sourceKind = GetString(reader, 12);
            if (!IsNormalizedPluginDependencySourceKind(sourceKind))
                continue;

            result.Add(new PluginDependencyEdge(
                GetLong(reader, 0),
                GetLong(reader, 1),
                GetString(reader, 2),
                GetString(reader, 3),
                GetLong(reader, 4),
                GetString(reader, 5),
                ParseDependencyRelationship(GetString(reader, 6)),
                GetString(reader, 7),
                GetString(reader, 8),
                GetString(reader, 9),
                GetString(reader, 10),
                GetString(reader, 11),
                sourceKind,
                ReadStrings(GetString(reader, 13, "[]")),
                GetBool(reader, 14)));
        }
        return result;
    }

    private static PluginDependencyProvider? ReadDependencyProvider(
        SqliteConnection connection,
        string numericColumn,
        long numericValue)
    {
        if (!TableExists(connection, "plugin_dependency_providers"))
            return null;
        if (numericColumn != "provider_plugin_id")
            throw new ArgumentOutOfRangeException(nameof(numericColumn));

        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT provider_plugin_id,provider_internal_name,required_by_count,recommended_by_count,
                   optional_by_count,total_dependent_plugins
              FROM plugin_dependency_providers
             WHERE {numericColumn}=$value
             LIMIT 1;
            """;
        command.Parameters.AddWithValue("$value", numericValue);
        return ReadDependencyProvider(command);
    }

    private static PluginDependencyProvider? ReadDependencyProvider(
        SqliteConnection connection,
        string providerInternalName)
    {
        if (!TableExists(connection, "plugin_dependency_providers"))
            return null;

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT provider_plugin_id,provider_internal_name,required_by_count,recommended_by_count,
                   optional_by_count,total_dependent_plugins
              FROM plugin_dependency_providers
             WHERE provider_internal_name=$internalName COLLATE NOCASE
             LIMIT 1;
            """;
        command.Parameters.AddWithValue("$internalName", providerInternalName);
        return ReadDependencyProvider(command);
    }

    private static PluginDependencyProvider? ReadDependencyProvider(SqliteCommand command)
    {
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return null;

        return new PluginDependencyProvider(
            GetLong(reader, 0),
            GetString(reader, 1),
            GetInt(reader, 2),
            GetInt(reader, 3),
            GetInt(reader, 4),
            GetInt(reader, 5));
    }

    private static bool IsNormalizedPluginDependencySourceKind(string value)
        => (value ?? string.Empty).Trim().ToLowerInvariant() is
            "external-plugin" or "plugin" or "project-reference";

    private static PluginDependencyRelationship ParseDependencyRelationship(string value)
        => (value ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "required" => PluginDependencyRelationship.Required,
            "recommended" => PluginDependencyRelationship.Recommended,
            "optional" => PluginDependencyRelationship.Optional,
            _ => PluginDependencyRelationship.Observed,
        };

    public void ReplaceFromBundle(string zipPath)
    {
        var parent = Path.GetDirectoryName(DatabasePath) ?? ".";
        Directory.CreateDirectory(parent);
        var staged = Path.Combine(parent, $"omega-catalog.staged-{Guid.NewGuid():N}.sqlite");
        var backup = Path.Combine(parent, $"omega-catalog.backup-{Guid.NewGuid():N}.sqlite");

        try
        {
            ExtractDatabase(zipPath, staged);

            // Never open the staged path with SQLite: a native provider may keep a file handle
            // alive just long enough to make the subsequent File.Move fail. Validate a byte-for-byte
            // disposable copy instead; the untouched staged file stays movable.
            WithDisposableDatabaseCopy(staged, validationPath =>
            {
                using var candidate = OpenReadOnly(validationPath);
                ValidateConnection(candidate);
                ValidateRuntimeSnapshot(candidate);
                return true;
            });

            lock (sync)
            {
                var hadExisting = File.Exists(DatabasePath);
                try
                {
                    if (hadExisting)
                        File.Move(DatabasePath, backup, overwrite: true);
                    File.Move(staged, DatabasePath, overwrite: true);
                    if (File.Exists(backup))
                        File.Delete(backup);
                }
                catch
                {
                    if (File.Exists(DatabasePath))
                        File.Delete(DatabasePath);
                    if (File.Exists(backup))
                        File.Move(backup, DatabasePath, overwrite: true);
                    throw;
                }
            }
        }
        finally
        {
            TryDelete(staged);
            TryDelete(backup);
        }
    }

    public bool ImportBootstrapBundle(string bundlePath)
    {
        if (Exists || !File.Exists(bundlePath))
            return false;
        ReplaceFromBundle(bundlePath);
        return true;
    }

    internal static void ValidateDatabaseFile(string path)
    {
        EnsureSqliteInitialized();
        WithDisposableDatabaseCopy(path, validationPath =>
        {
            using var connection = OpenReadOnly(validationPath);
            ValidateConnection(connection);
            return true;
        });
    }

    internal static void EnsureSqliteInitialized()
    {
        if (Interlocked.Exchange(ref sqliteInitialized, 1) != 0)
            return;

        // Omega ships the e_sqlite3 native runtime with the plugin package. This avoids depending on
        // the host Windows installation for winsqlite3.dll and also works when FFXIV/Dalamud runs
        // through Wine/Proton. The bundle owns provider initialization for this packaged runtime.
        SQLitePCL.Batteries_V2.Init();
    }

    private static SqliteConnection OpenReadOnly(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Omega catalog database does not exist.", path);
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString());
        connection.Open();
        return connection;
    }

    private static void ValidateConnection(SqliteConnection connection)
    {
        var schemaVersion = ReadMeta(connection, "schema_version");
        var schemaName = ReadMeta(connection, "schema_name");
        if (!int.TryParse(schemaVersion, out var parsed) || parsed != SchemaVersion ||
            !schemaName.Equals(SchemaName, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Unsupported Omega SQLite catalog schema.");
        }

        var databaseRole = ReadMeta(connection, "database_role");
        if (!string.IsNullOrWhiteSpace(databaseRole) && !databaseRole.Equals("marketplace", StringComparison.Ordinal))
            throw new InvalidDataException("Omega refuses a SQLite database that is not a marketplace projection.");
        if (ReadMeta(connection, "detailed_security_evidence_included").Equals("1", StringComparison.Ordinal))
            throw new InvalidDataException("Omega refuses SQLite databases that contain detailed server-side security evidence.");

        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA integrity_check;";
        var result = command.ExecuteScalar()?.ToString();
        if (!string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"Omega SQLite catalog failed integrity_check: {result ?? "no result"}.");

        using var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM runtime_plugin_variants;";
        if (Convert.ToInt64(count.ExecuteScalar() ?? 0L) <= 0)
            throw new InvalidDataException("Omega SQLite catalog contains no active plugin variants.");
    }

    private static void ValidateRuntimeSnapshot(SqliteConnection candidate)
    {
        // Validate the client read model without eagerly retaining verbose historical/evidence text.
        _ = ReadVariants(candidate, includeDetails: false);
        _ = ReadSourceDefinitions(candidate);
        _ = ReadGeneratedAt(candidate);
        _ = ReadMeta(candidate, "catalog_revision");
        _ = ReadMeta(candidate, "definitions_revision");
        _ = ReadMeta(candidate, "security_revision");
        _ = ReadMeta(candidate, "evidence_revision");
        _ = ReadRevisionUpdatedAt(candidate);
        _ = ReadChangelogEntryCount(candidate);
    }

    private static IReadOnlyList<MarketplacePlugin> ReadVariants(
        SqliteConnection connection,
        bool includeDetails,
        string? internalName = null)
    {
        var runtimeColumns = RuntimeViewColumns(connection);
        var hasSecurityProjection = runtimeColumns.Contains("security_status");
        var authorsProjection = runtimeColumns.Contains("authors_json")
            ? "authors_json"
            : "'[]' AS authors_json";
        var websiteReadmeProjection = runtimeColumns.Contains("website_readme_excerpt")
            ? "website_readme_excerpt"
            : "'' AS website_readme_excerpt";
        var websiteLinksProjection = runtimeColumns.Contains("website_links_json")
            ? "website_links_json"
            : "'[]' AS website_links_json";
        var omegaBannerProjection = runtimeColumns.Contains("omega_banner_url")
            ? "omega_banner_url"
            : "'' AS omega_banner_url";
        var adultContentProjection = runtimeColumns.Contains("plugin_nsfw")
            ? "plugin_nsfw"
            : "0 AS plugin_nsfw";
        var catalogPluginIdProjection = runtimeColumns.Contains("plugin_id")
            ? "plugin_id"
            : "0 AS plugin_id";
        var catalogVariantIdProjection = runtimeColumns.Contains("variant_id")
            ? "variant_id"
            : "0 AS variant_id";
        var automationLevelProjection = runtimeColumns.Contains("security_automation_level")
            ? "security_automation_level"
            : "'none' AS security_automation_level";
        var automationCapabilitiesProjection = runtimeColumns.Contains("security_automation_capabilities_json")
            ? "security_automation_capabilities_json"
            : "'[]' AS security_automation_capabilities_json";
        var dependenciesProjection = runtimeColumns.Contains("security_dependencies_json")
            ? "security_dependencies_json"
            : "'[]' AS security_dependencies_json";
        var dependencyTotalProjection = runtimeColumns.Contains("security_dependency_total_count")
            ? "security_dependency_total_count"
            : "0 AS security_dependency_total_count";
        var knownAdvisoryCountProjection = runtimeColumns.Contains("security_known_advisory_count")
            ? "security_known_advisory_count"
            : "0 AS security_known_advisory_count";
        var knownAdvisorySeverityProjection = runtimeColumns.Contains("security_known_advisory_highest_severity")
            ? "security_known_advisory_highest_severity"
            : "'none' AS security_known_advisory_highest_severity";
        var riskScoreProjection = runtimeColumns.Contains("security_risk_score")
            ? "security_risk_score"
            : "0 AS security_risk_score";
        var sourceAttributionConfidenceProjection = runtimeColumns.Contains("security_source_attribution_confidence")
            ? "security_source_attribution_confidence"
            : "0 AS security_source_attribution_confidence";
        var sourceAttributionBasisProjection = runtimeColumns.Contains("security_source_attribution_basis_json")
            ? "security_source_attribution_basis_json"
            : "'[]' AS security_source_attribution_basis_json";
        var reviewCoverageLabelProjection = runtimeColumns.Contains("security_review_coverage_label")
            ? "security_review_coverage_label"
            : "'Unresolved' AS security_review_coverage_label";
        var websiteLicenseProjection = runtimeColumns.Contains("website_license")
            ? "website_license"
            : "'' AS website_license";
        var securityProjection = hasSecurityProjection
            ? $"""
                   security_status,security_scanned_at_utc,security_artifact_sha256,security_scanner_version,
                   security_highest_severity,security_informational_count,security_caution_count,security_high_count,
                   security_critical_count,security_capabilities_json,{automationLevelProjection},{automationCapabilitiesProjection},
                   security_findings_json,{dependenciesProjection},{dependencyTotalProjection},{knownAdvisoryCountProjection},
                   {knownAdvisorySeverityProjection},{riskScoreProjection},security_source_available,
                   security_source_repository,security_source_commit,security_source_to_binary_verified,security_error
              """
            : """
                   '' AS security_status,'' AS security_scanned_at_utc,'' AS security_artifact_sha256,'' AS security_scanner_version,
                   'none' AS security_highest_severity,0 AS security_informational_count,0 AS security_caution_count,0 AS security_high_count,
                   0 AS security_critical_count,'[]' AS security_capabilities_json,'none' AS security_automation_level,
                   '[]' AS security_automation_capabilities_json,'[]' AS security_findings_json,'[]' AS security_dependencies_json,
                   0 AS security_dependency_total_count,0 AS security_known_advisory_count,'none' AS security_known_advisory_highest_severity,
                   0 AS security_risk_score,0 AS security_source_available,
                   '' AS security_source_repository,'' AS security_source_commit,0 AS security_source_to_binary_verified,'' AS security_error
              """;

        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT internal_name,author,name,punchline,description,changelog,assembly_version,
                   testing_assembly_version,dalamud_api_level,testing_dalamud_api_level,
                   applicable_version,minimum_dalamud_version,repo_url,download_link_install,
                   download_link_update,download_link_testing,icon_url,image_urls_json,tags_json,
                   category_tags_json,download_count,last_update,is_hide,is_testing_exclusive,
                   dip17_channel,source_name,source_url,source_is_official,website_url,website_title,
                   website_description,{websiteReadmeProjection},website_image_urls_json,website_enriched,{adultContentProjection},
                   {securityProjection},
                   {authorsProjection},{websiteLinksProjection},{omegaBannerProjection},{catalogPluginIdProjection},
                   {sourceAttributionConfidenceProjection},{sourceAttributionBasisProjection},{reviewCoverageLabelProjection},
                   {websiteLicenseProjection},{catalogVariantIdProjection}
              FROM runtime_plugin_variants
             WHERE ($internalName='' OR internal_name COLLATE NOCASE=$internalName);
            """;
        command.Parameters.AddWithValue(
            "$internalName",
            string.IsNullOrWhiteSpace(internalName) ? string.Empty : internalName.Trim());
        using var reader = command.ExecuteReader();
        var result = new List<MarketplacePlugin>();
        while (reader.Read())
        {
            result.Add(new MarketplacePlugin
            {
                InternalName = GetString(reader, 0),
                Author = GetString(reader, 1),
                Name = GetString(reader, 2),
                Punchline = GetString(reader, 3),
                Description = GetString(reader, 4),
                Changelog = GetString(reader, 5),
                AssemblyVersionText = GetString(reader, 6, "0.0.0.0"),
                TestingAssemblyVersionText = GetNullableString(reader, 7),
                DalamudApiLevel = GetInt(reader, 8),
                TestingDalamudApiLevel = GetNullableInt(reader, 9),
                ApplicableVersion = GetString(reader, 10, "any"),
                MinimumDalamudVersionText = GetNullableString(reader, 11),
                RepoUrl = GetString(reader, 12),
                DownloadLinkInstall = GetString(reader, 13),
                DownloadLinkUpdate = GetString(reader, 14),
                DownloadLinkTesting = GetString(reader, 15),
                IconUrl = GetString(reader, 16),
                ImageUrls = ReadStrings(GetString(reader, 17, "[]")),
                Tags = ReadStrings(GetString(reader, 18, "[]")),
                CategoryTags = ReadStrings(GetString(reader, 19, "[]")),
                DownloadCount = GetLong(reader, 20),
                LastUpdate = GetLong(reader, 21),
                IsHide = GetBool(reader, 22),
                IsTestingExclusive = GetBool(reader, 23),
                Dip17Channel = GetString(reader, 24),
                SourceName = GetString(reader, 25),
                SourceUrl = GetString(reader, 26),
                SourceIsOfficial = GetBool(reader, 27),
                OmegaWebsiteUrl = GetString(reader, 28),
                OmegaWebsiteTitle = GetString(reader, 29),
                OmegaWebsiteDescription = GetString(reader, 30),
                OmegaWebsiteReadmeExcerpt = includeDetails ? GetString(reader, 31) : string.Empty,
                OmegaWebsiteImageUrls = ReadStrings(GetString(reader, 32, "[]")),
                OmegaEnriched = GetBool(reader, 33),
                OmegaIsAdultContent = GetBool(reader, 34),
                SecurityStatus = GetString(reader, 35),
                SecurityScannedAtUtcText = GetString(reader, 36),
                SecurityArtifactSha256 = GetString(reader, 37),
                SigmascopeVersion = GetString(reader, 38),
                SecurityHighestSeverity = GetString(reader, 39, "none"),
                SecurityInformationalCount = GetInt(reader, 40),
                SecurityCautionCount = GetInt(reader, 41),
                SecurityHighCount = GetInt(reader, 42),
                SecurityCriticalCount = GetInt(reader, 43),
                SecurityCapabilities = ReadStrings(GetString(reader, 44, "[]")),
                SecurityAutomationLevel = GetString(reader, 45, "none"),
                SecurityAutomationCapabilities = ReadAutomationCapabilities(GetString(reader, 46, "[]")),
                SecurityFindings = includeDetails
                    ? ReadSecurityFindings(GetString(reader, 47, "[]"))
                    : ReadSecurityFindingSummaries(GetString(reader, 47, "[]")),
                SecurityDependencies = ReadDependencies(GetString(reader, 48, "[]")),
                SecurityDependencyTotalCount = GetInt(reader, 49),
                SecurityKnownAdvisoryCount = GetInt(reader, 50),
                SecurityKnownAdvisoryHighestSeverity = GetString(reader, 51, "none"),
                SecurityRiskScore = GetInt(reader, 52),
                SecuritySourceAvailable = GetBool(reader, 53),
                SecuritySourceRepository = GetString(reader, 54),
                SecuritySourceCommit = GetString(reader, 55),
                SecuritySourceToBinaryVerified = GetBool(reader, 56),
                SecurityError = GetString(reader, 57),
                Authors = ReadStrings(GetString(reader, 58, "[]")),
                OmegaProjectLinks = includeDetails ? ReadProjectLinks(GetString(reader, 59, "[]")) : [],
                OmegaBannerUrl = GetString(reader, 60),
                CatalogPluginId = GetLong(reader, 61),
                SecuritySourceAttributionConfidence = GetInt(reader, 62),
                SecuritySourceAttributionBasis = includeDetails ? ReadStrings(GetString(reader, 63, "[]")) : [],
                SecurityReviewCoverageLabel = GetString(reader, 64, "Unresolved"),
                OmegaWebsiteLicense = GetString(reader, 65),
                CatalogVariantId = GetLong(reader, 66),
            });
        }
        return result;
    }

    private static HashSet<string> RuntimeViewColumns(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA table_info(runtime_plugin_variants);";
        using var reader = command.ExecuteReader();
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (reader.Read())
            columns.Add(reader.GetString(1));
        return columns;
    }


    private static IReadOnlyList<MarketplaceChangelogEntry> ReadPluginChangelogHistory(
        SqliteConnection connection,
        string internalName)
    {
        using var exists = connection.CreateCommand();
        exists.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='plugin_variants';";
        if (Convert.ToInt64(exists.ExecuteScalar() ?? 0L) == 0)
            return [];

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT p.internal_name,s.name,s.url,v.assembly_version,v.last_update,v.changelog,v.active,v.last_seen_utc
              FROM plugin_variants v
              JOIN plugins p ON p.plugin_id=v.plugin_id
              JOIN sources s ON s.source_id=v.source_id
             WHERE p.internal_name=$internalName COLLATE NOCASE
               AND TRIM(v.changelog)<>''
             ORDER BY CASE WHEN v.last_update>0 THEN 0 ELSE 1 END,
                      v.last_update DESC,v.last_seen_utc DESC,v.assembly_version DESC
             LIMIT 96;
            """;
        command.Parameters.AddWithValue("$internalName", internalName);
        using var reader = command.ExecuteReader();
        var result = new List<MarketplaceChangelogEntry>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read() && result.Count < 32)
        {
            var changelog = GetString(reader, 5).Trim();
            var key = $"{GetString(reader, 2).TrimEnd('/')}\u001f{GetString(reader, 3)}\u001f{changelog}";
            if (!seen.Add(key))
                continue;

            result.Add(new MarketplaceChangelogEntry(
                GetString(reader, 0),
                GetString(reader, 1),
                GetString(reader, 2),
                GetString(reader, 3),
                GetLong(reader, 4),
                changelog,
                GetBool(reader, 6)));
        }

        return result;
    }

    private static IReadOnlyList<CuratedSourceDefinition> ReadSourceDefinitions(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT source_id,curated_id,name,url,description,is_official,enabled_by_default,integrate_with_dalamud
              FROM sources
             WHERE url<>''
             ORDER BY is_official DESC,name COLLATE NOCASE,url COLLATE NOCASE;
            """;
        using var reader = command.ExecuteReader();
        var result = new List<CuratedSourceDefinition>();
        while (reader.Read())
        {
            var id = GetString(reader, 1);
            if (string.IsNullOrWhiteSpace(id))
                id = $"catalog-source-{reader.GetInt64(0)}";
            result.Add(new CuratedSourceDefinition
            {
                Id = id,
                Name = GetString(reader, 2, GetString(reader, 3)),
                Url = GetString(reader, 3),
                Description = GetString(reader, 4),
                IsOfficial = GetBool(reader, 5),
                EnabledByDefault = GetBool(reader, 6),
                IntegrateWithDalamudByDefault = GetBool(reader, 7),
            });
        }
        return result;
    }

    private static DateTimeOffset? ReadGeneratedAt(SqliteConnection connection)
        => DateTimeOffset.TryParse(ReadMeta(connection, "generated_at_utc"), out var parsed) ? parsed : null;

    private static DateTimeOffset? ReadRevisionUpdatedAt(SqliteConnection connection)
    {
        foreach (var key in new[] { "catalog_revision_updated_at_utc", "security_revision_updated_at_utc" })
        {
            if (DateTimeOffset.TryParse(ReadMeta(connection, key), out var parsed))
                return parsed;
        }
        return null;
    }

    private static int ReadChangelogEntryCount(SqliteConnection connection)
    {
        using var exists = connection.CreateCommand();
        exists.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='catalog_changelog';";
        if (Convert.ToInt32(exists.ExecuteScalar() ?? 0) == 0)
            return 0;

        using var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM catalog_changelog;";
        return Convert.ToInt32(count.ExecuteScalar() ?? 0);
    }

    private static string ReadMeta(SqliteConnection connection, string key)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT value FROM catalog_meta WHERE key=$key LIMIT 1;";
        command.Parameters.AddWithValue("$key", key);
        return command.ExecuteScalar()?.ToString() ?? string.Empty;
    }

    private static T WithDisposableDatabaseCopy<T>(string sourcePath, Func<string, T> action)
    {
        if (!File.Exists(sourcePath))
            throw new FileNotFoundException("Omega catalog database does not exist.", sourcePath);

        var copyPath = Path.Combine(Path.GetTempPath(), $"omega-catalog.read-{Guid.NewGuid():N}.sqlite");
        File.Copy(sourcePath, copyPath, overwrite: false);
        try
        {
            return action(copyPath);
        }
        finally
        {
            // Pooling is disabled, but clearing pools also protects against future provider changes.
            SqliteConnection.ClearAllPools();
            TryDelete(copyPath);
        }
    }

    private static void TryDelete(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;

        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                if (!File.Exists(path))
                    return;
                File.Delete(path);
                return;
            }
            catch (IOException) when (attempt < 4)
            {
                Thread.Sleep(20);
            }
            catch (UnauthorizedAccessException) when (attempt < 4)
            {
                Thread.Sleep(20);
            }
            catch
            {
                return;
            }
        }
    }

    private static void ExtractDatabase(string zipPath, string destination)
    {
        using var archive = ZipFile.OpenRead(zipPath);
        var entries = archive.Entries
            .Where(x => Path.GetFileName(x.FullName).Equals(DatabaseFileName, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (entries.Length != 1)
            throw new InvalidDataException($"Omega catalog bundle must contain exactly one {DatabaseFileName} file.");
        if (entries[0].Length <= 0 || entries[0].Length > 128L * 1024 * 1024)
            throw new InvalidDataException("Omega SQLite database has an invalid size.");

        using var source = entries[0].Open();
        using var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        source.CopyTo(target);
    }

    private static IReadOnlyList<string> ReadStrings(string json)
    {
        try
        {
            var values = JsonSerializer.Deserialize<List<string>>(json);
            return values?.Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() ?? [];
        }
        catch
        {
            return [];
        }
    }

    private static IReadOnlyList<MarketplaceSecurityFinding> ReadSecurityFindings(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<List<MarketplaceSecurityFinding>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            }) ?? [];
        }
        catch
        {
            return [];
        }
    }


    private static IReadOnlyList<MarketplaceSecurityFinding> ReadSecurityFindingSummaries(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "[]" : json);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
                return [];

            return document.RootElement.EnumerateArray()
                .Where(x => x.ValueKind == JsonValueKind.Object)
                .Select(x => new MarketplaceSecurityFinding
                {
                    RuleId = ReadJsonString(x, "ruleId"),
                    Severity = ReadJsonString(x, "severity"),
                    Category = ReadJsonString(x, "category"),
                    Title = ReadJsonString(x, "title"),
                })
                .Where(x => !string.IsNullOrWhiteSpace(x.RuleId) || !string.IsNullOrWhiteSpace(x.Title))
                .ToArray();
        }
        catch
        {
            return [];
        }
    }

    private static IReadOnlyList<MarketplaceProjectLink> ReadProjectLinks(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "[]" : json);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
                return [];
            return document.RootElement.EnumerateArray()
                .Where(x => x.ValueKind == JsonValueKind.Object)
                .Select(x => new MarketplaceProjectLink(
                    ReadJsonString(x, "kind"),
                    ReadJsonString(x, "label"),
                    ReadJsonString(x, "url")))
                .Where(x => !string.IsNullOrWhiteSpace(x.Kind) && !string.IsNullOrWhiteSpace(x.Url))
                .Take(8)
                .ToArray();
        }
        catch
        {
            return [];
        }
    }

    private static string ReadJsonString(JsonElement element, string name)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.String)
                return property.Value.GetString() ?? string.Empty;
        }
        return string.Empty;
    }

    private static IReadOnlyList<MarketplaceAutomationCapability> ReadAutomationCapabilities(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<List<MarketplaceAutomationCapability>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            }) ?? [];
        }
        catch
        {
            return [];
        }
    }

    private static IReadOnlyList<MarketplaceDependency> ReadDependencies(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<List<MarketplaceDependency>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            }) ?? [];
        }
        catch
        {
            return [];
        }
    }

    private static string GetString(SqliteDataReader reader, int ordinal, string fallback = "")
        => reader.IsDBNull(ordinal) ? fallback : reader.GetString(ordinal);
    private static string? GetNullableString(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    private static int GetInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : Convert.ToInt32(reader.GetValue(ordinal));
    private static int? GetNullableInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? null : Convert.ToInt32(reader.GetValue(ordinal));
    private static long GetLong(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0L : Convert.ToInt64(reader.GetValue(ordinal));
    private static bool GetBool(SqliteDataReader reader, int ordinal)
        => !reader.IsDBNull(ordinal) && Convert.ToInt32(reader.GetValue(ordinal)) != 0;
}

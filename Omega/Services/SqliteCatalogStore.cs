using System.IO.Compression;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Dalagab.Omega;

internal sealed record SqliteCatalogSnapshot(
    IReadOnlyList<MarketplacePlugin> Variants,
    IReadOnlyList<CuratedSourceDefinition> SourceDefinitions,
    DateTimeOffset? GeneratedAtUtc,
    string CatalogRevision,
    string SecurityRevision,
    string EvidenceRevision,
    DateTimeOffset? RevisionUpdatedAtUtc,
    int ChangelogEntryCount,
    IReadOnlyDictionary<string, IReadOnlyList<MarketplaceChangelogEntry>> PluginChangelogHistory);

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
                    ReadVariants(connection),
                    ReadSourceDefinitions(connection),
                    ReadGeneratedAt(connection),
                    ReadMeta(connection, "catalog_revision"),
                    ReadMeta(connection, "security_revision"),
                    ReadMeta(connection, "evidence_revision"),
                    ReadRevisionUpdatedAt(connection),
                    ReadChangelogEntryCount(connection),
                    ReadPluginChangelogHistory(connection));
            });
        }
    }

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
        _ = ReadVariants(candidate);
        _ = ReadSourceDefinitions(candidate);
        _ = ReadGeneratedAt(candidate);
        _ = ReadMeta(candidate, "catalog_revision");
        _ = ReadMeta(candidate, "security_revision");
        _ = ReadMeta(candidate, "evidence_revision");
        _ = ReadRevisionUpdatedAt(candidate);
        _ = ReadChangelogEntryCount(candidate);
        _ = ReadPluginChangelogHistory(candidate);
    }

    private static IReadOnlyList<MarketplacePlugin> ReadVariants(SqliteConnection connection)
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
                   {authorsProjection},{websiteLinksProjection},{omegaBannerProjection}
              FROM runtime_plugin_variants;
            """;
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
                OmegaWebsiteReadmeExcerpt = GetString(reader, 31),
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
                SecurityFindings = ReadSecurityFindings(GetString(reader, 47, "[]")),
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
                OmegaProjectLinks = ReadProjectLinks(GetString(reader, 59, "[]")),
                OmegaBannerUrl = GetString(reader, 60),
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


    private static IReadOnlyDictionary<string, IReadOnlyList<MarketplaceChangelogEntry>> ReadPluginChangelogHistory(SqliteConnection connection)
    {
        using var exists = connection.CreateCommand();
        exists.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='plugin_variants';";
        if (Convert.ToInt64(exists.ExecuteScalar() ?? 0L) == 0)
            return new Dictionary<string, IReadOnlyList<MarketplaceChangelogEntry>>(StringComparer.OrdinalIgnoreCase);

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT p.internal_name,s.name,s.url,v.assembly_version,v.last_update,v.changelog,v.active,v.last_seen_utc
              FROM plugin_variants v
              JOIN plugins p ON p.plugin_id=v.plugin_id
              JOIN sources s ON s.source_id=v.source_id
             WHERE TRIM(v.changelog)<>''
             ORDER BY p.internal_name COLLATE NOCASE,
                      CASE WHEN v.last_update>0 THEN 0 ELSE 1 END,
                      v.last_update DESC,v.last_seen_utc DESC,v.assembly_version DESC;
            """;
        using var reader = command.ExecuteReader();
        var mutable = new Dictionary<string, List<MarketplaceChangelogEntry>>(StringComparer.OrdinalIgnoreCase);
        var seen = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        while (reader.Read())
        {
            var internalName = GetString(reader, 0);
            if (string.IsNullOrWhiteSpace(internalName))
                continue;
            if (!mutable.TryGetValue(internalName, out var entries))
            {
                entries = [];
                mutable[internalName] = entries;
                seen[internalName] = new HashSet<string>(StringComparer.Ordinal);
            }
            if (entries.Count >= 32)
                continue;

            var changelog = GetString(reader, 5).Trim();
            var key = $"{GetString(reader, 2).TrimEnd('/')}\u001f{GetString(reader, 3)}\u001f{changelog}";
            if (!seen[internalName].Add(key))
                continue;
            entries.Add(new MarketplaceChangelogEntry(
                internalName,
                GetString(reader, 1),
                GetString(reader, 2),
                GetString(reader, 3),
                GetLong(reader, 4),
                changelog,
                GetBool(reader, 6)));
        }

        return mutable.ToDictionary(
            pair => pair.Key,
            pair => (IReadOnlyList<MarketplaceChangelogEntry>)pair.Value,
            StringComparer.OrdinalIgnoreCase);
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

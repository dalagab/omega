using System.IO.Compression;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Dalagab.Omega;

internal sealed record SqliteCatalogSnapshot(
    IReadOnlyList<MarketplacePlugin> Variants,
    IReadOnlyList<CuratedSourceDefinition> SourceDefinitions,
    DateTimeOffset? GeneratedAtUtc);

/// <summary>
/// Owns Omega's single production catalog database. JSON is never a runtime catalog format:
/// the client validates and reads one SQLite file, and online updates atomically replace it.
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
            using var connection = OpenReadOnly(DatabasePath);
            ValidateConnection(connection);
            return new SqliteCatalogSnapshot(
                ReadVariants(connection),
                ReadSourceDefinitions(connection),
                ReadGeneratedAt(connection));
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
            using (var candidate = OpenReadOnly(staged))
                ValidateConnection(candidate);

            lock (sync)
            {
                var hadExisting = File.Exists(DatabasePath);
                try
                {
                    if (hadExisting)
                        File.Move(DatabasePath, backup, overwrite: true);
                    File.Move(staged, DatabasePath, overwrite: true);
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
            try { File.Delete(staged); } catch { }
            try { File.Delete(backup); } catch { }
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
        using var connection = OpenReadOnly(path);
        ValidateConnection(connection);
    }

    private static void EnsureSqliteInitialized()
    {
        if (Interlocked.Exchange(ref sqliteInitialized, 1) != 0)
            return;

        // FFXIV/Dalamud is a Windows application. Using the Windows-provided SQLite library avoids
        // shipping an unmanaged database DLL inside the plugin package.
        SQLitePCL.raw.SetProvider(new SQLitePCL.SQLite3Provider_winsqlite3());
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

    private static IReadOnlyList<MarketplacePlugin> ReadVariants(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT internal_name,author,name,punchline,description,changelog,assembly_version,
                   testing_assembly_version,dalamud_api_level,testing_dalamud_api_level,
                   applicable_version,minimum_dalamud_version,repo_url,download_link_install,
                   download_link_update,download_link_testing,icon_url,image_urls_json,tags_json,
                   category_tags_json,download_count,last_update,is_hide,is_testing_exclusive,
                   dip17_channel,source_name,source_url,source_is_official,website_url,website_title,
                   website_description,website_image_urls_json,website_enriched
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
                OmegaWebsiteImageUrls = ReadStrings(GetString(reader, 31, "[]")),
                OmegaEnriched = GetBool(reader, 32),
            });
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

    private static string ReadMeta(SqliteConnection connection, string key)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT value FROM catalog_meta WHERE key=$key LIMIT 1;";
        command.Parameters.AddWithValue("$key", key);
        return command.ExecuteScalar()?.ToString() ?? string.Empty;
    }

    private static void ExtractDatabase(string zipPath, string destination)
    {
        using var archive = ZipFile.OpenRead(zipPath);
        var entries = archive.Entries
            .Where(x => Path.GetFileName(x.FullName).Equals(DatabaseFileName, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (entries.Length != 1)
            throw new InvalidDataException($"Omega catalog bundle must contain exactly one {DatabaseFileName} file.");
        if (entries[0].Length <= 0 || entries[0].Length > 256L * 1024 * 1024)
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

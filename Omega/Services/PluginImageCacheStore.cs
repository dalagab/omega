using Microsoft.Data.Sqlite;

namespace Dalagab.Omega;

internal sealed record CachedMarketplaceImage(
    byte[] Bytes,
    string ContentType,
    string ETag,
    string LastModified,
    DateTimeOffset LastCheckedAtUtc)
{
    public bool NeedsRefresh(DateTimeOffset now, TimeSpan maxAge)
        => LastCheckedAtUtc == default || now - LastCheckedAtUtc >= maxAge;
}

/// <summary>
/// Persistent local cache for already-compressed marketplace artwork. The production marketplace
/// database stays small; icons/screenshots are cached in a separate SQLite file after first use and
/// survive Omega restarts. The cache is bounded and evicts least-recently-used entries.
/// </summary>
internal sealed class PluginImageCacheStore : IDisposable
{
    internal const string DatabaseFileName = "omega-image-cache.sqlite";
    internal const long MaximumCacheBytes = 256L * 1024L * 1024L;
    internal const int MaximumEntryCount = 4096;
    private const long PruneTargetBytes = 224L * 1024L * 1024L;
    private const int PruneTargetEntryCount = 3584;

    private readonly object sync = new();

    public PluginImageCacheStore(string databasePath)
    {
        DatabasePath = databasePath;
        Directory.CreateDirectory(Path.GetDirectoryName(databasePath) ?? ".");
        SqliteCatalogStore.EnsureSqliteInitialized();
        Initialize();
    }

    public string DatabasePath { get; }

    public CachedMarketplaceImage? TryRead(string url)
    {
        lock (sync)
        {
            if (!File.Exists(DatabasePath))
                return null;

            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT content,content_type,etag,last_modified,last_checked_utc
                  FROM image_cache
                 WHERE url=$url COLLATE NOCASE;
                """;
            command.Parameters.AddWithValue("$url", url);
            using var reader = command.ExecuteReader();
            if (!reader.Read())
                return null;

            var bytes = (byte[])reader[0];
            if (bytes.Length == 0)
                return null;

            var result = new CachedMarketplaceImage(
                bytes,
                reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
                reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
                ParseUtc(reader.IsDBNull(4) ? string.Empty : reader.GetString(4)));
            reader.Close();

            using var touch = connection.CreateCommand();
            touch.CommandText = "UPDATE image_cache SET last_access_utc=$access WHERE url=$url COLLATE NOCASE;";
            touch.Parameters.AddWithValue("$access", UtcNow());
            touch.Parameters.AddWithValue("$url", url);
            touch.ExecuteNonQuery();
            return result;
        }
    }

    public void Put(
        string url,
        byte[] bytes,
        string? contentType,
        string? etag,
        string? lastModified)
    {
        if (bytes.Length == 0)
            return;

        lock (sync)
        {
            using var connection = Open();
            var now = UtcNow();
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO image_cache(
                    url,content,content_type,etag,last_modified,byte_count,stored_at_utc,last_checked_utc,last_access_utc)
                VALUES($url,$content,$type,$etag,$modified,$bytes,$stored,$checked,$access)
                ON CONFLICT(url) DO UPDATE SET
                    content=excluded.content,
                    content_type=excluded.content_type,
                    etag=excluded.etag,
                    last_modified=excluded.last_modified,
                    byte_count=excluded.byte_count,
                    stored_at_utc=excluded.stored_at_utc,
                    last_checked_utc=excluded.last_checked_utc,
                    last_access_utc=excluded.last_access_utc;
                """;
            command.Parameters.AddWithValue("$url", url);
            command.Parameters.AddWithValue("$content", bytes);
            command.Parameters.AddWithValue("$type", contentType ?? string.Empty);
            command.Parameters.AddWithValue("$etag", etag ?? string.Empty);
            command.Parameters.AddWithValue("$modified", lastModified ?? string.Empty);
            command.Parameters.AddWithValue("$bytes", bytes.LongLength);
            command.Parameters.AddWithValue("$stored", now);
            command.Parameters.AddWithValue("$checked", now);
            command.Parameters.AddWithValue("$access", now);
            command.ExecuteNonQuery();
            PruneIfNeeded(connection);
        }
    }

    public void MarkChecked(string url, string? etag = null, string? lastModified = null)
    {
        lock (sync)
        {
            if (!File.Exists(DatabasePath))
                return;
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                UPDATE image_cache
                   SET last_checked_utc=$checked,
                       last_access_utc=$access,
                       etag=CASE WHEN $etagTest<>'' THEN $etag ELSE etag END,
                       last_modified=CASE WHEN $modifiedTest<>'' THEN $modified ELSE last_modified END
                 WHERE url=$url COLLATE NOCASE;
                """;
            var now = UtcNow();
            command.Parameters.AddWithValue("$checked", now);
            command.Parameters.AddWithValue("$access", now);
            command.Parameters.AddWithValue("$etagTest", etag ?? string.Empty);
            command.Parameters.AddWithValue("$etag", etag ?? string.Empty);
            command.Parameters.AddWithValue("$modifiedTest", lastModified ?? string.Empty);
            command.Parameters.AddWithValue("$modified", lastModified ?? string.Empty);
            command.Parameters.AddWithValue("$url", url);
            command.ExecuteNonQuery();
        }
    }

    public void Remove(string url)
    {
        lock (sync)
        {
            if (!File.Exists(DatabasePath))
                return;
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM image_cache WHERE url=$url COLLATE NOCASE;";
            command.Parameters.AddWithValue("$url", url);
            command.ExecuteNonQuery();
        }
    }

    internal (long Bytes, int Entries) GetStatistics()
    {
        lock (sync)
        {
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT COALESCE(SUM(byte_count),0),COUNT(*) FROM image_cache;";
            using var reader = command.ExecuteReader();
            if (!reader.Read())
                return (0, 0);
            return (reader.GetInt64(0), checked((int)reader.GetInt64(1)));
        }
    }

    internal void Clear()
    {
        lock (sync)
        {
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM image_cache;";
            command.ExecuteNonQuery();
            using var vacuum = connection.CreateCommand();
            vacuum.CommandText = "VACUUM;";
            vacuum.ExecuteNonQuery();
        }
    }

    public void Dispose()
    {
        // Connections are intentionally short-lived so the cache file can be inspected or removed
        // while Omega is not actively performing a cache operation.
    }

    private void Initialize()
    {
        lock (sync)
        {
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                PRAGMA journal_mode=DELETE;
                PRAGMA synchronous=NORMAL;
                PRAGMA auto_vacuum=INCREMENTAL;
                CREATE TABLE IF NOT EXISTS image_cache (
                    url TEXT PRIMARY KEY COLLATE NOCASE,
                    content BLOB NOT NULL,
                    content_type TEXT NOT NULL DEFAULT '',
                    etag TEXT NOT NULL DEFAULT '',
                    last_modified TEXT NOT NULL DEFAULT '',
                    byte_count INTEGER NOT NULL,
                    stored_at_utc TEXT NOT NULL,
                    last_checked_utc TEXT NOT NULL,
                    last_access_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_image_cache_access ON image_cache(last_access_utc);
                """;
            command.ExecuteNonQuery();
            PruneIfNeeded(connection);
        }
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString());
        connection.Open();
        return connection;
    }

    private static void PruneIfNeeded(SqliteConnection connection)
    {
        using var totals = connection.CreateCommand();
        totals.CommandText = "SELECT COALESCE(SUM(byte_count),0),COUNT(*) FROM image_cache;";
        using var reader = totals.ExecuteReader();
        if (!reader.Read())
            return;
        var bytes = reader.GetInt64(0);
        var entries = checked((int)reader.GetInt64(1));
        reader.Close();
        if (bytes <= MaximumCacheBytes && entries <= MaximumEntryCount)
            return;

        using var candidates = connection.CreateCommand();
        candidates.CommandText = "SELECT url,byte_count FROM image_cache ORDER BY last_access_utc ASC;";
        using var rows = candidates.ExecuteReader();
        var remove = new List<string>();
        while (rows.Read() && (bytes > PruneTargetBytes || entries > PruneTargetEntryCount))
        {
            remove.Add(rows.GetString(0));
            bytes -= rows.GetInt64(1);
            entries--;
        }
        rows.Close();

        using var transaction = connection.BeginTransaction();
        foreach (var url in remove)
        {
            using var delete = connection.CreateCommand();
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM image_cache WHERE url=$url COLLATE NOCASE;";
            delete.Parameters.AddWithValue("$url", url);
            delete.ExecuteNonQuery();
        }
        transaction.Commit();

        using var reclaim = connection.CreateCommand();
        reclaim.CommandText = "PRAGMA incremental_vacuum(256);";
        reclaim.ExecuteNonQuery();
    }

    private static string UtcNow()
        => DateTimeOffset.UtcNow.ToString("O");

    private static DateTimeOffset ParseUtc(string value)
        => DateTimeOffset.TryParse(value, out var parsed) ? parsed : default;
}

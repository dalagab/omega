using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Dalagab.Omega;

internal sealed class CatalogDatabaseRecord
{
    public int SchemaVersion { get; set; } = 1;
    public string Url { get; set; } = string.Empty;
    public string ETag { get; set; } = string.Empty;
    public string LastModified { get; set; } = string.Empty;
    public string ContentSha256 { get; set; } = string.Empty;
    public DateTimeOffset FetchedAtUtc { get; set; }
    public DateTimeOffset CheckedAtUtc { get; set; }
    public string ManifestJson { get; set; } = string.Empty;
}

/// <summary>
/// Durable, dependency-free repository catalog database. Each source is stored independently so
/// checking one plugin/source never rewrites the full marketplace catalog. A verified central
/// bundle may atomically replace the curated portion while preserving user-added repository records.
/// </summary>
internal sealed class CatalogDatabase
{
    private readonly string directory;
    private readonly object sync = new();
    private readonly JsonSerializerOptions jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public CatalogDatabase(string directory)
    {
        this.directory = directory;
        Directory.CreateDirectory(directory);
    }

    public string DirectoryPath => directory;

    public CatalogDatabaseRecord? TryRead(string url)
    {
        var normalized = NormalizeUrl(url);
        var path = PathFor(normalized);
        lock (sync)
        {
            try
            {
                if (!File.Exists(path))
                    return null;

                var record = JsonSerializer.Deserialize<CatalogDatabaseRecord>(File.ReadAllText(path), jsonOptions);
                return TryValidateRecord(record, normalized, out var validated) ? validated : null;
            }
            catch
            {
                return null;
            }
        }
    }

    public CatalogDatabaseRecord Store(
        string url,
        string manifestJson,
        string? etag,
        string? lastModified,
        DateTimeOffset checkedAtUtc)
    {
        var record = new CatalogDatabaseRecord
        {
            SchemaVersion = 1,
            Url = NormalizeUrl(url),
            ETag = etag ?? string.Empty,
            LastModified = lastModified ?? string.Empty,
            ContentSha256 = HashText(manifestJson),
            FetchedAtUtc = checkedAtUtc,
            CheckedAtUtc = checkedAtUtc,
            ManifestJson = manifestJson,
        };
        Write(record);
        return record;
    }

    public CatalogDatabaseRecord MarkChecked(
        CatalogDatabaseRecord record,
        string? etag,
        string? lastModified,
        DateTimeOffset checkedAtUtc)
    {
        record.ETag = string.IsNullOrWhiteSpace(etag) ? record.ETag : etag;
        record.LastModified = string.IsNullOrWhiteSpace(lastModified) ? record.LastModified : lastModified;
        record.CheckedAtUtc = checkedAtUtc;
        Write(record);
        return record;
    }

    /// <summary>
    /// Imports one record from an Omega-generated catalog bundle. Newer local data wins for
    /// additive imports such as a packaged bootstrap bundle.
    /// </summary>
    public bool ImportRecord(CatalogDatabaseRecord record)
    {
        if (!TryValidateRecord(record, null, out var validated))
            return false;

        var existing = TryRead(validated.Url);
        if (existing is not null && existing.CheckedAtUtc >= validated.CheckedAtUtc)
            return false;

        Write(validated);
        return true;
    }

    /// <summary>
    /// Replaces the complete database with a verified authoritative record set plus records that
    /// must survive locally (normally user-added repositories). Files are staged first, then the
    /// database directory is swapped so a failed central update never leaves a half-written catalog.
    /// </summary>
    public void ReplaceAll(
        IEnumerable<CatalogDatabaseRecord> authoritativeRecords,
        IEnumerable<CatalogDatabaseRecord> preservedLocalRecords)
    {
        var combined = new Dictionary<string, CatalogDatabaseRecord>(StringComparer.OrdinalIgnoreCase);

        foreach (var record in preservedLocalRecords)
        {
            if (TryValidateRecord(record, null, out var validated))
                combined[NormalizeUrl(validated.Url)] = validated;
        }

        var authoritativeCount = 0;
        foreach (var record in authoritativeRecords)
        {
            if (!TryValidateRecord(record, null, out var validated))
                throw new InvalidDataException($"Online catalog contains an invalid database record for {record.Url}.");
            combined[NormalizeUrl(validated.Url)] = validated;
            authoritativeCount++;
        }

        if (authoritativeCount == 0)
            throw new InvalidDataException("Online catalog contains no valid repository records.");

        var parent = Path.GetDirectoryName(directory) ?? ".";
        Directory.CreateDirectory(parent);
        var staging = Path.Combine(parent, $"{Path.GetFileName(directory)}.staging-{Guid.NewGuid():N}");
        var backup = Path.Combine(parent, $"{Path.GetFileName(directory)}.backup-{Guid.NewGuid():N}");

        Directory.CreateDirectory(staging);
        try
        {
            foreach (var record in combined.Values)
                WriteToDirectory(staging, record);

            lock (sync)
            {
                var hadExisting = Directory.Exists(directory);
                try
                {
                    if (hadExisting)
                        Directory.Move(directory, backup);
                    Directory.Move(staging, directory);
                    if (Directory.Exists(backup))
                        Directory.Delete(backup, recursive: true);
                }
                catch
                {
                    if (Directory.Exists(directory))
                        Directory.Delete(directory, recursive: true);
                    if (Directory.Exists(backup))
                        Directory.Move(backup, directory);
                    throw;
                }
            }
        }
        finally
        {
            if (Directory.Exists(staging))
                Directory.Delete(staging, recursive: true);
            if (Directory.Exists(backup))
                Directory.Delete(backup, recursive: true);
        }
    }

    internal static bool TryValidateRecord(
        CatalogDatabaseRecord? record,
        string? requiredNormalizedUrl,
        out CatalogDatabaseRecord validated)
    {
        validated = null!;
        if (record is null ||
            record.SchemaVersion != 1 ||
            string.IsNullOrWhiteSpace(record.Url) ||
            string.IsNullOrWhiteSpace(record.ManifestJson) ||
            !Uri.TryCreate(record.Url, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        var normalized = NormalizeUrl(record.Url);
        if (!string.IsNullOrWhiteSpace(requiredNormalizedUrl) &&
            !normalized.Equals(requiredNormalizedUrl, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var expectedHash = HashText(record.ManifestJson);
        if (!expectedHash.Equals(record.ContentSha256, StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            _ = RepositoryManifestParser.Parse(
                record.ManifestJson,
                new RepositorySource { Name = "Catalog database", Url = normalized });
        }
        catch
        {
            return false;
        }

        record.Url = normalized;
        record.ContentSha256 = expectedHash;
        validated = record;
        return true;
    }

    private void Write(CatalogDatabaseRecord record)
    {
        lock (sync)
            WriteToDirectory(directory, record);
    }

    private void WriteToDirectory(string targetDirectory, CatalogDatabaseRecord record)
    {
        Directory.CreateDirectory(targetDirectory);
        var path = Path.Combine(targetDirectory, FileNameFor(NormalizeUrl(record.Url)));
        var temp = path + ".tmp";
        var json = JsonSerializer.Serialize(record, jsonOptions);
        File.WriteAllText(temp, json, new UTF8Encoding(false));
        File.Move(temp, path, true);
    }

    private string PathFor(string normalizedUrl) => Path.Combine(directory, FileNameFor(normalizedUrl));

    private static string FileNameFor(string normalizedUrl) => $"{HashText(normalizedUrl)}.json";

    private static string HashText(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string NormalizeUrl(string? url) => (url ?? string.Empty).Trim().TrimEnd('/');
}

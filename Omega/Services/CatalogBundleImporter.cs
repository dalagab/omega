using System.IO.Compression;
using System.Text.Json;

namespace Dalagab.Omega;

internal sealed class CatalogBundleImportResult
{
    public int ImportedRecords { get; init; }
    public int SkippedRecords { get; init; }
    public IReadOnlyList<CuratedSourceDefinition> SourceDefinitions { get; init; } = [];
    public IReadOnlyList<CatalogDatabaseRecord> Records { get; init; } = [];
}

/// <summary>
/// Reads/imports the database bundle produced by the Omega GitHub catalog-builder workflow.
/// Bundle records are revalidated locally before they are accepted.
/// </summary>
internal static class CatalogBundleImporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public static CatalogBundleImportResult Read(string zipPath)
    {
        if (!File.Exists(zipPath))
            return new CatalogBundleImportResult();

        var skipped = 0;
        var sources = new List<CuratedSourceDefinition>();
        var records = new List<CatalogDatabaseRecord>();

        using var archive = ZipFile.OpenRead(zipPath);
        foreach (var entry in archive.Entries)
        {
            if (entry.FullName.Equals("sources.json", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = entry.Open();
                var definitions = JsonSerializer.Deserialize<List<CuratedSourceDefinition>>(stream, JsonOptions);
                if (definitions is { Count: > 0 })
                    sources.AddRange(definitions);
                continue;
            }

            if (!entry.FullName.StartsWith("catalog-db/", StringComparison.OrdinalIgnoreCase) ||
                !entry.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            try
            {
                using var stream = entry.Open();
                var record = JsonSerializer.Deserialize<CatalogDatabaseRecord>(stream, JsonOptions);
                if (CatalogDatabase.TryValidateRecord(record, null, out var validated))
                    records.Add(validated);
                else
                    skipped++;
            }
            catch
            {
                skipped++;
            }
        }

        return new CatalogBundleImportResult
        {
            ImportedRecords = records.Count,
            SkippedRecords = skipped,
            SourceDefinitions = sources,
            Records = records,
        };
    }

    public static CatalogBundleImportResult Import(string zipPath, CatalogDatabase database)
    {
        var read = Read(zipPath);
        var imported = 0;
        var skipped = read.SkippedRecords;
        foreach (var record in read.Records)
        {
            if (database.ImportRecord(record))
                imported++;
            else
                skipped++;
        }

        return new CatalogBundleImportResult
        {
            ImportedRecords = imported,
            SkippedRecords = skipped,
            SourceDefinitions = read.SourceDefinitions,
            Records = read.Records,
        };
    }
}

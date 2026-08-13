using System.Text.Json;

namespace Dalagab.Omega;

internal static class CuratedSourceCatalog
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public static bool MergeInto(Configuration configuration, string catalogPath)
    {
        var definitions = LoadDefinitions(catalogPath);
        var changed = MergeDefinitions(configuration, definitions, configuration.Version < 5);

        // Old builds stored the official source as a normal configuration row. If the
        // bundled catalog could not be read for any reason, keep the official feed alive.
        if (!configuration.Repositories.Any(x => x.IsOfficial))
        {
            configuration.Repositories.Insert(0, new RepositorySource
            {
                Name = "Dalamud official",
                Url = "https://kamori.goats.dev/Plugin/PluginMaster",
                Enabled = true,
                IsOfficial = true,
                IsExperimental = false,
                IsCurated = true,
                CuratedId = "dalamud-official",
                CuratedDescription = "Official Dalamud plugin repository.",
                IntegrateWithDalamud = true,
            });
            changed = true;
        }

        if (configuration.Version < 7)
        {
            configuration.Version = 7;
            changed = true;
        }

        return changed;
    }

    /// <summary>
    /// Merges source definitions carried by an Omega prebuilt catalog bundle. Existing user
    /// enable/disable choices are preserved; only newly discovered definitions default enabled.
    /// </summary>
    public static bool MergeDefinitionsInto(Configuration configuration, IEnumerable<CuratedSourceDefinition> definitions)
        => MergeDefinitions(configuration, definitions, enableAllCuratedMigration: false);

    private static bool MergeDefinitions(
        Configuration configuration,
        IEnumerable<CuratedSourceDefinition> definitions,
        bool enableAllCuratedMigration)
    {
        var changed = false;

        foreach (var definition in definitions)
        {
            if (string.IsNullOrWhiteSpace(definition.Id) ||
                !Uri.TryCreate(definition.Url, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps)
            {
                Plugin.Log.Warning("Skipping invalid curated Omega source {CuratedId} / {Url}", definition.Id, definition.Url);
                continue;
            }

            var normalized = NormalizeUrl(definition.Url);
            var source = configuration.Repositories.FirstOrDefault(x =>
                (!string.IsNullOrWhiteSpace(x.CuratedId) &&
                 x.CuratedId.Equals(definition.Id, StringComparison.OrdinalIgnoreCase)) ||
                NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase) ||
                (definition.IsOfficial && x.IsOfficial));

            if (source is null)
            {
                source = new RepositorySource
                {
                    Enabled = definition.EnabledByDefault,
                    IntegrateWithDalamud = definition.IsOfficial || definition.IntegrateWithDalamudByDefault,
                };
                configuration.Repositories.Add(source);
                changed = true;
            }

            changed |= SetIfDifferent(source.CuratedId, definition.Id, value => source.CuratedId = value);
            changed |= SetIfDifferent(source.Name, definition.Name, value => source.Name = value);
            changed |= SetIfDifferent(source.Url, uri.ToString(), value => source.Url = value);
            changed |= SetIfDifferent(source.CuratedDescription, definition.Description, value => source.CuratedDescription = value);

            if (!source.IsCurated)
            {
                source.IsCurated = true;
                changed = true;
            }

            if (source.IsOfficial != definition.IsOfficial)
            {
                source.IsOfficial = definition.IsOfficial;
                changed = true;
            }

            var experimental = !definition.IsOfficial;
            if (source.IsExperimental != experimental)
            {
                source.IsExperimental = experimental;
                changed = true;
            }

            if (enableAllCuratedMigration && !source.Enabled)
            {
                source.Enabled = true;
                changed = true;
            }

            if (definition.IsOfficial && !source.IntegrateWithDalamud)
            {
                source.IntegrateWithDalamud = true;
                changed = true;
            }
        }

        return changed;
    }

    private static IReadOnlyList<CuratedSourceDefinition> LoadDefinitions(string path)
    {
        try
        {
            if (!File.Exists(path))
                return DefaultDefinitions();

            var json = File.ReadAllText(path);
            var definitions = JsonSerializer.Deserialize<List<CuratedSourceDefinition>>(json, JsonOptions);
            return definitions is { Count: > 0 } ? definitions : DefaultDefinitions();
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Failed to read Omega curated source catalog from {Path}", path);
            return DefaultDefinitions();
        }
    }

    private static IReadOnlyList<CuratedSourceDefinition> DefaultDefinitions() =>
    [
        new CuratedSourceDefinition
        {
            Id = "dalamud-official",
            Name = "Dalamud official",
            Url = "https://kamori.goats.dev/Plugin/PluginMaster",
            Description = "Official Dalamud plugin repository.",
            IsOfficial = true,
            EnabledByDefault = true,
            IntegrateWithDalamudByDefault = true,
        },
    ];

    private static bool SetIfDifferent(string current, string desired, Action<string> setter)
    {
        if (string.Equals(current, desired, StringComparison.Ordinal))
            return false;
        setter(desired);
        return true;
    }

    private static string NormalizeUrl(string? url) => (url ?? string.Empty).Trim().TrimEnd('/');
}

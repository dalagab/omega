using System.Text.Json;

namespace Dalagab.Omega;

internal static class RepositoryManifestParser
{
    internal const int MaximumEntriesPerRepository = 10000;

    internal static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
    };

    public static IReadOnlyList<MarketplacePlugin> Parse(string json, RepositorySource source)
    {
        using var document = JsonDocument.Parse(json, JsonOptions);
        return Parse(document.RootElement, source);
    }

    public static IReadOnlyList<MarketplacePlugin> Parse(JsonElement root, RepositorySource source)
    {
        JsonElement pluginArray;
        if (root.ValueKind == JsonValueKind.Array)
        {
            pluginArray = root;
        }
        else if (root.ValueKind == JsonValueKind.Object && TryGetArray(root, out pluginArray))
        {
            // Wrapper formats are accepted as a convenience, but plain Dalamud arrays are the primary format.
        }
        else
        {
            throw new InvalidDataException("Repository JSON must be a Dalamud-style plugin manifest array or an object containing a plugins array.");
        }

        if (pluginArray.GetArrayLength() > MaximumEntriesPerRepository)
            throw new InvalidDataException($"Repository contains more than {MaximumEntriesPerRepository} entries.");

        var plugins = new List<MarketplacePlugin>();
        foreach (var element in pluginArray.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object)
                continue;

            var plugin = MarketplacePlugin.FromJson(element, source);
            if (string.IsNullOrWhiteSpace(plugin.InternalName) || string.IsNullOrWhiteSpace(plugin.Name))
                continue;
            plugins.Add(plugin);
        }

        return plugins;
    }

    private static bool TryGetArray(JsonElement root, out JsonElement plugins)
    {
        foreach (var property in root.EnumerateObject())
        {
            if ((property.Name.Equals("plugins", StringComparison.OrdinalIgnoreCase) ||
                 property.Name.Equals("pluginmaster", StringComparison.OrdinalIgnoreCase)) &&
                property.Value.ValueKind == JsonValueKind.Array)
            {
                plugins = property.Value;
                return true;
            }
        }

        plugins = default;
        return false;
    }
}

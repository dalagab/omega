namespace Dalagab.Omega;

internal sealed record MarketplaceTagInfo(string Name, int PluginCount);

internal sealed class MarketplaceTagIndex
{
    private readonly IReadOnlyDictionary<string, HashSet<string>> tagsByInternalName;

    public MarketplaceTagIndex(
        IReadOnlyList<MarketplaceTagInfo> tags,
        IReadOnlyDictionary<string, HashSet<string>> tagsByInternalName)
    {
        Tags = tags;
        this.tagsByInternalName = tagsByInternalName;
    }

    public IReadOnlyList<MarketplaceTagInfo> Tags { get; }

    public bool MatchesAll(string internalName, IReadOnlyCollection<string> requiredTags)
    {
        if (requiredTags.Count == 0)
            return true;
        if (!tagsByInternalName.TryGetValue(internalName, out var tags))
            return false;

        foreach (var requiredTag in requiredTags)
        {
            var tag = requiredTag?.Trim();
            if (!string.IsNullOrWhiteSpace(tag) && !tags.Contains(tag))
                return false;
        }

        return true;
    }
}

/// <summary>
/// Builds the normalized Steam-style tag index and applies case-insensitive multi-tag AND matching
/// without repository/network activity.
/// </summary>
internal static class MarketplaceTagRules
{
    public static MarketplaceTagIndex Build(IEnumerable<MarketplacePlugin> variants)
    {
        var tagsByPlugin = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var casingVotes = new Dictionary<string, Dictionary<string, int>>(StringComparer.OrdinalIgnoreCase);

        foreach (var variant in variants)
        {
            if (string.IsNullOrWhiteSpace(variant.InternalName))
                continue;

            if (!tagsByPlugin.TryGetValue(variant.InternalName, out var pluginTags))
            {
                pluginTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                tagsByPlugin[variant.InternalName] = pluginTags;
            }

            foreach (var rawTag in variant.Tags)
            {
                var tag = rawTag?.Trim();
                if (string.IsNullOrWhiteSpace(tag))
                    continue;

                pluginTags.Add(tag);

                if (!casingVotes.TryGetValue(tag, out var votes))
                {
                    votes = new Dictionary<string, int>(StringComparer.Ordinal);
                    casingVotes[tag] = votes;
                }

                votes[tag] = votes.TryGetValue(tag, out var count) ? count + 1 : 1;
            }
        }

        var pluginCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var pluginTags in tagsByPlugin.Values)
        {
            foreach (var tag in pluginTags)
                pluginCounts[tag] = pluginCounts.TryGetValue(tag, out var count) ? count + 1 : 1;
        }

        var infos = pluginCounts
            .Select(pair => new MarketplaceTagInfo(PreferredCasing(pair.Key, casingVotes), pair.Value))
            .OrderByDescending(x => x.PluginCount)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new MarketplaceTagIndex(infos, tagsByPlugin);
    }

    private static string PreferredCasing(
        string normalizedTag,
        IReadOnlyDictionary<string, Dictionary<string, int>> casingVotes)
    {
        if (!casingVotes.TryGetValue(normalizedTag, out var votes) || votes.Count == 0)
            return normalizedTag;

        var lowerCase = votes.Keys
            .Where(x => x.Equals(x.ToLowerInvariant(), StringComparison.Ordinal))
            .OrderByDescending(x => votes[x])
            .ThenBy(x => x, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(lowerCase))
            return lowerCase;

        return votes
            .OrderByDescending(x => x.Value)
            .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Key, StringComparer.Ordinal)
            .First()
            .Key;
    }
}

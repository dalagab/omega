namespace Dalagab.Omega;

/// <summary>
/// Extracts bounded user-facing usage/command information from metadata already collected by Omega.
/// This deliberately avoids network access from the game client; website README data comes from the
/// catalog enrichment workflow.
/// </summary>
internal static class MarketplaceUsageRules
{
    private static readonly string[] UsageHeadings =
    [
        "how to use", "usage", "using", "getting started", "quick start", "commands",
        "command", "configuration", "config", "controls", "keybinds", "key binds",
    ];

    public static string Extract(MarketplacePresentationContent content)
    {
        var readmeUsage = ExtractMarkdownUsage(content.Readme);
        if (!string.IsNullOrWhiteSpace(readmeUsage))
            return readmeUsage;

        return ExtractDescriptionUsage(content.Description);
    }

    internal static string ExtractMarkdownUsage(string? markdown)
    {
        var lines = NormalizeLines(markdown);
        if (lines.Length == 0)
            return string.Empty;

        var sections = new List<string>();
        for (var index = 0; index < lines.Length; index++)
        {
            if (!TryMarkdownHeading(lines[index], out var level, out var title) || !IsUsageHeading(title))
                continue;

            var section = new List<string> { title };
            for (var body = index + 1; body < lines.Length; body++)
            {
                if (TryMarkdownHeading(lines[body], out var nextLevel, out _) && nextLevel <= level)
                    break;
                section.Add(lines[body]);
            }

            var value = string.Join("\n", section).Trim();
            if (!string.IsNullOrWhiteSpace(value))
                sections.Add(value);
            if (sections.Count >= 3)
                break;
        }

        return Bound(string.Join("\n\n", sections));
    }

    internal static string ExtractDescriptionUsage(string? description)
    {
        var lines = NormalizeLines(description);
        if (lines.Length == 0)
            return string.Empty;

        var start = -1;
        for (var index = 0; index < lines.Length; index++)
        {
            var normalized = NormalizeHeading(lines[index]);
            if (IsUsageHeading(normalized) ||
                normalized.StartsWith("command prefix", StringComparison.OrdinalIgnoreCase))
            {
                start = index;
                break;
            }
        }

        if (start >= 0)
            return Bound(string.Join("\n", lines.Skip(start)).Trim());

        var commandLines = lines
            .Select((line, index) => (line, index))
            .Where(x => x.line.TrimStart().StartsWith("/", StringComparison.Ordinal))
            .ToArray();
        if (commandLines.Length == 0)
            return string.Empty;

        var first = Math.Max(0, commandLines[0].index - 1);
        var last = Math.Min(lines.Length - 1, commandLines[^1].index + 1);
        return Bound(string.Join("\n", lines[first..(last + 1)]).Trim());
    }

    private static bool TryMarkdownHeading(string line, out int level, out string title)
    {
        var trimmed = line.TrimStart();
        level = 0;
        while (level < trimmed.Length && level < 6 && trimmed[level] == '#')
            level++;
        if (level == 0 || level >= trimmed.Length || !char.IsWhiteSpace(trimmed[level]))
        {
            title = string.Empty;
            return false;
        }

        title = trimmed[(level + 1)..].Trim().TrimEnd('#').Trim();
        return title.Length > 0;
    }

    private static bool IsUsageHeading(string value)
    {
        var normalized = NormalizeHeading(value);
        return UsageHeadings.Any(heading =>
            normalized.Equals(heading, StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(heading + " ", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(heading + ":", StringComparison.OrdinalIgnoreCase));
    }

    private static string NormalizeHeading(string value)
        => (value ?? string.Empty).Trim().Trim(':').Trim().ToLowerInvariant();

    private static string[] NormalizeLines(string? value)
        => (value ?? string.Empty)
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n')
            .Select(line => line.TrimEnd())
            .ToArray();

    private static string Bound(string value)
        => value.Length <= 6000 ? value : value[..6000].TrimEnd() + "\n…";
}

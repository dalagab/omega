using System.Text.RegularExpressions;

namespace Dalagab.Omega;

/// <summary>
/// Conservative parser/intersector for the normalized plugin dependency version grammar.
/// Unknown syntax is intentionally rejected for required dependencies rather than guessed.
/// </summary>
internal sealed class PluginVersionConstraint
{
    private static readonly Regex ComparatorRegex = new(
        @"(?<op>>=|<=|==|=|>|<)\s*(?<version>v?\d+(?:\.\d+){0,3})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly Regex BareVersionRegex = new(
        @"^v?\d+(?:\.\d+){0,3}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly Regex NugetRangeRegex = new(
        @"^(?<left>\[|\()\s*(?<min>v?\d+(?:\.\d+){0,3})?\s*,\s*(?<max>v?\d+(?:\.\d+){0,3})?\s*(?<right>\]|\))$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly Regex NugetExactRegex = new(
        @"^\[\s*(?<version>v?\d+(?:\.\d+){0,3})\s*\]$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private PluginVersionConstraint(
        string displayText,
        Version? lower,
        bool lowerInclusive,
        Version? upper,
        bool upperInclusive)
    {
        DisplayText = displayText;
        Lower = lower;
        LowerInclusive = lowerInclusive;
        Upper = upper;
        UpperInclusive = upperInclusive;
    }

    public string DisplayText { get; }
    public Version? Lower { get; }
    public bool LowerInclusive { get; }
    public Version? Upper { get; }
    public bool UpperInclusive { get; }

    public static PluginVersionConstraint Any { get; } = new("any", null, true, null, true);

    public bool Allows(Version version)
    {
        if (Lower is not null)
        {
            var compare = version.CompareTo(Lower);
            if (compare < 0 || (compare == 0 && !LowerInclusive))
                return false;
        }
        if (Upper is not null)
        {
            var compare = version.CompareTo(Upper);
            if (compare > 0 || (compare == 0 && !UpperInclusive))
                return false;
        }
        return true;
    }

    public static bool TryParse(string? text, out PluginVersionConstraint constraint, out string error)
    {
        var value = (text ?? string.Empty).Trim();
        if (value.Length == 0 || value.Equals("any", StringComparison.OrdinalIgnoreCase) || value == "*")
        {
            constraint = Any;
            error = string.Empty;
            return true;
        }

        var exactRange = NugetExactRegex.Match(value);
        if (exactRange.Success && TryVersion(exactRange.Groups["version"].Value, out var exactVersion))
        {
            constraint = new(value, exactVersion, true, exactVersion, true);
            error = string.Empty;
            return true;
        }

        var nugetRange = NugetRangeRegex.Match(value);
        if (nugetRange.Success)
        {
            Version? lower = null;
            Version? upper = null;
            if (nugetRange.Groups["min"].Success)
            {
                if (!TryVersion(nugetRange.Groups["min"].Value, out var parsedLower))
                    return Fail(value, out constraint, out error);
                lower = parsedLower;
            }
            if (nugetRange.Groups["max"].Success)
            {
                if (!TryVersion(nugetRange.Groups["max"].Value, out var parsedUpper))
                    return Fail(value, out constraint, out error);
                upper = parsedUpper;
            }
            constraint = new(
                value,
                lower,
                nugetRange.Groups["left"].Value == "[",
                upper,
                nugetRange.Groups["right"].Value == "]");
            if (!IsNonEmpty(constraint))
            {
                error = $"Version range '{value}' is empty.";
                return false;
            }
            error = string.Empty;
            return true;
        }

        if (BareVersionRegex.IsMatch(value) && TryVersion(value, out var bare))
        {
            constraint = new(value, bare, true, bare, true);
            error = string.Empty;
            return true;
        }

        var matches = ComparatorRegex.Matches(value);
        if (matches.Count == 0)
            return Fail(value, out constraint, out error);

        var residue = ComparatorRegex.Replace(value, string.Empty)
            .Replace(",", string.Empty, StringComparison.Ordinal)
            .Replace("&&", string.Empty, StringComparison.Ordinal)
            .Replace(";", string.Empty, StringComparison.Ordinal)
            .Trim();
        if (residue.Length != 0)
            return Fail(value, out constraint, out error);

        Version? lowerBound = null;
        var lowerInclusive = true;
        Version? upperBound = null;
        var upperInclusive = true;

        foreach (Match match in matches)
        {
            if (!TryVersion(match.Groups["version"].Value, out var version))
                return Fail(value, out constraint, out error);
            var op = match.Groups["op"].Value;
            switch (op)
            {
                case ">":
                case ">=":
                    SetLower(ref lowerBound, ref lowerInclusive, version, op == ">=");
                    break;
                case "<":
                case "<=":
                    SetUpper(ref upperBound, ref upperInclusive, version, op == "<=");
                    break;
                case "=":
                case "==":
                    SetLower(ref lowerBound, ref lowerInclusive, version, true);
                    SetUpper(ref upperBound, ref upperInclusive, version, true);
                    break;
            }
        }

        constraint = new(value, lowerBound, lowerInclusive, upperBound, upperInclusive);
        if (!IsNonEmpty(constraint))
        {
            error = $"Version constraint '{value}' has no possible version.";
            return false;
        }
        error = string.Empty;
        return true;
    }

    public static bool TryIntersect(
        IEnumerable<string> values,
        out PluginVersionConstraint constraint,
        out string effectiveText,
        out string error)
    {
        var texts = values
            .Select(x => (x ?? string.Empty).Trim())
            .Where(x => x.Length > 0 && !x.Equals("any", StringComparison.OrdinalIgnoreCase) && x != "*")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (texts.Length == 0)
        {
            constraint = Any;
            effectiveText = "any";
            error = string.Empty;
            return true;
        }

        Version? lower = null;
        var lowerInclusive = true;
        Version? upper = null;
        var upperInclusive = true;
        foreach (var text in texts)
        {
            if (!TryParse(text, out var parsed, out error))
            {
                constraint = Any;
                effectiveText = string.Join(" ∩ ", texts);
                return false;
            }
            if (parsed.Lower is not null)
                SetLower(ref lower, ref lowerInclusive, parsed.Lower, parsed.LowerInclusive);
            if (parsed.Upper is not null)
                SetUpper(ref upper, ref upperInclusive, parsed.Upper, parsed.UpperInclusive);
        }

        constraint = new(string.Join(" ∩ ", texts), lower, lowerInclusive, upper, upperInclusive);
        effectiveText = constraint.DisplayText;
        if (!IsNonEmpty(constraint))
        {
            error = $"Version requirements {effectiveText} cannot be satisfied together.";
            return false;
        }
        error = string.Empty;
        return true;
    }

    private static bool TryVersion(string value, out Version version)
    {
        var normalized = value.Trim();
        if (normalized.StartsWith('v') || normalized.StartsWith('V'))
            normalized = normalized[1..];
        var parts = normalized.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 1)
            normalized += ".0";
        if (Version.TryParse(normalized, out var parsed))
        {
            version = parsed;
            return true;
        }
        version = new Version(0, 0);
        return false;
    }

    private static void SetLower(ref Version? current, ref bool inclusive, Version candidate, bool candidateInclusive)
    {
        if (current is null || candidate.CompareTo(current) > 0)
        {
            current = candidate;
            inclusive = candidateInclusive;
            return;
        }
        if (candidate.CompareTo(current) == 0)
            inclusive = inclusive && candidateInclusive;
    }

    private static void SetUpper(ref Version? current, ref bool inclusive, Version candidate, bool candidateInclusive)
    {
        if (current is null || candidate.CompareTo(current) < 0)
        {
            current = candidate;
            inclusive = candidateInclusive;
            return;
        }
        if (candidate.CompareTo(current) == 0)
            inclusive = inclusive && candidateInclusive;
    }

    private static bool IsNonEmpty(PluginVersionConstraint value)
    {
        if (value.Lower is null || value.Upper is null)
            return true;
        var compare = value.Lower.CompareTo(value.Upper);
        return compare < 0 || (compare == 0 && value.LowerInclusive && value.UpperInclusive);
    }

    private static bool Fail(string value, out PluginVersionConstraint constraint, out string error)
    {
        constraint = Any;
        error = $"Version constraint '{value}' uses syntax Omega does not safely understand yet.";
        return false;
    }
}

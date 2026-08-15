using System.Buffers.Binary;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dalagab.Omega;

namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static string Root { get; set; } = string.Empty;

    internal static void TestRegressionBuildWiring()
    {
        var solution = File.ReadAllText(Path.Combine(Root, "Omega.sln"));
        Contains(solution, "Omega.RegressionTests", "regression project in solution");

        var project = File.ReadAllText(Path.Combine(Root, "Omega.RegressionTests", "Omega.RegressionTests.csproj"));
        Contains(project, "RunOmegaRegressionTests", "after-build regression target");
        Contains(project, "AfterTargets=\"Build\"", "regression target runs after build");
        Contains(project, "ReferenceOutputAssembly=\"false\"", "build ordering without loading Dalamud runtime");
    }

    internal static RepositorySource Source(string name) => new()
    {
        Name = name,
        Url = $"https://example.invalid/{Uri.EscapeDataString(name)}.json",
    };

    internal static MarketplacePlugin Plugin(
        string internalName,
        string version,
        int api,
        string install = "https://example.invalid/plugin.zip",
        string sourceName = "Community",
        bool official = false)
        => new()
        {
            Name = internalName,
            InternalName = internalName,
            AssemblyVersionText = version,
            DalamudApiLevel = api,
            DownloadLinkInstall = install,
            SourceName = sourceName,
            SourceUrl = $"https://example.invalid/{Uri.EscapeDataString(sourceName)}.json",
            SourceIsOfficial = official,
        };

    internal static string ReadMarketplaceCatalogServiceSource()
    {
        var directory = Path.Combine(Root, "Omega", "Services");
        return string.Join(
            "\n",
            Directory.EnumerateFiles(directory, "MarketplaceCatalogService*.cs")
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .Select(File.ReadAllText));
    }

    internal static string ReadMarketplaceWindowSource()
    {
        var directory = Path.Combine(Root, "Omega", "UI");
        return string.Join(
            "\n",
            Directory.EnumerateFiles(directory, "MarketplaceWindow*.cs")
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .Select(File.ReadAllText));
    }

    internal static string FindRepositoryRoot(string start)
    {
        var current = new DirectoryInfo(start);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Omega.sln")) &&
                Directory.Exists(Path.Combine(current.FullName, "Omega")))
                return current.FullName;
            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate Omega repository Root.");
    }

    internal static string RequiredString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
            throw new InvalidDataException($"Missing string property '{name}'.");
        return value.GetString() ?? string.Empty;
    }

    internal static string Capture(string input, string pattern)
    {
        var match = Regex.Match(input, pattern);
        if (!match.Success)
            throw new InvalidDataException($"Pattern not found: {pattern}");
        return match.Groups[1].Value;
    }

    internal static void Contains(string input, string expected, string message)
    {
        if (!input.Contains(expected, StringComparison.Ordinal))
            throw new InvalidOperationException($"{message}: missing '{expected}'");
    }

    internal static void DoesNotContain(string input, string unexpected, string message)
    {
        if (input.Contains(unexpected, StringComparison.Ordinal))
            throw new InvalidOperationException($"{message}: unexpectedly contained '{unexpected}'");
    }

    internal static void True(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    internal static void False(bool condition, string message) => True(!condition, message);

    internal static void Equal<T>(T expected, T actual, string message)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException($"{message}: expected '{expected}', got '{actual}'");
    }

    internal static void Throws<TException>(Action action, string message) where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }
}

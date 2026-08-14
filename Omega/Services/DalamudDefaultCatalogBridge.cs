using System.Collections;
using System.Reflection;
using Dalamud.Plugin;

namespace Dalagab.Omega;

/// <summary>
/// Reads Dalamud's already-loaded official plugin catalogue from PluginManager without causing
/// network traffic. This keeps Omega's default-plugin view identical to the normal Dalamud installer.
/// </summary>
internal sealed class DalamudDefaultCatalogBridge
{
    private const string OfficialSourceName = "Dalamud official";
    private const string OfficialSourceUrl = "https://kamori.goats.dev/Plugin/PluginMaster";

    public IReadOnlyList<MarketplacePlugin> ReadAvailable()
    {
        try
        {
            var manager = GetPluginManager();
            var available = Get(manager, "AvailablePlugins") as IEnumerable;
            if (available is null)
                return [];

            var result = new List<MarketplacePlugin>();
            foreach (var manifest in available)
            {
                if (manifest is null || !IsOfficial(manifest))
                    continue;

                var plugin = Map(manifest);
                if (!string.IsNullOrWhiteSpace(plugin.Name) && !string.IsNullOrWhiteSpace(plugin.InternalName))
                    result.Add(plugin);
            }

            return result
                .GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
                .Select(x => x.OrderByDescending(v => v.AssemblyVersion).First())
                .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega could not read Dalamud's in-memory default plugin catalogue.");
            return [];
        }
    }

    private static bool IsOfficial(object manifest)
    {
        var source = Get(manifest, "SourceRepo");
        if (source is null)
            return false;
        return !Bool(Get(source, "IsThirdParty"), true);
    }

    private static MarketplacePlugin Map(object manifest)
    {
        var source = Get(manifest, "SourceRepo");
        var sourceUrl = Text(Get(source, "PluginMasterUrl"), OfficialSourceUrl);
        return new MarketplacePlugin
        {
            Author = Text(Get(manifest, "Author")),
            Name = Text(Get(manifest, "Name")),
            InternalName = Text(Get(manifest, "InternalName")),
            Punchline = Text(Get(manifest, "Punchline")),
            Description = Text(Get(manifest, "Description")),
            Changelog = Text(Get(manifest, "Changelog")),
            AssemblyVersionText = Text(Get(manifest, "AssemblyVersion"), "0.0.0.0"),
            TestingAssemblyVersionText = NullableText(Get(manifest, "TestingAssemblyVersion")),
            DalamudApiLevel = Number<int>(Get(manifest, "DalamudApiLevel")),
            TestingDalamudApiLevel = NullableNumber<int>(Get(manifest, "TestingDalamudApiLevel")),
            ApplicableVersion = Text(Get(manifest, "ApplicableVersion"), "any"),
            MinimumDalamudVersionText = NullableText(Get(manifest, "MinimumDalamudVersion")),
            RepoUrl = Text(Get(manifest, "RepoUrl")),
            DownloadLinkInstall = Text(Get(manifest, "DownloadLinkInstall")),
            DownloadLinkUpdate = Text(Get(manifest, "DownloadLinkUpdate")),
            DownloadLinkTesting = Text(Get(manifest, "DownloadLinkTesting")),
            IconUrl = Text(Get(manifest, "IconUrl")),
            ImageUrls = Strings(Get(manifest, "ImageUrls")),
            Tags = Strings(Get(manifest, "Tags")),
            CategoryTags = Strings(Get(manifest, "CategoryTags")),
            DownloadCount = Number<long>(Get(manifest, "DownloadCount")),
            LastUpdate = Number<long>(Get(manifest, "LastUpdate")),
            IsHide = Bool(Get(manifest, "IsHide")),
            IsTestingExclusive = Bool(Get(manifest, "IsTestingExclusive")),
            Dip17Channel = Text(Get(manifest, "Dip17Channel")),
            SourceName = OfficialSourceName,
            SourceUrl = sourceUrl,
            SourceIsOfficial = true,
        };
    }

    private static object GetPluginManager()
    {
        var assembly = typeof(IDalamudPluginInterface).Assembly;
        var managerType = RequireType(assembly, "Dalamud.Plugin.Internal.PluginManager");
        var serviceOpenType = RequireType(assembly, "Dalamud.Service`1");
        var serviceType = serviceOpenType.MakeGenericType(managerType);
        var get = serviceType.GetMethod("Get", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMethodException("Dalamud service locator could not resolve PluginManager.");
        return get.Invoke(null, null) ?? throw new InvalidOperationException("Dalamud PluginManager service was null.");
    }

    private static object? Get(object? target, string property)
        => target?.GetType().GetProperty(property, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.GetValue(target);

    private static Type RequireType(Assembly assembly, string name)
        => assembly.GetType(name, throwOnError: false) ?? throw new TypeLoadException($"Dalamud internal type changed: {name}");

    private static string Text(object? value, string fallback = "")
        => value?.ToString() is { Length: > 0 } text ? text : fallback;

    private static string? NullableText(object? value)
        => value is null ? null : Text(value);

    private static bool Bool(object? value, bool fallback = false)
        => value is bool flag ? flag : fallback;

    private static T Number<T>(object? value) where T : struct, IConvertible
        => value is null ? default : (T)Convert.ChangeType(value, typeof(T));

    private static T? NullableNumber<T>(object? value) where T : struct, IConvertible
        => value is null ? null : Number<T>(value);

    private static IReadOnlyList<string> Strings(object? value)
    {
        if (value is not IEnumerable values || value is string)
            return [];
        return values.Cast<object?>()
            .Select(x => x?.ToString())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Cast<string>()
            .ToArray();
    }
}

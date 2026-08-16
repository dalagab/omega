using System.Buffers.Binary;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dalagab.Omega;

namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestManifestParserCommunityTolerance()
    {
        const string json = """
        [
          // community feeds commonly contain comments/trailing commas
          {
            "Author": "Tester",
            "Name": "Test Plugin",
            "InternalName": "TestPlugin",
            "AssemblyVersion": "1.2.3.4",
            "DalamudApiLevel": "15",
            "IsHide": "False",
            "LastUpdated": "123456789",
            "CategoryTags": ["Utility"],
            "ImageUrls": ["https://example.invalid/screenshot-1.png", "https://example.invalid/screenshot-2.png"],
            "OmegaWebsiteUrl": "https://example.invalid/project",
            "OmegaWebsiteDescription": "Richer website description",
            "OmegaWebsiteImageUrls": ["https://example.invalid/web-shot.png"],
            "OmegaEnriched": true,
            "DownloadLinkInstall": "https://example.invalid/test.zip",
          },
        ]
        """;

        var parsed = RepositoryManifestParser.Parse(json, Source("Community"));
        Equal(1, parsed.Count, "entry count");
        var plugin = parsed[0];
        Equal("Test Plugin", plugin.Name, "name");
        Equal(15, plugin.DalamudApiLevel, "string API level");
        Equal(123456789L, plugin.LastUpdate, "LastUpdated alias");
        False(plugin.IsHide, "string boolean");
        True(plugin.EffectiveCategories.Contains("Utility"), "category parsing");
        Equal(2, plugin.ImageUrls.Count, "screenshot URL parsing");
        True(plugin.OmegaEnriched, "website enrichment marker parsing");
        Equal(1, plugin.OmegaWebsiteImageUrls.Count, "website image parsing");
    }


    internal static void TestPresentationRichnessSelection()
    {
        var sparse = new MarketplacePlugin
        {
            InternalName = "SamePlugin",
            Name = "Same Plugin",
            SourceName = "Official",
            SourceUrl = "https://example.invalid/official.json",
            SourceIsOfficial = true,
            ImageUrls = ["https://example.invalid/one.png"],
            Description = "Short",
        };
        var rich = new MarketplacePlugin
        {
            InternalName = "SamePlugin",
            Name = "Same Plugin",
            SourceName = "Community rich source",
            SourceUrl = "https://example.invalid/rich.json",
            ImageUrls = ["https://example.invalid/a.png", "https://example.invalid/b.png", "https://example.invalid/c.png"],
            OmegaWebsiteImageUrls = ["https://example.invalid/d.png"],
            OmegaWebsiteDescription = "A much richer presentation source with screenshots and descriptive content.",
            OmegaEnriched = true,
        };

        var content = MarketplacePresentationRules.Choose(sparse, [sparse, rich]);
        Equal("Official", content.Variant.SourceName, "the selected baseline source owns product presentation");
        Equal(1, content.Images.Count, "baseline presentation does not silently borrow screenshots from another repository");
        False(content.IsEnhanced, "enrichment state follows the baseline source rather than an unrelated mirror");

        var communityOnly = MarketplacePresentationRules.Choose(rich, [sparse, rich]);
        Equal("Community rich source", communityOnly.Variant.SourceName, "an explicitly selected community baseline keeps its own metadata");
        Equal(4, communityOnly.Images.Count, "selected baseline presentation keeps its complete screenshot set");
    }

    internal static void TestManifestParserWrappers()
    {
        const string pluginsWrapper = """{"plugins":[{"Name":"One","InternalName":"One"}]}""";
        const string masterWrapper = """{"PluginMaster":[{"Name":"Two","InternalName":"Two"}]}""";
        Equal(1, RepositoryManifestParser.Parse(pluginsWrapper, Source("A")).Count, "plugins wrapper");
        Equal(1, RepositoryManifestParser.Parse(masterWrapper, Source("B")).Count, "pluginmaster wrapper");
    }

    internal static void TestManifestParserRejectsInvalidShape()
    {
        Throws<InvalidDataException>(
            () => RepositoryManifestParser.Parse("{\"Name\":\"not a repository\"}", Source("Invalid")),
            "single object must not become an install repository");
    }

    internal static void TestManifestParserSkipsInvalidEntries()
    {
        const string json = """
        [
          {"Name":"Missing internal name"},
          {"InternalName":"MissingName"},
          {"Name":"Valid","InternalName":"Valid"}
        ]
        """;
        var parsed = RepositoryManifestParser.Parse(json, Source("Validation"));
        Equal(1, parsed.Count, "only complete identities survive");
        Equal("Valid", parsed[0].InternalName, "valid identity");
    }

    internal static void TestStableApiCompatibility()
    {
        var plugin = Plugin("Stable", "1.0.0.0", 15, install: "https://example.invalid/stable.zip");
        True(plugin.SupportsApiLevel(15, false), "API 15 stable should be supported");
        Equal(15, plugin.DisplayApiLevel(15, false), "display current supported API");
        False(plugin.SupportsApiLevel(16, false), "future API should not be inferred compatible");
    }

    internal static void TestTestingApiCompatibility()
    {
        var plugin = new MarketplacePlugin
        {
            Name = "Testing",
            InternalName = "Testing",
            AssemblyVersionText = "1.0.0.0",
            DalamudApiLevel = 14,
            DownloadLinkInstall = "https://example.invalid/stable.zip",
            TestingAssemblyVersionText = "2.0.0.0",
            TestingDalamudApiLevel = 15,
            DownloadLinkTesting = "https://example.invalid/testing.zip",
        };

        False(plugin.SupportsApiLevel(15, false), "testing build must remain opt-in");
        True(plugin.SupportsApiLevel(15, true), "testing build should satisfy API when enabled");
        True(plugin.HasCurrentApiBuild(15, true, out var testing) && testing, "testing selection flag");
    }

    internal static void TestOmegaApiRangeCompatibility()
    {
        var plugin = new MarketplacePlugin
        {
            Name = "Range",
            InternalName = "Range",
            DalamudApiLevel = 13,
            OmegaMinimumApiLevel = 14,
            OmegaMaximumApiLevel = 16,
        };
        True(plugin.SupportsApiLevel(15, false), "declared Omega range");
        False(plugin.SupportsApiLevel(17, false), "outside declared Omega range");
    }

    internal static void TestUnmaintainedThreshold()
    {
        False(Plugin("Api14", "1.0.0.0", 14).IsUnmaintained(15), "one API behind is only outdated");
        False(Plugin("Api13", "1.0.0.0", 13).IsUnmaintained(15), "two APIs behind is only outdated");
        True(Plugin("Api12", "1.0.0.0", 12).IsUnmaintained(15), "three APIs behind is unmaintained");
        False(Plugin("Unknown", "1.0.0.0", 0).IsUnmaintained(15), "unknown API is not mislabeled unmaintained");
    }

    internal static void TestRepositoryStaleRule()
    {
        var stale = new[]
        {
            Plugin("OldA", "1.0.0.0", 12, sourceName: "Old Repo"),
            Plugin("OldB", "1.0.0.0", 11, sourceName: "Old Repo"),
        };
        True(RepositoryHealthRules.IsStale(stale, 15), "all plugins three or more APIs behind");

        var mixed = stale.Concat(new[] { Plugin("Recent", "1.0.0.0", 14, sourceName: "Old Repo") });
        False(RepositoryHealthRules.IsStale(mixed, 15), "one recent plugin keeps repository active");

        var unknown = new[] { Plugin("Unknown", "1.0.0.0", 0, sourceName: "Unknown Repo") };
        False(RepositoryHealthRules.IsStale(unknown, 15), "unknown API never marks a repository stale");
    }

    internal static void TestDuplicateVariantRetention()
    {
        var projection = MarketplaceCatalogRules.Project(new[]
        {
            Plugin("Same", "1.0.0.0", 15, sourceName: "Repo A"),
            Plugin("Same", "2.0.0.0", 15, sourceName: "Repo B"),
        });

        Equal(1, projection.Plugins.Count, "one storefront presentation entry");
        Equal(2, projection.Variants.Count, "all repository variants retained");
        Equal(2, MarketplaceCatalogRules.GetVariants(projection.Variants, "Same").Count, "source chooser sees both variants");
    }

    internal static void TestStableApiVariantAggregation()
    {
        var variants = new[]
        {
            Plugin("Same", "9.0.0.0", 0, sourceName: "Presentation Repo"),
            Plugin("Same", "1.0.0.0", 15, sourceName: "Stable API Repo"),
            Plugin("Same", "2.0.0.0", 14, sourceName: "Older Repo"),
            Plugin("Same", "3.0.0.0", 16, sourceName: "Future Repo"),
        };

        var projection = MarketplaceCatalogRules.Project(variants);
        Equal("Presentation Repo", projection.Plugins[0].SourceName, "presentation may come from variant without API metadata");
        Equal(16, MarketplaceCatalogRules.GetStableApiLevel(projection.Variants, "Same"), "highest stable API remains discoverable");
        Equal(15, MarketplaceCatalogRules.GetStableApiLevel(projection.Variants, "Same", 15), "current supported stable API is preferred for the badge");
    }

    internal static void TestOfficialVariantWinsProjection()
    {
        var official = Plugin("Same", "1.0.0.0", 15, sourceName: "Dalamud official", official: true);
        var newerCommunity = Plugin("Same", "99.0.0.0", 15, sourceName: "Community");
        var projection = MarketplaceCatalogRules.Project(new[] { newerCommunity, official });
        Equal("Dalamud official", projection.Plugins[0].SourceName, "official source precedence");
    }

    internal static void TestHighestCommunityVersionWinsProjection()
    {
        var projection = MarketplaceCatalogRules.Project(new[]
        {
            Plugin("Same", "1.0.0.0", 15, sourceName: "Repo A"),
            Plugin("Same", "3.0.0.0", 15, sourceName: "Repo B"),
            Plugin("Same", "2.0.0.0", 15, sourceName: "Repo C"),
        });
        Equal("Repo B", projection.Plugins[0].SourceName, "highest stable community version");
    }

    internal static void TestHiddenVariantFiltering()
    {
        var hidden = new MarketplacePlugin
        {
            Name = "Hidden",
            InternalName = "Hidden",
            IsHide = true,
            SourceName = "Hidden Repo",
        };
        var visible = Plugin("Visible", "1.0.0.0", 15, sourceName: "Visible Repo");
        var projection = MarketplaceCatalogRules.Project(new[] { hidden, visible });
        Equal(1, projection.Plugins.Count, "hidden storefront entry removed");
        Equal(1, projection.Variants.Count, "hidden source variant removed");
        Equal("Visible", projection.Plugins[0].InternalName, "visible plugin remains");
    }

    internal static void TestCuratedSources()
    {
        var path = Path.Combine(Root, "sources", "curated-sources.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var entries = doc.RootElement.EnumerateArray().ToArray();
        True(entries.Length >= 136, "reviewed curated + discovered source floor");

        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var officialCount = 0;
        var enabledCount = 0;
        foreach (var entry in entries)
        {
            var id = RequiredString(entry, "id");
            var url = RequiredString(entry, "url");
            True(ids.Add(id), $"duplicate curated id: {id}");
            True(urls.Add(url.TrimEnd('/')), $"duplicate curated URL: {url}");
            True(Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps, $"HTTPS source required: {id}");
            False(url.Contains("github.com/", StringComparison.OrdinalIgnoreCase) && url.Contains("/blob/", StringComparison.OrdinalIgnoreCase), $"GitHub blob URL must be normalized: {id}");
            if (entry.TryGetProperty("isOfficial", out var official) && official.ValueKind == JsonValueKind.True)
                officialCount++;
            if (entry.TryGetProperty("enabledByDefault", out var enabled) && enabled.ValueKind == JsonValueKind.True)
                enabledCount++;
        }

        Equal(1, officialCount, "exactly one official source");
        Equal(entries.Length, enabledCount, "all curated sources default enabled");

        foreach (var requiredId in new[]
        {
            "dalamud-official", "unknownx7", "nightmarexiv", "combat-reborn", "sea-of-stars",
            "eisenhuth-trustworthy", "sphene-dev", "ktisis-direct", "lmeter-direct",
            "karlin-main", "autovisor-direct", "ookura-risona",
            "williamw1979-ffxiv", "movemexiv", "automarket-pro", "aethergel-plugins",
            "lightless-sync", "playersync", "xivsync", "aetherlove-aetheros",
        })
            True(ids.Contains(requiredId), $"required curated source missing: {requiredId}");

        var defaults = entries.ToDictionary(
            entry => RequiredString(entry, "id"),
            entry => entry.TryGetProperty("enabledByDefault", out var enabled) && enabled.ValueKind == JsonValueKind.True,
            StringComparer.OrdinalIgnoreCase);
        foreach (var pair in defaults)
            True(pair.Value, $"curated source should default enabled: {pair.Key}");

        var discoveredCount = entries.Count(entry =>
            entry.TryGetProperty("description", out var description) &&
            description.GetString()?.Contains("user-provided Dalamud source batches", StringComparison.OrdinalIgnoreCase) == true);
        True(discoveredCount >= 90, "uploaded source batches should contribute reviewed repository-index candidates");
    }

}

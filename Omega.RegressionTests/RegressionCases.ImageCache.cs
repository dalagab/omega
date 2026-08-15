namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestPersistentMarketplaceImageCache()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"omega-image-cache-regression-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, PluginImageCacheStore.DatabaseFileName);
        try
        {
            var bytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 1, 2, 3, 4, 5, 6 };
            const string url = "https://example.invalid/screenshot.png";
            using (var store = new PluginImageCacheStore(path))
            {
                store.Put(url, bytes, "image/png", "\"etag-1\"", "Fri, 15 Aug 2026 12:00:00 GMT");
                var cached = store.TryRead(url);
                True(cached is not null, "stored image must be readable from the persistent SQLite cache");
                True(cached!.Bytes.SequenceEqual(bytes), "persistent cache must preserve the original encoded image bytes");
                Equal("image/png", cached.ContentType, "persistent cache content type");
                Equal("\"etag-1\"", cached.ETag, "persistent cache ETag");
                False(cached.NeedsRefresh(DateTimeOffset.UtcNow, TimeSpan.FromDays(7)), "newly cached artwork should be fresh");
                var stats = store.GetStatistics();
                Equal(1, stats.Entries, "persistent cache entry count");
                Equal((long)bytes.Length, stats.Bytes, "persistent cache byte count");
            }

            using (var reopened = new PluginImageCacheStore(path))
            {
                var cached = reopened.TryRead(url);
                True(cached is not null, "image cache must survive Omega/store restarts");
                True(cached!.Bytes.SequenceEqual(bytes), "reopened cache must return the same encoded bytes");
                reopened.Clear();
                Equal(0, reopened.GetStatistics().Entries, "clear must remove persistent image entries");
            }
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }

        var icons = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginIconCache.cs"));
        Contains(icons, "Task.Run(() => persistentCache.TryRead(url)", "persistent SQLite reads must stay off the UI thread");
        Contains(icons, "PersistentImageMaxAge = TimeSpan.FromDays(7)", "cached images must be revalidated periodically");
        Contains(icons, "If-None-Match", "stale persistent images must use conditional HTTP revalidation");

        var storeSource = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginImageCacheStore.cs"));
        Contains(storeSource, "omega-image-cache.sqlite", "artwork must use a separate local cache database");
        Contains(storeSource, "MaximumCacheBytes = 256L * 1024L * 1024L", "persistent image cache must be disk-bounded");
        Contains(storeSource, "ORDER BY last_access_utc ASC", "persistent image cache must evict least-recently-used entries");

        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(plugin, "new PluginIconCache(PluginInterface.ConfigDirectory.FullName)", "plugin must persist artwork under the Omega configuration directory");
    }
}

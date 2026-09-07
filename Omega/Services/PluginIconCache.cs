using System.Collections.Concurrent;
using Dalamud.Interface.Textures.TextureWraps;

namespace Dalagab.Omega;

/// <summary>
/// Lazily loads marketplace artwork for currently visible storefront entries. Downloaded image
/// bytes are persisted in a bounded local SQLite cache so artwork survives Omega restarts; the
/// production marketplace database remains small and contains only image URLs/metadata.
/// </summary>
internal sealed class PluginIconCache : IDisposable
{
    private const int MaximumImageBytes = 8 * 1024 * 1024;
    private const int MaximumProjectImageBytes = 32 * 1024 * 1024;
    private const int HeavyProjectImageThresholdBytes = MaximumImageBytes;
    private const int MaximumConcurrentIconLoads = 2;
    private const int MaximumLiveTextures = 192;
    private static readonly TimeSpan MinimumLiveTextureIdleAge = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan PersistentImageMaxAge = TimeSpan.FromDays(7);
    private static readonly TimeSpan FailedImageRetryDelay = TimeSpan.FromMinutes(2);

    private readonly HttpClient httpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(12),
    };

    private readonly PluginImageCacheStore persistentCache;
    private readonly CancellationTokenSource cancellation = new();
    private readonly SemaphoreSlim loadGate = new(MaximumConcurrentIconLoads, MaximumConcurrentIconLoads);
    private readonly Dictionary<string, Task<IDalamudTextureWrap?>> loads = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> loadMaximumBytes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> liveTextureLastUse = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> failedLoadAt = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ProjectMediaInfo> projectMedia = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Task> refreshes = new(StringComparer.OrdinalIgnoreCase);

    public PluginIconCache(string configurationDirectory)
    {
        persistentCache = new PluginImageCacheStore(
            Path.Combine(configurationDirectory, PluginImageCacheStore.DatabaseFileName));
    }

    public IDalamudTextureWrap? GetOrQueue(string? url)
        => GetOrQueue(url, MaximumImageBytes);

    public IDalamudTextureWrap? GetOrQueueProjectImage(string? url)
        => GetOrQueue(url, MaximumProjectImageBytes);

    public bool IsHeavyProjectMedia(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return false;

        url = NormalizeUrl(url);
        if (projectMedia.TryGetValue(url, out var info))
            return info.IsHeavy;
        return IsLikelyAnimatedProjectMediaUrl(url);
    }

    public bool IsAnimatedProjectMedia(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return false;

        url = NormalizeUrl(url);
        if (projectMedia.TryGetValue(url, out var info))
            return info.IsAnimated;
        return IsLikelyAnimatedProjectMediaUrl(url);
    }

    private IDalamudTextureWrap? GetOrQueue(string? url, int maximumImageBytes)
    {
        if (string.IsNullOrWhiteSpace(url))
            return null;

        url = NormalizeUrl(url);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed) ||
            (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp))
        {
            return null;
        }

        var now = Environment.TickCount64;
        liveTextureLastUse[url] = now;
        if (!loads.TryGetValue(url, out var load))
        {
            load = LoadAsync(url, maximumImageBytes, cancellation.Token);
            loads[url] = load;
            loadMaximumBytes[url] = maximumImageBytes;
        }
        else if (load.IsCompletedSuccessfully && load.Result is null)
        {
            var previousMaximum = loadMaximumBytes.TryGetValue(url, out var observedMaximum)
                ? observedMaximum
                : MaximumImageBytes;
            // A URL may first be encountered as ordinary artwork and later be recognized as
            // project media. Upgrade a completed 8 MiB failure immediately when the open product
            // page explicitly permits the larger bounded media tier; do not make the user wait for
            // the normal transient-failure retry cooldown.
            if (maximumImageBytes > previousMaximum)
            {
                loads.Remove(url);
                failedLoadAt.Remove(url);
                load = LoadAsync(url, maximumImageBytes, cancellation.Token);
                loads[url] = load;
                loadMaximumBytes[url] = maximumImageBytes;
            }
            else if (!failedLoadAt.TryGetValue(url, out var failedAt))
            {
                failedLoadAt[url] = now;
            }
            else if (now - failedAt >= FailedImageRetryDelay.TotalMilliseconds)
            {
                loads.Remove(url);
                failedLoadAt.Remove(url);
                load = LoadAsync(url, maximumImageBytes, cancellation.Token);
                loads[url] = load;
                loadMaximumBytes[url] = maximumImageBytes;
            }
        }
        else if (load.IsCompletedSuccessfully)
        {
            failedLoadAt.Remove(url);
        }

        // Re-check the working-set bound on ordinary cache hits too. This lets a burst of fast
        // scrolling settle back to the target once older textures have been idle for a moment.
        TrimLiveTextures(url);
        return load.IsCompletedSuccessfully ? load.Result : null;
    }

    public bool IsTerminalFailure(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return true;

        url = NormalizeUrl(url);
        return loads.TryGetValue(url, out var load) &&
               load.IsCompletedSuccessfully &&
               load.Result is null;
    }

    public void Dispose()
    {
        cancellation.Cancel();

        foreach (var load in loads.Values)
        {
            if (load.IsCompletedSuccessfully)
                load.Result?.Dispose();
        }

        loads.Clear();
        loadMaximumBytes.Clear();
        liveTextureLastUse.Clear();
        failedLoadAt.Clear();
        projectMedia.Clear();
        httpClient.Dispose();
        persistentCache.Dispose();
        loadGate.Dispose();
        cancellation.Dispose();
    }

    private void TrimLiveTextures(string currentUrl)
    {
        if (loads.Count <= MaximumLiveTextures)
            return;

        var now = Environment.TickCount64;
        var minimumIdleMs = (long)MinimumLiveTextureIdleAge.TotalMilliseconds;
        var candidates = loads
            .Where(pair => !pair.Key.Equals(currentUrl, StringComparison.OrdinalIgnoreCase) && pair.Value.IsCompleted)
            .OrderBy(pair => liveTextureLastUse.TryGetValue(pair.Key, out var lastUse) ? lastUse : long.MinValue)
            .ToArray();

        foreach (var pair in candidates)
        {
            if (loads.Count <= MaximumLiveTextures)
                break;

            var lastUse = liveTextureLastUse.TryGetValue(pair.Key, out var observed) ? observed : long.MinValue;
            if (lastUse != long.MinValue && now - lastUse < minimumIdleMs)
                continue;

            if (loads.Remove(pair.Key, out var completed))
            {
                if (completed.IsCompletedSuccessfully)
                    completed.Result?.Dispose();
                loadMaximumBytes.Remove(pair.Key);
                liveTextureLastUse.Remove(pair.Key);
                failedLoadAt.Remove(pair.Key);
            }
        }
    }

    private static string NormalizeUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            !uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase))
        {
            return url;
        }

        var parts = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 5 && parts[2].Equals("blob", StringComparison.OrdinalIgnoreCase))
        {
            return $"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/{parts[3]}/{string.Join("/", parts.Skip(4))}";
        }

        return url;
    }

    private async Task<IDalamudTextureWrap?> LoadAsync(string url, int maximumImageBytes, CancellationToken cancellationToken)
    {
        try
        {
            // Keep the UI thread free even when the cache is already local. SQLite work happens on
            // a worker thread and image decode/upload remains owned by Dalamud's texture provider.
            var cached = await Task.Run(() => persistentCache.TryRead(url), cancellationToken).ConfigureAwait(false);
            if (cached is not null)
            {
                if (maximumImageBytes > MaximumImageBytes)
                    RememberProjectMedia(url, cached.ContentType, cached.Bytes.LongLength);

                if (cached.Bytes.Length > maximumImageBytes)
                {
                    await Task.Run(() => persistentCache.Remove(url), cancellationToken).ConfigureAwait(false);
                    cached = null;
                }
            }

            if (cached is not null)
            {
                try
                {
                    var texture = await CreateTextureAsync(cached.Bytes, url, cancellationToken).ConfigureAwait(false);
                    if (texture is not null)
                    {
                        if (cached.NeedsRefresh(DateTimeOffset.UtcNow, PersistentImageMaxAge))
                            QueueBackgroundRefresh(url, cached, maximumImageBytes, cancellationToken);
                        return texture;
                    }
                }
                catch (Exception ex)
                {
                    Plugin.Log.Debug(ex, "Cached marketplace artwork was invalid and will be fetched again from {Url}", url);
                }

                await Task.Run(() => persistentCache.Remove(url), cancellationToken).ConfigureAwait(false);
            }

            return await DownloadAsync(url, null, createTexture: true, maximumImageBytes, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Unable to load marketplace artwork from {Url}", url);
            return null;
        }
    }

    private void QueueBackgroundRefresh(
        string url,
        CachedMarketplaceImage cached,
        int maximumImageBytes,
        CancellationToken cancellationToken)
    {
        refreshes.GetOrAdd(url, _ => RefreshAndForgetAsync(url, cached, maximumImageBytes, cancellationToken));
    }

    private async Task RefreshAndForgetAsync(
        string url,
        CachedMarketplaceImage cached,
        int maximumImageBytes,
        CancellationToken cancellationToken)
    {
        try
        {
            await DownloadAsync(url, cached, createTexture: false, maximumImageBytes, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Normal during plugin shutdown.
        }
        catch (Exception ex)
        {
            // A stale-cache refresh is opportunistic. The already-decoded cached image remains
            // usable, so connection failures should not dump a full exception stack into the
            // normal debug log as though artwork loading itself failed.
            Plugin.Log.Debug(
                "Marketplace artwork refresh skipped for {Url}: {Message}. Cached artwork remains available.",
                url,
                ex.Message);
        }
        finally
        {
            refreshes.TryRemove(url, out _);
        }
    }

    private async Task<IDalamudTextureWrap?> DownloadAsync(
        string url,
        CachedMarketplaceImage? cached,
        bool createTexture,
        int maximumImageBytes,
        CancellationToken cancellationToken)
    {
        var entered = false;
        try
        {
            await loadGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (!string.IsNullOrWhiteSpace(cached?.ETag))
                request.Headers.TryAddWithoutValidation("If-None-Match", cached.ETag);
            if (!string.IsNullOrWhiteSpace(cached?.LastModified))
                request.Headers.TryAddWithoutValidation("If-Modified-Since", cached.LastModified);

            using var response = await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);

            if (response.StatusCode == System.Net.HttpStatusCode.NotModified && cached is not null)
            {
                await Task.Run(
                    () => persistentCache.MarkChecked(
                        url,
                        response.Headers.ETag?.ToString(),
                        response.Content.Headers.LastModified?.ToString("R")),
                    cancellationToken).ConfigureAwait(false);
                return null;
            }

            if (!response.IsSuccessStatusCode)
                return null;

            var contentLength = response.Content.Headers.ContentLength;
            var contentType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
            if (maximumImageBytes > MaximumImageBytes)
                RememberProjectMedia(url, contentType, contentLength);

            if (contentLength is { } knownLength && knownLength > maximumImageBytes)
                return null;

            if (contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase) ||
                contentType.Contains("json", StringComparison.OrdinalIgnoreCase) ||
                contentType.Contains("html", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            if (maximumImageBytes > MaximumImageBytes)
                RememberProjectMedia(url, contentType, bytes.LongLength);
            if (bytes.Length == 0 || bytes.Length > maximumImageBytes)
                return null;

            await Task.Run(
                () => persistentCache.Put(
                    url,
                    bytes,
                    contentType,
                    response.Headers.ETag?.ToString(),
                    response.Content.Headers.LastModified?.ToString("R")),
                cancellationToken).ConfigureAwait(false);

            return createTexture
                ? await CreateTextureAsync(bytes, url, cancellationToken).ConfigureAwait(false)
                : null;
        }
        finally
        {
            if (entered)
                loadGate.Release();
        }
    }


    private void RememberProjectMedia(string url, string? contentType, long? contentLength)
    {
        var normalizedType = (contentType ?? string.Empty).Trim().ToLowerInvariant();
        var animated = normalizedType.Contains("gif", StringComparison.Ordinal) ||
                       normalizedType.Contains("apng", StringComparison.Ordinal) ||
                       IsLikelyAnimatedProjectMediaUrl(url);
        var heavy = animated || contentLength is > HeavyProjectImageThresholdBytes;
        projectMedia[url] = new ProjectMediaInfo(contentLength, normalizedType, animated, heavy);
    }

    private static bool IsLikelyAnimatedProjectMediaUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        var extension = Path.GetExtension(uri.AbsolutePath);
        return extension.Equals(".gif", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".apng", StringComparison.OrdinalIgnoreCase);
    }

    private readonly record struct ProjectMediaInfo(
        long? ContentLength,
        string ContentType,
        bool IsAnimated,
        bool IsHeavy);

    private static async Task<IDalamudTextureWrap?> CreateTextureAsync(
        byte[] bytes,
        string url,
        CancellationToken cancellationToken)
        => await Plugin.TextureProvider.CreateFromImageAsync(
            bytes,
            $"Omega plugin artwork: {url}",
            cancellationToken).ConfigureAwait(false);
}

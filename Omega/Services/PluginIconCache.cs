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
    private const int MaximumConcurrentIconLoads = 2;
    private static readonly TimeSpan PersistentImageMaxAge = TimeSpan.FromDays(7);

    private readonly HttpClient httpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(12),
    };

    private readonly PluginImageCacheStore persistentCache;
    private readonly CancellationTokenSource cancellation = new();
    private readonly SemaphoreSlim loadGate = new(MaximumConcurrentIconLoads, MaximumConcurrentIconLoads);
    private readonly Dictionary<string, Task<IDalamudTextureWrap?>> loads = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Task> refreshes = new(StringComparer.OrdinalIgnoreCase);

    public PluginIconCache(string configurationDirectory)
    {
        persistentCache = new PluginImageCacheStore(
            Path.Combine(configurationDirectory, PluginImageCacheStore.DatabaseFileName));
    }

    public IDalamudTextureWrap? GetOrQueue(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return null;

        url = NormalizeUrl(url);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed) ||
            (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp))
        {
            return null;
        }

        if (!loads.TryGetValue(url, out var load))
        {
            load = LoadAsync(url, cancellation.Token);
            loads[url] = load;
        }

        return load.IsCompletedSuccessfully ? load.Result : null;
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
        httpClient.Dispose();
        persistentCache.Dispose();
        loadGate.Dispose();
        cancellation.Dispose();
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

    private async Task<IDalamudTextureWrap?> LoadAsync(string url, CancellationToken cancellationToken)
    {
        try
        {
            // Keep the UI thread free even when the cache is already local. SQLite work happens on
            // a worker thread and image decode/upload remains owned by Dalamud's texture provider.
            var cached = await Task.Run(() => persistentCache.TryRead(url), cancellationToken).ConfigureAwait(false);
            if (cached is not null)
            {
                try
                {
                    var texture = await CreateTextureAsync(cached.Bytes, url, cancellationToken).ConfigureAwait(false);
                    if (texture is not null)
                    {
                        if (cached.NeedsRefresh(DateTimeOffset.UtcNow, PersistentImageMaxAge))
                            QueueBackgroundRefresh(url, cached, cancellationToken);
                        return texture;
                    }
                }
                catch (Exception ex)
                {
                    Plugin.Log.Debug(ex, "Cached marketplace artwork was invalid and will be fetched again from {Url}", url);
                }

                await Task.Run(() => persistentCache.Remove(url), cancellationToken).ConfigureAwait(false);
            }

            return await DownloadAsync(url, null, createTexture: true, cancellationToken).ConfigureAwait(false);
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

    private void QueueBackgroundRefresh(string url, CachedMarketplaceImage cached, CancellationToken cancellationToken)
    {
        refreshes.GetOrAdd(url, _ => RefreshAndForgetAsync(url, cached, cancellationToken));
    }

    private async Task RefreshAndForgetAsync(string url, CachedMarketplaceImage cached, CancellationToken cancellationToken)
    {
        try
        {
            await DownloadAsync(url, cached, createTexture: false, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Normal during plugin shutdown.
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Unable to refresh cached marketplace artwork from {Url}", url);
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

            if (response.Content.Headers.ContentLength is > MaximumImageBytes)
                return null;

            var contentType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
            if (contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase) ||
                contentType.Contains("json", StringComparison.OrdinalIgnoreCase) ||
                contentType.Contains("html", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            if (bytes.Length == 0 || bytes.Length > MaximumImageBytes)
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

    private static async Task<IDalamudTextureWrap?> CreateTextureAsync(
        byte[] bytes,
        string url,
        CancellationToken cancellationToken)
        => await Plugin.TextureProvider.CreateFromImageAsync(
            bytes,
            $"Omega plugin artwork: {url}",
            cancellationToken).ConfigureAwait(false);
}

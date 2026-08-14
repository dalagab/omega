using Dalamud.Interface.Textures.TextureWraps;

namespace Dalagab.Omega;

/// <summary>
/// Lazily downloads plugin artwork for currently visible storefront entries.
/// Icons are kept only for the current Omega session; repository JSON reloads remain fully manual.
/// </summary>
internal sealed class PluginIconCache : IDisposable
{
    private const int MaximumIconBytes = 4 * 1024 * 1024;
    private const int MaximumConcurrentIconLoads = 2;

    private readonly HttpClient httpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(12),
    };

    private readonly CancellationTokenSource cancellation = new();
    private readonly SemaphoreSlim loadGate = new(MaximumConcurrentIconLoads, MaximumConcurrentIconLoads);
    private readonly Dictionary<string, Task<IDalamudTextureWrap?>> loads = new(StringComparer.OrdinalIgnoreCase);

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
        var entered = false;
        try
        {
            await loadGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;

            using var response = await httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                return null;

            if (response.Content.Headers.ContentLength is > MaximumIconBytes)
                return null;

            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            if (bytes.Length == 0 || bytes.Length > MaximumIconBytes)
                return null;

            return await Plugin.TextureProvider.CreateFromImageAsync(
                bytes,
                $"Omega plugin artwork: {url}",
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Unable to load marketplace icon from {Url}", url);
            return null;
        }
        finally
        {
            if (entered)
                loadGate.Release();
        }
    }
}

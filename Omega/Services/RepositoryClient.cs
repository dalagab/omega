using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace Dalagab.Omega;

internal sealed class RepositoryFetchResult
{
    public bool NotModified { get; init; }
    public string ManifestJson { get; init; } = string.Empty;
    public string ETag { get; init; } = string.Empty;
    public string LastModified { get; init; } = string.Empty;
}

/// <summary>
/// Performs bounded direct HTTP reads for explicit user-added repository checks. The production
/// public catalog itself is supplied by the online SQLite database, not rebuilt inside the game.
/// </summary>
internal sealed class RepositoryClient : IDisposable
{
    private const int MaxResponseBytes = 16 * 1024 * 1024;
    private readonly HttpClient httpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(20),
        MaxResponseContentBufferSize = 16 * 1024 * 1024,
    };

    public RepositoryClient()
    {
        httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"Dalagab.Omega/{BuildInfo.Version}");
    }

    public async Task<RepositoryFetchResult> FetchAsync(
        RepositorySource source,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, source.Url);

        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
            throw new InvalidDataException($"Repository response exceeds {MaxResponseBytes / (1024 * 1024)} MiB limit.");

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var memory = new MemoryStream();
        var buffer = new byte[81920];
        var total = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
                break;
            total += read;
            if (total > MaxResponseBytes)
                throw new InvalidDataException($"Repository response exceeds {MaxResponseBytes / (1024 * 1024)} MiB limit.");
            await memory.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        memory.Position = 0;
        using var reader = new StreamReader(memory, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1024, leaveOpen: true);
        var manifestJson = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);

        // Validate the response before it can replace a working database record.
        _ = RepositoryManifestParser.Parse(manifestJson, source);

        return new RepositoryFetchResult
        {
            ManifestJson = manifestJson,
            ETag = response.Headers.ETag?.ToString() ?? string.Empty,
            LastModified = response.Content.Headers.LastModified?.ToString("R") ?? string.Empty,
        };
    }

    public void Dispose() => httpClient.Dispose();
}

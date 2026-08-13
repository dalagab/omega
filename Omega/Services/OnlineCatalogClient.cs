using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Dalagab.Omega;

internal sealed class OnlineCatalogEndpointDefinition
{
    public int SchemaVersion { get; init; } = 1;
    public string DescriptorUrl { get; init; } = string.Empty;
}

internal sealed class OnlineCatalogDescriptor
{
    public string Schema { get; init; } = string.Empty;
    public int SchemaVersion { get; init; } = 1;
    public string GeneratedAtUtc { get; init; } = string.Empty;
    public string CatalogSha256 { get; init; } = string.Empty;
    public string BundleSha256 { get; init; } = string.Empty;
    // Legacy exact-bundle hash field accepted for early catalog.json prototypes.
    public string Sha256 { get; init; } = string.Empty;
    public long Size { get; init; }
    public string DownloadUrl { get; init; } = string.Empty;
}

internal sealed class OnlineCatalogState
{
    public int SchemaVersion { get; set; } = 1;
    public string DescriptorUrl { get; set; } = string.Empty;
    public string CatalogSha256 { get; set; } = string.Empty;
    public DateTimeOffset? GeneratedAtUtc { get; set; }
    public DateTimeOffset? AppliedAtUtc { get; set; }
}

internal enum OnlineCatalogCheckStatus
{
    Unavailable,
    Current,
    Downloaded,
}

internal sealed class OnlineCatalogCheckResult
{
    public OnlineCatalogCheckStatus Status { get; init; }
    public OnlineCatalogDescriptor? Descriptor { get; init; }
    public string BundlePath { get; init; } = string.Empty;
    public string Error { get; init; } = string.Empty;
}

internal static class OnlineCatalogEndpointCatalog
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public static OnlineCatalogEndpointDefinition Load(string assemblyDirectory, string configDirectory)
    {
        foreach (var path in new[]
        {
            Path.Combine(configDirectory, "catalog-endpoint.json"),
            Path.Combine(assemblyDirectory, "catalog-endpoint.json"),
        })
        {
            try
            {
                if (!File.Exists(path))
                    continue;

                var endpoint = JsonSerializer.Deserialize<OnlineCatalogEndpointDefinition>(File.ReadAllText(path), JsonOptions);
                if (endpoint is not null &&
                    endpoint.SchemaVersion == 1 &&
                    IsHttpsUrl(endpoint.DescriptorUrl))
                {
                    return endpoint;
                }
            }
            catch
            {
                // Invalid endpoint files simply disable the preferred online path.
            }
        }

        return new OnlineCatalogEndpointDefinition();
    }

    private static bool IsHttpsUrl(string? value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;
}

internal sealed class OnlineCatalogStateStore
{
    private readonly string path;
    private readonly JsonSerializerOptions jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public OnlineCatalogStateStore(string configDirectory)
    {
        path = Path.Combine(configDirectory, "catalog-online-state.json");
    }

    public OnlineCatalogState Load()
    {
        try
        {
            if (!File.Exists(path))
                return new OnlineCatalogState();
            var state = JsonSerializer.Deserialize<OnlineCatalogState>(File.ReadAllText(path), jsonOptions);
            return state is { SchemaVersion: 1 } ? state : new OnlineCatalogState();
        }
        catch
        {
            return new OnlineCatalogState();
        }
    }

    public void Save(OnlineCatalogState state)
    {
        var temp = path + ".tmp";
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
        File.WriteAllText(temp, JsonSerializer.Serialize(state, jsonOptions), new UTF8Encoding(false));
        File.Move(temp, path, true);
    }

    public void ClearAppliedCatalog(string descriptorUrl)
    {
        Save(new OnlineCatalogState
        {
            SchemaVersion = 1,
            DescriptorUrl = descriptorUrl,
        });
    }
}

/// <summary>
/// Checks one tiny Omega catalog descriptor and downloads the catalog bundle only when its semantic catalog hash changed.
/// Repository discovery and upstream validation stay on the GitHub runner; the game client never crawls GitHub.
/// </summary>
internal sealed class OnlineCatalogClient : IDisposable
{
    private const int MaxDescriptorBytes = 256 * 1024;
    private const long MaxBundleBytes = 128L * 1024 * 1024;

    private readonly HttpClient httpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(25),
    };

    private readonly JsonSerializerOptions jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public OnlineCatalogClient()
    {
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"Dalagab.Omega/{BuildInfo.Version}");
    }

    public async Task<OnlineCatalogCheckResult> CheckAsync(
        string descriptorUrl,
        string currentAppliedSha256,
        string tempDirectory,
        CancellationToken cancellationToken)
    {
        if (!TryHttpsUri(descriptorUrl, out var descriptorUri))
            return Unavailable("No valid HTTPS online catalog descriptor is configured.");

        try
        {
            var descriptorJson = await DownloadSmallTextAsync(descriptorUri, MaxDescriptorBytes, cancellationToken).ConfigureAwait(false);
            var descriptor = JsonSerializer.Deserialize<OnlineCatalogDescriptor>(descriptorJson, jsonOptions)
                ?? throw new InvalidDataException("Online catalog descriptor is empty.");
            ValidateDescriptor(descriptor, descriptorUri);

            var catalogSha256 = EffectiveCatalogSha256(descriptor);
            var bundleSha256 = EffectiveBundleSha256(descriptor);

            if (catalogSha256.Equals(currentAppliedSha256, StringComparison.OrdinalIgnoreCase))
            {
                return new OnlineCatalogCheckResult
                {
                    Status = OnlineCatalogCheckStatus.Current,
                    Descriptor = descriptor,
                };
            }

            var downloadUri = ResolveDownloadUri(descriptorUri, descriptor.DownloadUrl);
            Directory.CreateDirectory(tempDirectory);
            var tempPath = Path.Combine(tempDirectory, $"omega-catalog-{Guid.NewGuid():N}.zip");
            await DownloadFileAsync(downloadUri, tempPath, descriptor.Size, cancellationToken).ConfigureAwait(false);

            var actualSha = await ComputeSha256Async(tempPath, cancellationToken).ConfigureAwait(false);
            if (!actualSha.Equals(bundleSha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(tempPath);
                throw new InvalidDataException("Downloaded Omega catalog SHA-256 does not match catalog.json.");
            }

            return new OnlineCatalogCheckResult
            {
                Status = OnlineCatalogCheckStatus.Downloaded,
                Descriptor = descriptor,
                BundlePath = tempPath,
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Unavailable(ex.Message);
        }
    }

    internal static Uri ResolveDownloadUri(Uri descriptorUri, string downloadUrl)
    {
        if (string.IsNullOrWhiteSpace(downloadUrl))
            throw new InvalidDataException("Online catalog download URL is missing.");

        if (Uri.TryCreate(downloadUrl, UriKind.Absolute, out var absolute))
        {
            if (absolute.Scheme != Uri.UriSchemeHttps)
                throw new InvalidDataException("Online catalog download URL must use HTTPS.");
            return absolute;
        }

        if (!Uri.TryCreate(descriptorUri, downloadUrl, out var relative) || relative.Scheme != Uri.UriSchemeHttps)
            throw new InvalidDataException("Online catalog download URL is invalid.");
        return relative;
    }

    internal static bool IsValidSha256(string? value)
        => value is { Length: 64 } && value.All(c => char.IsAsciiHexDigit(c));

    internal static string EffectiveCatalogSha256(OnlineCatalogDescriptor descriptor)
        => !string.IsNullOrWhiteSpace(descriptor.CatalogSha256) ? descriptor.CatalogSha256 : descriptor.Sha256;

    internal static string EffectiveBundleSha256(OnlineCatalogDescriptor descriptor)
        => !string.IsNullOrWhiteSpace(descriptor.BundleSha256) ? descriptor.BundleSha256 : descriptor.Sha256;

    private static void ValidateDescriptor(OnlineCatalogDescriptor descriptor, Uri descriptorUri)
    {
        if (descriptor.SchemaVersion != 1 ||
            !string.Equals(descriptor.Schema, "omega.catalog.v1", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Unsupported Omega online catalog descriptor schema.");
        }

        if (!IsValidSha256(EffectiveCatalogSha256(descriptor)))
            throw new InvalidDataException("Online catalog descriptor has an invalid catalog SHA-256.");
        if (!IsValidSha256(EffectiveBundleSha256(descriptor)))
            throw new InvalidDataException("Online catalog descriptor has an invalid bundle SHA-256.");
        if (descriptor.Size <= 0 || descriptor.Size > MaxBundleBytes)
            throw new InvalidDataException("Online catalog descriptor has an invalid bundle size.");

        _ = ResolveDownloadUri(descriptorUri, descriptor.DownloadUrl);
    }

    private async Task<string> DownloadSmallTextAsync(Uri uri, int maxBytes, CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var contentLength = response.Content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > maxBytes)
            throw new InvalidDataException("Online catalog descriptor is too large.");

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var memory = new MemoryStream();
        var buffer = new byte[16 * 1024];
        var total = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
                break;
            total += read;
            if (total > maxBytes)
                throw new InvalidDataException("Online catalog descriptor is too large.");
            await memory.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        return Encoding.UTF8.GetString(memory.ToArray());
    }

    private async Task DownloadFileAsync(Uri uri, string destination, long expectedSize, CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > MaxBundleBytes)
            throw new InvalidDataException("Online catalog bundle exceeds the client size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true);
        var buffer = new byte[81920];
        long total = 0;
        while (true)
        {
            var read = await source.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
                break;
            total += read;
            if (total > MaxBundleBytes)
                throw new InvalidDataException("Online catalog bundle exceeds the client size limit.");
            await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        if (expectedSize > 0 && total != expectedSize)
            throw new InvalidDataException($"Online catalog size mismatch: expected {expectedSize}, received {total}.");
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
        using var sha = SHA256.Create();
        var hash = await sha.ComputeHashAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static bool TryHttpsUri(string? value, out Uri uri)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var parsed) && parsed.Scheme == Uri.UriSchemeHttps)
        {
            uri = parsed;
            return true;
        }
        uri = null!;
        return false;
    }

    private static OnlineCatalogCheckResult Unavailable(string error) => new()
    {
        Status = OnlineCatalogCheckStatus.Unavailable,
        Error = error,
    };

    public void Dispose() => httpClient.Dispose();
}

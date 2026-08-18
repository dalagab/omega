using System.Net;
using System.Text.Json;

namespace Dalagab.Omega;

/// <summary>
/// Periodically checks Omega's public PluginMaster entry for a newer application build. Dalamud
/// remains the update authority; this service only records availability and surfaces a shortcut to
/// the normal Dalamud update UI.
/// </summary>
internal sealed class OmegaSelfUpdateService : IDisposable
{
    internal const string RepositoryManifestUrl =
        "https://github.com/dalagab/omega/releases/download/omega-latest/pluginmaster.json";

    private static readonly TimeSpan InitialDelay = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(6);
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(30);
    private const int MaximumManifestBytes = 256 * 1024;

    private readonly Configuration configuration;
    private readonly HttpClient httpClient = new() { Timeout = TimeSpan.FromSeconds(20) };
    private readonly CancellationTokenSource cts = new();
    private readonly Task worker;
    private int running;

    public OmegaSelfUpdateService(Configuration configuration)
    {
        this.configuration = configuration;
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"Dalagab.Omega/{BuildInfo.Version}");
        worker = RunAsync(cts.Token);
    }

    public bool IsChecking => Volatile.Read(ref running) != 0;
    public string AvailableVersion => configuration.AvailableApplicationVersion ?? string.Empty;
    public string AvailableDisplayVersion => ProductVersionText(AvailableVersion);
    public bool UpdateAvailable => TryComparableVersion(AvailableVersion, out var available) &&
                                   TryComparableVersion(BuildInfo.Version, out var current) &&
                                   available.CompareTo(current) > 0;
    public string LastError { get; private set; } = string.Empty;

    public void TriggerIfDue()
    {
        if (!IsDue())
            return;
        _ = CheckNowAsync(cts.Token);
    }

    public Task CheckNowAsync() => CheckNowAsync(cts.Token);

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(InitialDelay, cancellationToken).ConfigureAwait(false);
            while (!cancellationToken.IsCancellationRequested)
            {
                if (IsDue())
                    await CheckNowAsync(cancellationToken).ConfigureAwait(false);
                await Task.Delay(PollInterval, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private bool IsDue()
    {
        if (IsChecking)
            return false;
        var last = configuration.LastApplicationUpdateCheckUtc;
        return last is null || DateTimeOffset.UtcNow - last.Value >= CheckInterval;
    }

    private async Task CheckNowAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref running, 1) != 0)
            return;

        try
        {
            LastError = string.Empty;
            using var request = new HttpRequestMessage(HttpMethod.Get, RepositoryManifestUrl);
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);

            // Before the first release produced by the generated-feed workflow, the canonical
            // omega-latest/pluginmaster.json asset legitimately does not exist yet. Treat that
            // bootstrap 404 as "no stable feed published" rather than an update-system failure.
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                configuration.LastApplicationUpdateCheckUtc = DateTimeOffset.UtcNow;
                configuration.Save();
                Plugin.Log.Information(
                    "Omega application update check deferred because the stable release feed has not been initialized yet.");
                return;
            }

            response.EnsureSuccessStatusCode();

            if (response.Content.Headers.ContentLength is > MaximumManifestBytes)
                throw new InvalidDataException("Omega repository manifest exceeded the maximum allowed size.");

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var bounded = new MemoryStream();
            var buffer = new byte[16 * 1024];
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    break;
                if (bounded.Length + read > MaximumManifestBytes)
                    throw new InvalidDataException("Omega repository manifest exceeded the maximum allowed size.");
                bounded.Write(buffer, 0, read);
            }

            bounded.Position = 0;
            using var document = JsonDocument.Parse(bounded);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("Omega repository manifest had an unexpected root shape.");

            var remoteVersion = string.Empty;
            foreach (var entry in document.RootElement.EnumerateArray())
            {
                if (!entry.TryGetProperty("InternalName", out var internalName) ||
                    !string.Equals(internalName.GetString(), Plugin.PluginInterface.InternalName, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (entry.TryGetProperty("AssemblyVersion", out var assemblyVersion))
                    remoteVersion = assemblyVersion.GetString() ?? string.Empty;
                break;
            }

            if (!TryComparableVersion(remoteVersion, out var remote))
                throw new InvalidDataException("Omega repository manifest did not contain a valid AssemblyVersion.");
            if (!TryComparableVersion(BuildInfo.Version, out var current))
                throw new InvalidDataException("The running Omega version could not be parsed.");

            configuration.AvailableApplicationVersion = remote.CompareTo(current) > 0 ? remoteVersion : string.Empty;
            configuration.LastApplicationUpdateCheckUtc = DateTimeOffset.UtcNow;
            configuration.Save();

            Plugin.Log.Information(
                "Omega application update check completed; current={Current}; remote={Remote}; updateAvailable={UpdateAvailable}",
                BuildInfo.Version,
                remoteVersion,
                remote.CompareTo(current) > 0);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            LastError = ex.GetBaseException().Message;
            configuration.LastApplicationUpdateCheckUtc = DateTimeOffset.UtcNow;
            configuration.Save();
            Plugin.Log.Warning(ex, "Omega application update check failed; existing update state remains unchanged.");
        }
        finally
        {
            Interlocked.Exchange(ref running, 0);
        }
    }

    private static string ProductVersionText(string? value)
    {
        if (!TryComparableVersion(value, out var version))
            return (value ?? string.Empty).Trim();
        return version.Revision == 0
            ? $"{version.Major}.{version.Minor}.{version.Build}"
            : version.ToString();
    }

    internal static bool TryComparableVersion(string? value, out Version version)
    {
        version = new Version(0, 0, 0, 0);
        if (!Version.TryParse((value ?? string.Empty).Trim(), out var parsed))
            return false;
        version = new Version(
            Math.Max(0, parsed.Major),
            Math.Max(0, parsed.Minor),
            Math.Max(0, parsed.Build),
            Math.Max(0, parsed.Revision));
        return true;
    }

    public void Dispose()
    {
        cts.Cancel();
        try { worker.Wait(TimeSpan.FromMilliseconds(250)); } catch { }
        httpClient.Dispose();
        cts.Dispose();
    }
}

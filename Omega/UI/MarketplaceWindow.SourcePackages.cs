using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private sealed record ProductPackageRepository(string Name, string Url, bool Official);

    private sealed record ProductSourcePackage(
        string Identity,
        string Channels,
        string Version,
        int ApiLevel,
        string DownloadUrl,
        string Sha256,
        IReadOnlyList<ProductPackageRepository> Repositories);

    private sealed record ProductPackageCandidate(
        string Identity,
        string Channel,
        string Version,
        int ApiLevel,
        string DownloadUrl,
        string Sha256,
        string SourceName,
        string SourceUrl,
        bool Official);

    private void DrawProductSourcePackages(MarketplacePlugin plugin)
    {
        var packages = BuildProductSourcePackages(plugin);
        if (packages.Count == 0)
            return;

        DrawProductSectionHeading(
            "Packages & repositories",
            "Distinct downloadable packages and the repository manifests that reference them");

        ImGui.Indent(14f);
        ImGui.TextDisabled(
            $"{packages.Count} distinct package{(packages.Count == 1 ? string.Empty : "s")} referenced by " +
            $"{packages.Sum(x => x.Repositories.Count)} repository manifest{(packages.Sum(x => x.Repositories.Count) == 1 ? string.Empty : "s")}.");
        ImGui.Dummy(new Vector2(1f, 6f));

        foreach (var package in packages)
            DrawProductSourcePackage(package);

        ImGui.Unindent(14f);
    }

    private IReadOnlyList<ProductSourcePackage> BuildProductSourcePackages(MarketplacePlugin plugin)
    {
        var variants = new[] { plugin }
            .Concat(catalog.GetPresentationVariants(plugin.InternalName))
            .Where(x => !string.IsNullOrWhiteSpace(x.InternalName))
            .GroupBy(
                x => $"{NormalizeUrl(x.SourceUrl)}\u001f{x.AssemblyVersionText}\u001f{x.TestingAssemblyVersionText}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .ToArray();

        var candidates = new List<ProductPackageCandidate>();
        foreach (var variant in variants)
        {
            var stableUrl = !string.IsNullOrWhiteSpace(variant.DownloadLinkInstall)
                ? variant.DownloadLinkInstall
                : variant.DownloadLinkUpdate;
            if (!string.IsNullOrWhiteSpace(stableUrl))
            {
                var stableSha = !variant.IsTestingExclusive ? variant.SecurityArtifactSha256 : string.Empty;
                candidates.Add(CreateProductPackageCandidate(
                    variant,
                    "Stable",
                    variant.AssemblyVersionText,
                    variant.DalamudApiLevel,
                    stableUrl,
                    stableSha));
            }

            if (!string.IsNullOrWhiteSpace(variant.DownloadLinkTesting))
            {
                var testingSha = variant.IsTestingExclusive || string.IsNullOrWhiteSpace(stableUrl)
                    ? variant.SecurityArtifactSha256
                    : string.Empty;
                candidates.Add(CreateProductPackageCandidate(
                    variant,
                    "Testing",
                    variant.TestingAssemblyVersionText ?? variant.AssemblyVersionText,
                    variant.TestingDalamudApiLevel ?? variant.DalamudApiLevel,
                    variant.DownloadLinkTesting,
                    testingSha));
            }
        }

        return candidates
            .GroupBy(x => x.Identity, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var ordered = group
                    .OrderByDescending(x => x.Official)
                    .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var first = ordered[0];
                var repositories = ordered
                    .GroupBy(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase)
                    .Select(x => x.First())
                    .OrderByDescending(x => x.Official)
                    .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
                    .Select(x => new ProductPackageRepository(
                        string.IsNullOrWhiteSpace(x.SourceName) ? "Unnamed repository" : x.SourceName,
                        x.SourceUrl,
                        x.Official))
                    .ToArray();
                var channels = string.Join(" / ", ordered.Select(x => x.Channel).Distinct(StringComparer.OrdinalIgnoreCase));
                var version = ordered.Select(x => x.Version).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "—";
                var api = ordered.Select(x => x.ApiLevel).FirstOrDefault(x => x > 0);
                var sha = ordered.Select(x => x.Sha256).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? string.Empty;
                return new ProductSourcePackage(
                    group.Key,
                    channels,
                    version,
                    api,
                    first.DownloadUrl,
                    sha,
                    repositories);
            })
            .OrderByDescending(x => x.Repositories.Any(r => r.Official))
            .ThenByDescending(x => x.Channels.Contains("Stable", StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(x => Version.TryParse(x.Version, out var version) ? version : new Version(0, 0))
            .ThenBy(x => x.Identity, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static ProductPackageCandidate CreateProductPackageCandidate(
        MarketplacePlugin variant,
        string channel,
        string version,
        int apiLevel,
        string downloadUrl,
        string sha256)
    {
        var normalizedSha = (sha256 ?? string.Empty).Trim().ToLowerInvariant();
        var normalizedUrl = NormalizePackageUrl(downloadUrl);
        var identity = !string.IsNullOrWhiteSpace(normalizedSha)
            ? $"sha256:{normalizedSha}"
            : $"url:{normalizedUrl}";
        return new ProductPackageCandidate(
            identity,
            channel,
            version,
            apiLevel,
            downloadUrl,
            normalizedSha,
            variant.SourceName,
            variant.SourceUrl,
            variant.SourceIsOfficial);
    }

    private static string NormalizePackageUrl(string? value)
        => (value ?? string.Empty).Trim().TrimEnd('/');

    private void DrawProductSourcePackage(ProductSourcePackage package)
    {
        var versionText = string.IsNullOrWhiteSpace(package.Version) ? "version unknown" : $"v{package.Version}";
        var apiText = package.ApiLevel > 0 ? $"API {package.ApiLevel}" : "API unknown";
        var repoText = $"{package.Repositories.Count} repositor{(package.Repositories.Count == 1 ? "y" : "ies")}";
        var label = $"{package.Channels} package · {versionText} · {apiText} · {repoText}##package-{StableId(package.Identity)}";

        ImGui.PushStyleColor(ImGuiCol.Header, new Vector4(0.07f, 0.16f, 0.18f, 0.72f));
        ImGui.PushStyleColor(ImGuiCol.HeaderHovered, new Vector4(0.08f, 0.23f, 0.25f, 0.84f));
        var open = ImGui.TreeNodeEx(label, ImGuiTreeNodeFlags.DefaultOpen | ImGuiTreeNodeFlags.SpanAvailWidth);
        ImGui.PopStyleColor(2);
        if (!open)
            return;

        ImGui.Indent(12f);
        if (!string.IsNullOrWhiteSpace(package.Sha256))
        {
            var shortHash = package.Sha256.Length > 16 ? package.Sha256[..16] + "…" : package.Sha256;
            ImGui.TextDisabled($"Artifact SHA-256: {shortHash}");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(package.Sha256);
        }
        else
        {
            ImGui.TextDisabled("Artifact hash: not available from the current scan");
        }

        if (!string.IsNullOrWhiteSpace(package.DownloadUrl))
        {
            ImGui.TextDisabled($"Package: {PackageLocationLabel(package.DownloadUrl)}");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(package.DownloadUrl);
        }

        ImGui.Spacing();
        ImGui.TextUnformatted("Repository manifests pointing to this package");
        foreach (var repository in package.Repositories)
        {
            if (repository.Official)
            {
                DrawDalamudOfficialLogoBadge(18f);
                ImGui.SameLine(0f, 7f);
                ImGui.TextUnformatted(repository.Name);
            }
            else
            {
                ImGui.TextDisabled("•");
                ImGui.SameLine(0f, 7f);
                ImGui.TextUnformatted(repository.Name);
            }
            if (ImGui.IsItemHovered() && !string.IsNullOrWhiteSpace(repository.Url))
                ImGui.SetTooltip(repository.Url);
            if (!string.IsNullOrWhiteSpace(repository.Url))
            {
                ImGui.SameLine(0f, 8f);
                ImGui.TextDisabled(PackageLocationLabel(repository.Url));
                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip(repository.Url);
            }
        }
        ImGui.Unindent(12f);
        ImGui.TreePop();
        ImGui.Spacing();
    }

    private static string PackageLocationLabel(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return Shorten(url, 72);
        var tail = uri.AbsolutePath.Trim('/');
        if (tail.Length > 46)
            tail = "…" + tail[^45..];
        return string.IsNullOrWhiteSpace(tail) ? uri.Host : $"{uri.Host}/{tail}";
    }
}

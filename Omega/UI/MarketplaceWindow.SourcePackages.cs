using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private sealed record ProductPackageRepository(
        string Name,
        string Url,
        bool Official,
        RepositorySecurityComparison SecurityComparison);

    private sealed record ProductSourcePackage(
        string Identity,
        bool IsTestingOnly,
        string Version,
        int ApiLevel,
        string DownloadUrl,
        string Sha256,
        IReadOnlyList<ProductPackageRepository> Repositories);

    private sealed record ProductPackageCandidate(
        string Identity,
        bool IsTesting,
        string Version,
        int ApiLevel,
        string DownloadUrl,
        string Sha256,
        string SourceName,
        string SourceUrl,
        bool Official,
        MarketplacePlugin Variant);

    private void DrawProductSourcePackages(MarketplacePlugin plugin, int currentApi, Version currentDalamudVersion)
    {
        var packages = BuildProductSourcePackages(plugin, currentApi, currentDalamudVersion);
        if (packages.Count == 0)
            return;

        DrawProductSectionHeading("Packages & repositories");

        ImGui.Indent(14f);
        var preferredIdentity = ResolvePreferredInstallPackageIdentity(plugin, packages, currentApi, currentDalamudVersion);
        var preferredPackage = packages.FirstOrDefault(x => x.Identity.Equals(preferredIdentity, StringComparison.OrdinalIgnoreCase));
        foreach (var package in packages)
        {
            var preferredInstall = package.Identity.Equals(preferredIdentity, StringComparison.OrdinalIgnoreCase);
            var baselineDeviation = preferredPackage is not null && !preferredInstall &&
                                    package.ApiLevel == preferredPackage.ApiLevel &&
                                    package.Version.Equals(preferredPackage.Version, StringComparison.OrdinalIgnoreCase) &&
                                    !string.IsNullOrWhiteSpace(package.Sha256) &&
                                    !string.IsNullOrWhiteSpace(preferredPackage.Sha256) &&
                                    !package.Sha256.Equals(preferredPackage.Sha256, StringComparison.OrdinalIgnoreCase);
            DrawProductSourcePackage(package, currentApi, preferredInstall, baselineDeviation);
        }

        ImGui.Unindent(14f);
    }

    private IReadOnlyList<ProductSourcePackage> BuildProductSourcePackages(MarketplacePlugin plugin, int currentApi, Version currentDalamudVersion)
    {
        var variants = new[] { plugin }
            .Concat(catalog.GetPresentationVariants(plugin.InternalName))
            .Where(x => !string.IsNullOrWhiteSpace(x.InternalName))
            .GroupBy(
                x => $"{NormalizeUrl(x.SourceUrl)}\u001f{x.AssemblyVersionText}\u001f{x.TestingAssemblyVersionText}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .ToArray();

        var baseline = ResolveProductBaselineVariant(plugin, currentApi, currentDalamudVersion);
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
                    isTesting: false,
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
                    isTesting: true,
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
                    .OrderBy(x => RepositoryProviderRules.SortPriority(
                        x.SourceName,
                        x.SourceUrl,
                        x.Official,
                        catalog.GetRepositoryStatus(x.SourceUrl, currentApi)?.PluginCount ?? 0))
                    .ThenByDescending(x => catalog.GetRepositoryStatus(x.SourceUrl, currentApi)?.PluginCount ?? 0)
                    .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var first = ordered[0];
                var repositories = ordered
                    .GroupBy(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase)
                    .Select(x => x.First())
                    .OrderBy(x => RepositoryProviderRules.SortPriority(
                        x.SourceName,
                        x.SourceUrl,
                        x.Official,
                        catalog.GetRepositoryStatus(x.SourceUrl, currentApi)?.PluginCount ?? 0))
                    .ThenByDescending(x => catalog.GetRepositoryStatus(x.SourceUrl, currentApi)?.PluginCount ?? 0)
                    .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
                    .Select(x => new ProductPackageRepository(
                        string.IsNullOrWhiteSpace(x.SourceName) ? "Unnamed repository" : x.SourceName,
                        x.SourceUrl,
                        x.Official,
                        CompareRepositorySecurity(x.Variant, baseline)))
                    .ToArray();
                var isTestingOnly = ordered.All(x => x.IsTesting);
                var version = ordered.Select(x => x.Version).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "—";
                var api = ordered.Select(x => x.ApiLevel).FirstOrDefault(x => x > 0);
                var sha = ordered.Select(x => x.Sha256).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? string.Empty;
                return new ProductSourcePackage(
                    group.Key,
                    isTestingOnly,
                    version,
                    api,
                    first.DownloadUrl,
                    sha,
                    repositories);
            })
            .OrderByDescending(x => x.Repositories.Any(r => r.Official))
            .ThenBy(x => x.IsTestingOnly)
            .ThenByDescending(x => Version.TryParse(x.Version, out var version) ? version : new Version(0, 0))
            .ThenBy(x => x.Identity, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static ProductPackageCandidate CreateProductPackageCandidate(
        MarketplacePlugin variant,
        bool isTesting,
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
            isTesting,
            version,
            apiLevel,
            downloadUrl,
            normalizedSha,
            variant.SourceName,
            variant.SourceUrl,
            variant.SourceIsOfficial,
            variant);
    }

    private static string NormalizePackageUrl(string? value)
        => (value ?? string.Empty).Trim().TrimEnd('/');

    private string ResolvePreferredInstallPackageIdentity(
        MarketplacePlugin plugin,
        IReadOnlyList<ProductSourcePackage> packages,
        int currentApi,
        Version currentDalamudVersion)
    {
        var preferred = GetInstallCandidates(plugin.InternalName, currentApi, currentDalamudVersion).FirstOrDefault();
        if (preferred is null || !preferred.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out var useTesting))
            return string.Empty;

        var version = useTesting
            ? preferred.TestingAssemblyVersionText ?? preferred.AssemblyVersionText
            : preferred.AssemblyVersionText;
        return packages.FirstOrDefault(package =>
            package.ApiLevel == currentApi &&
            package.Version.Equals(version, StringComparison.OrdinalIgnoreCase) &&
            package.Repositories.Any(repository => NormalizeUrl(repository.Url)
                .Equals(NormalizeUrl(preferred.SourceUrl), StringComparison.OrdinalIgnoreCase)))?.Identity ?? string.Empty;
    }

    private void DrawProductSourcePackage(ProductSourcePackage package, int currentApi, bool preferredInstall, bool baselineDeviation)
    {
        var versionText = string.IsNullOrWhiteSpace(package.Version) ? "Version unknown" : $"v{package.Version}";
        var repoText = $"{package.Repositories.Count} repositor{(package.Repositories.Count == 1 ? "y" : "ies")}";
        var visibleLabel = $"{versionText} · {repoText}";
        var label = $"{visibleLabel}##package-{StableId(package.Identity)}";

        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, MarketplaceLayoutRules.ControlCornerRadius);
        if (package.IsTestingOnly)
        {
            ImGui.PushStyleColor(ImGuiCol.Header, new Vector4(0.23f, 0.20f, 0.07f, 0.74f));
            ImGui.PushStyleColor(ImGuiCol.HeaderHovered, new Vector4(0.30f, 0.26f, 0.08f, 0.86f));
            ImGui.PushStyleColor(ImGuiCol.HeaderActive, new Vector4(0.34f, 0.29f, 0.09f, 0.92f));
        }
        else if (preferredInstall)
        {
            ImGui.PushStyleColor(ImGuiCol.Header, new Vector4(0.07f, 0.24f, 0.13f, 0.76f));
            ImGui.PushStyleColor(ImGuiCol.HeaderHovered, new Vector4(0.09f, 0.31f, 0.17f, 0.88f));
            ImGui.PushStyleColor(ImGuiCol.HeaderActive, new Vector4(0.10f, 0.35f, 0.19f, 0.94f));
        }
        else if (baselineDeviation)
        {
            ImGui.PushStyleColor(ImGuiCol.Header, new Vector4(0.30f, 0.07f, 0.08f, 0.76f));
            ImGui.PushStyleColor(ImGuiCol.HeaderHovered, new Vector4(0.38f, 0.09f, 0.10f, 0.88f));
            ImGui.PushStyleColor(ImGuiCol.HeaderActive, new Vector4(0.43f, 0.10f, 0.11f, 0.94f));
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Header, new Vector4(0.08f, 0.09f, 0.11f, 0.72f));
            ImGui.PushStyleColor(ImGuiCol.HeaderHovered, new Vector4(0.12f, 0.13f, 0.16f, 0.84f));
            ImGui.PushStyleColor(ImGuiCol.HeaderActive, new Vector4(0.14f, 0.15f, 0.18f, 0.90f));
        }

        var open = ImGui.TreeNodeEx(label, ImGuiTreeNodeFlags.Framed | ImGuiTreeNodeFlags.SpanAvailWidth);
        var headerMin = ImGui.GetItemRectMin();
        var headerMax = ImGui.GetItemRectMax();
        ImGui.PopStyleColor(3);
        ImGui.PopStyleVar();

        if (package.IsTestingOnly)
            DrawProductTestingPackageIcon(headerMin, headerMax);
        else if (baselineDeviation)
            DrawProductBaselineDeviationIcon(headerMin, headerMax);

        if (!open)
            return;

        ImGui.Indent(12f);
        if (baselineDeviation)
        {
            ImGui.TextColored(new Vector4(0.94f, 0.28f, 0.26f, 1f), "Artifact differs from the preferred package baseline");
            ImGui.Spacing();
        }
        ImGui.TextDisabled(package.ApiLevel > 0 ? $"API: {package.ApiLevel}" : "API: unknown");

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
            if (repository.SecurityComparison.Worse)
                ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.94f, 0.28f, 0.26f, 1f));
            DrawRepositoryName(repository.Name, repository.Url, repository.Official, currentApi);
            if (repository.SecurityComparison.Worse)
                ImGui.PopStyleColor();
            if (ImGui.IsItemHovered() && !string.IsNullOrWhiteSpace(repository.Url))
                ImGui.SetTooltip(repository.SecurityComparison.Different
                    ? repository.SecurityComparison.Tooltip
                    : repository.Url);

            DrawRepositorySecurityDifferenceIndicator(repository.SecurityComparison);

            if (!string.IsNullOrWhiteSpace(repository.Url))
            {
                ImGui.SameLine(0f, 8f);
                if (repository.SecurityComparison.Worse)
                    ImGui.TextColored(new Vector4(0.94f, 0.28f, 0.26f, 1f), PackageLocationLabel(repository.Url));
                else
                    ImGui.TextDisabled(PackageLocationLabel(repository.Url));
                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip(repository.SecurityComparison.Different
                        ? repository.SecurityComparison.Tooltip
                        : repository.Url);
            }
        }
        ImGui.Unindent(12f);
        ImGui.TreePop();
        ImGui.Spacing();
    }

    private static void DrawProductTestingPackageIcon(Vector2 headerMin, Vector2 headerMax)
    {
        var draw = ImGui.GetWindowDrawList();
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = FontAwesomeIcon.Flask.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        var iconPosition = new Vector2(
            headerMax.X - glyphSize.X - 10f,
            headerMin.Y + Math.Max(0f, (headerMax.Y - headerMin.Y - glyphSize.Y) * 0.5f));
        draw.AddText(iconPosition, 0xFFE3D36Bu, glyph);
        ImGui.PopFont();
    }

    private static void DrawProductBaselineDeviationIcon(Vector2 headerMin, Vector2 headerMax)
    {
        var draw = ImGui.GetWindowDrawList();
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = FontAwesomeIcon.ExclamationTriangle.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        var iconPosition = new Vector2(
            headerMax.X - glyphSize.X - 10f,
            headerMin.Y + Math.Max(0f, (headerMax.Y - headerMin.Y - glyphSize.Y) * 0.5f));
        draw.AddText(iconPosition, 0xFF4444EEu, glyph);
        ImGui.PopFont();
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

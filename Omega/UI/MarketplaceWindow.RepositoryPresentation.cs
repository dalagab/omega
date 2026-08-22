using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private RepositoryProviderPresentation GetRepositoryProvider(
        string sourceName,
        string sourceUrl,
        bool official,
        int currentApi)
    {
        var count = catalog.GetRepositoryStatus(sourceUrl, currentApi)?.PluginCount ?? 0;
        return RepositoryProviderRules.Classify(sourceName, sourceUrl, official, count);
    }

    private void DrawRepositoryName(
        string sourceName,
        string sourceUrl,
        bool official,
        int currentApi,
        bool disabled = false)
    {
        var provider = GetRepositoryProvider(sourceName, sourceUrl, official, currentApi);
        DrawRepositoryProviderIcon(provider, 18f);
        if (!string.IsNullOrWhiteSpace(provider.IconUrl))
            ImGui.SameLine(0f, 7f);

        var name = string.IsNullOrWhiteSpace(sourceName) ? "Unnamed repository" : sourceName;
        if (disabled)
            ImGui.TextDisabled(name);
        else
            ImGui.TextUnformatted(name);

    }

    private string RepositoryStateLabel(string sourceName, string sourceUrl, bool official)
        => !official && !catalog.IsSourceInDefinitions(sourceUrl)
            ? "Unmanaged local"
            : RepositoryProviderRules.TrustLabel(sourceName, sourceUrl, official);

    private void DrawRepositoryTrustLabel(string sourceName, string sourceUrl, bool official)
    {
        var unmanaged = !official && !catalog.IsSourceInDefinitions(sourceUrl);
        var label = RepositoryStateLabel(sourceName, sourceUrl, official);
        var color = official
            ? new Vector4(0.35f, 0.78f, 0.92f, 1f)
            : unmanaged
                ? new Vector4(0.34f, 0.64f, 0.98f, 1f)
                : RepositoryProviderRules.IsStableProvider(sourceName, sourceUrl, official)
                    ? new Vector4(0.38f, 0.78f, 0.52f, 1f)
                    : new Vector4(0.95f, 0.64f, 0.20f, 1f);
        ImGui.TextColored(color, label);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(official
                ? "Built into Dalamud."
                : unmanaged
                    ? "Configured in Dalamud; not in Omega Definitions."
                    : RepositoryProviderRules.IsStableProvider(sourceName, sourceUrl, official)
                        ? "Recognized community source."
                        : configuration.TrustUnrecognizedSources
                            ? "Unrecognized community source. You chose to skip the generic source acknowledgement; Omega still reports security, permission, package, compatibility, and support concerns."
                            : "Unrecognized community source; acknowledgement required before install.");
    }

    private void DrawRepositoryProviderIcon(RepositoryProviderPresentation provider, float size)
    {
        if (provider.Kind == RepositoryProviderKind.Dalamud)
        {
            // Use Dalamud's shipped mark everywhere instead of the Goatcorp avatar, which carries
            // a dark-red square background and reads like a warning state in Omega.
            DrawDalamudOfficialLogoBadge(size);
            return;
        }

        if (string.IsNullOrWhiteSpace(provider.IconUrl))
            return;

        var texture = iconCache.GetOrQueue(provider.IconUrl);
        if (texture is not null && texture.Size.X > 0 && texture.Size.Y > 0)
        {
            ImGui.Image(texture.Handle, new Vector2(size, size));
            return;
        }

        // Reserve the exact icon slot while the shared image cache resolves the remote provider mark.
        ImGui.Dummy(new Vector2(size, size));
    }

    private void DrawAuthorRepositoryLine(MarketplacePlugin plugin, int currentApi)
    {
        var author = string.IsNullOrWhiteSpace(plugin.Author) ? "Installed plugin" : plugin.Author;
        ImGui.TextDisabled(Shorten(author, 28));
        ImGui.SameLine(0f, 6f);
        ImGui.TextDisabled("•");
        ImGui.SameLine(0f, 6f);
        DrawRepositoryName(
            SourceLabel(plugin),
            plugin.SourceUrl,
            plugin.SourceIsOfficial,
            currentApi,
            disabled: true);
    }


    private MarketplacePlugin ResolveInstalledVariant(MarketplacePlugin fallback, IExposedPlugin installedPlugin)
    {
        var installedUrl = NormalizeUrl(installedPlugin.Manifest.InstalledFromUrl);
        var installedVersion = installedPlugin.Version;
        if (!string.IsNullOrWhiteSpace(installedUrl))
        {
            var variants = catalog.GetVariants(fallback.InternalName);
            var exact = variants.FirstOrDefault(variant =>
                NormalizeUrl(variant.SourceUrl).Equals(installedUrl, StringComparison.OrdinalIgnoreCase) &&
                (installedVersion is null || variant.AssemblyVersion.Equals(installedVersion)));
            if (exact is not null)
                return exact;

            var sameSource = variants.FirstOrDefault(variant =>
                NormalizeUrl(variant.SourceUrl).Equals(installedUrl, StringComparison.OrdinalIgnoreCase));
            if (sameSource is not null)
                return sameSource;
        }
        return fallback;
    }

    private void DrawInstalledAuthorRepositoryLine(MarketplacePlugin fallback, IExposedPlugin installedPlugin, int currentApi)
    {
        var plugin = ResolveInstalledVariant(fallback, installedPlugin);
        var installedUrl = NormalizeUrl(installedPlugin.Manifest.InstalledFromUrl);
        var authorText = string.IsNullOrWhiteSpace(plugin.Author) ? "Installed plugin" : plugin.Author;
        ImGui.TextDisabled(Shorten(authorText, 28));
        ImGui.SameLine(0f, 6f);
        ImGui.TextDisabled("•");
        ImGui.SameLine(0f, 6f);

        if (!string.IsNullOrWhiteSpace(installedUrl) &&
            !NormalizeUrl(plugin.SourceUrl).Equals(installedUrl, StringComparison.OrdinalIgnoreCase))
        {
            var name = Uri.TryCreate(installedPlugin.Manifest.InstalledFromUrl, UriKind.Absolute, out var uri)
                ? uri.Host
                : "Installed source";
            DrawRepositoryName(name, installedPlugin.Manifest.InstalledFromUrl ?? string.Empty, false, currentApi, disabled: true);
            return;
        }

        DrawRepositoryName(SourceLabel(plugin), plugin.SourceUrl, plugin.SourceIsOfficial, currentApi, disabled: true);
    }

    private void DrawProductRepositoryMetadataRow(MarketplacePlugin plugin, int currentApi)
    {
        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        ImGui.TextDisabled("Source");
        ImGui.TableSetColumnIndex(1);
        DrawRepositoryName(
            SourceLabel(plugin),
            plugin.SourceUrl,
            plugin.SourceIsOfficial,
            currentApi);
        if (ImGui.IsItemHovered() && !string.IsNullOrWhiteSpace(plugin.SourceUrl))
            ImGui.SetTooltip(plugin.SourceUrl);
        ImGui.SameLine(0f, Ui(8f));
        ImGui.TextDisabled("•");
        ImGui.SameLine(0f, Ui(8f));
        DrawRepositoryTrustLabel(SourceLabel(plugin), plugin.SourceUrl, plugin.SourceIsOfficial);
    }

    private bool DrawRepositoryActionButton(
        string sourceName,
        string sourceUrl,
        bool official,
        int currentApi,
        string trailingText,
        string id,
        Vector2 size,
        bool selected)
    {
        var provider = GetRepositoryProvider(sourceName, sourceUrl, official, currentApi);
        var hasIcon = !string.IsNullOrWhiteSpace(provider.IconUrl);
        var visibleText = string.IsNullOrWhiteSpace(trailingText)
            ? sourceName
            : $"{sourceName}  •  {trailingText}";

        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, MarketplaceLayoutRules.ControlCornerRadius);
        if (selected)
        {
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.03f, 0.42f, 0.44f, 0.94f));
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.04f, 0.50f, 0.52f, 1f));
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0.03f, 0.34f, 0.36f, 1f));
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.08f, 0.10f, 0.13f, 0.94f));
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.12f, 0.15f, 0.18f, 1f));
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0.10f, 0.13f, 0.16f, 1f));
        }

        var clicked = ImGui.Button($"##repository-action-{id}", size);
        var min = ImGui.GetItemRectMin();
        var draw = ImGui.GetWindowDrawList();
        var textSize = ImGui.CalcTextSize(visibleText);
        var cursorX = min.X + 12f;
        if (hasIcon)
        {
            var iconSize = Math.Min(18f, size.Y - 8f);
            var iconY = min.Y + Math.Max(Ui(4f), (size.Y - iconSize) * 0.5f);
            if (provider.Kind == RepositoryProviderKind.Dalamud)
            {
                try
                {
                    var texture = Plugin.DalamudAssets.GetDalamudTextureWrap(global::Dalamud.DalamudAsset.LogoSmall);
                    var sourceSize = texture.Size;
                    var scale = Math.Min(iconSize / sourceSize.X, iconSize / sourceSize.Y);
                    var drawSize = sourceSize * scale;
                    var imageMin = new Vector2(
                        cursorX + ((iconSize - drawSize.X) * 0.5f),
                        iconY + ((iconSize - drawSize.Y) * 0.5f));
                    draw.AddImage(texture.Handle, imageMin, imageMin + drawSize);
                }
                catch
                {
                    // Keep the reserved icon slot if the shared Dalamud asset is temporarily unavailable.
                }
            }
            else
            {
                var texture = iconCache.GetOrQueue(provider.IconUrl);
                if (texture is not null && texture.Size.X > 0 && texture.Size.Y > 0)
                    draw.AddImage(texture.Handle, new Vector2(cursorX, iconY), new Vector2(cursorX + iconSize, iconY + iconSize));
            }
            cursorX += Ui(23f);
        }
        draw.AddText(
            new Vector2(cursorX, min.Y + Math.Max(0f, (size.Y - textSize.Y) * 0.5f)),
            ImGui.GetColorU32(ImGuiCol.Text),
            visibleText);

        ImGui.PopStyleColor(3);
        ImGui.PopStyleVar();
        return clicked;
    }

}

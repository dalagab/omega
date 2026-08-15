using System.Numerics;
using Dalamud.Bindings.ImGui;

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

    private void DrawRepositoryProviderIcon(RepositoryProviderPresentation provider, float size)
    {
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
            var texture = iconCache.GetOrQueue(provider.IconUrl);
            if (texture is not null && texture.Size.X > 0 && texture.Size.Y > 0)
            {
                var iconSize = Math.Min(18f, size.Y - 8f);
                var iconY = min.Y + Math.Max(4f, (size.Y - iconSize) * 0.5f);
                draw.AddImage(texture.Handle, new Vector2(cursorX, iconY), new Vector2(cursorX + iconSize, iconY + iconSize));
            }
            cursorX += 23f;
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

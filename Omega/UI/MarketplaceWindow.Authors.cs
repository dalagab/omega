using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawProductAuthors(MarketplacePlugin plugin)
    {
        var authors = plugin.EffectiveAuthors;
        if (authors.Count == 0)
        {
            ImGui.TextDisabled(string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author);
            return;
        }

        for (var index = 0; index < authors.Count; index++)
        {
            if (index > 0)
            {
                ImGui.SameLine(0f, 5f);
                ImGui.TextDisabled("•");
                ImGui.SameLine(0f, 5f);
            }

            var name = authors[index];
            ImGui.PushID($"product-author-{StableId(name)}-{index}");
            ImGui.TextColored(new System.Numerics.Vector4(0.36f, 0.78f, 0.86f, 1f), name);
            var hovered = ImGui.IsItemHovered();
            if (hovered)
                SetReadableTooltip($"Show all plugins by {name}");
            if (hovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left))
                OpenAuthorInDiscover(name);
            ImGui.PopID();
        }
    }

    private void OpenAuthorInDiscover(string authorName)
    {
        ResetFilters();
        selectedAuthors.Clear();
        AddSelectedAuthor(authorName);
        activeView = MarketplaceView.Discover;
        detailsOpen = false;
        selectedPlugin = null;
        filtersOpen = true;
        resetStorefrontScroll = true;
    }
}

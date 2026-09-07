using System.Diagnostics;
using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawProductReadme(MarketplacePresentationContent content)
    {
        var readme = content.Readme.Trim();
        if (string.IsNullOrWhiteSpace(readme))
            return;

        DrawProductSectionHeading("Project README");
        ImGui.Indent(14f);
        DrawMarketplaceMarkupText(readme, "readme");

        ImGui.Unindent(14f);
    }

    private void DrawMarketplaceMarkupText(string text, string idPrefix, int maximumBlocks = 160)
    {
        var blocks = MarketplaceReadmeMarkup.Parse(text);
        for (var index = 0; index < Math.Min(blocks.Count, maximumBlocks); index++)
            DrawProductReadmeBlock(blocks[index], index, idPrefix);
    }

    private void DrawProductReadmeBlock(MarketplaceReadmeBlock block, int index, string idPrefix = "readme")
    {
        var wrap = ImGui.GetCursorPosX() + Math.Max(Ui(320f), Math.Min(Ui(940f), ImGui.GetContentRegionAvail().X));
        switch (block.Kind)
        {
            case MarketplaceReadmeBlockKind.Heading:
                ImGui.Dummy(new Vector2(Ui(1f), Ui(block.Level <= 2 ? 8f : 4f)));
                ImGui.TextUnformatted(block.Text);
                if (block.Level <= 2)
                    ImGui.Separator();
                ImGui.Dummy(new Vector2(Ui(1f), Ui(3f)));
                break;
            case MarketplaceReadmeBlockKind.Bullet:
                ImGui.Bullet();
                ImGui.SameLine();
                ImGui.PushTextWrapPos(wrap);
                ImGui.TextWrapped(block.Text);
                ImGui.PopTextWrapPos();
                break;
            case MarketplaceReadmeBlockKind.Numbered:
                ImGui.PushTextWrapPos(wrap);
                ImGui.TextWrapped($"{Math.Max(1, block.Level)}. {block.Text}");
                ImGui.PopTextWrapPos();
                break;
            case MarketplaceReadmeBlockKind.Quote:
                ImGui.Indent(12f);
                ImGui.PushTextWrapPos(wrap);
                ImGui.TextDisabled(block.Text);
                ImGui.PopTextWrapPos();
                ImGui.Unindent(12f);
                break;
            case MarketplaceReadmeBlockKind.Code:
                ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.025f, 0.030f, 0.038f, 0.88f));
                var codeLines = Math.Clamp(block.Text.Count(ch => ch == '\n') + 1, 1, 14);
                ImGui.BeginChild($"{idPrefix}-code-{index}-{StableId(block.Text)}", new Vector2(Math.Min(Ui(940f), ImGui.GetContentRegionAvail().X), Ui(12f) + (codeLines * ImGui.GetTextLineHeightWithSpacing())), true, ImGuiWindowFlags.HorizontalScrollbar);
                ImGui.TextUnformatted(block.Text);
                ImGui.EndChild();
                ImGui.PopStyleColor();
                ImGui.Dummy(new Vector2(Ui(1f), Ui(4f)));
                break;
            case MarketplaceReadmeBlockKind.Rule:
                ImGui.Separator();
                ImGui.Dummy(new Vector2(Ui(1f), Ui(4f)));
                break;
            default:
                if (!string.IsNullOrWhiteSpace(block.Text))
                {
                    ImGui.PushTextWrapPos(wrap);
                    ImGui.TextWrapped(block.Text);
                    ImGui.PopTextWrapPos();
                }
                ImGui.Dummy(new Vector2(Ui(1f), Ui(4f)));
                break;
        }

        DrawMarketplaceMarkupLinks(block, index, idPrefix);
    }

    private void DrawMarketplaceMarkupLinks(MarketplaceReadmeBlock block, int index, string idPrefix)
    {
        if (block.Links is not { Count: > 0 })
            return;

        var first = true;
        for (var linkIndex = 0; linkIndex < Math.Min(block.Links.Count, 6); linkIndex++)
        {
            var link = block.Links[linkIndex];
            if (!Uri.TryCreate(link.Url, UriKind.Absolute, out var uri) ||
                !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!first)
                ImGui.SameLine(0f, Ui(7f));

            var label = string.IsNullOrWhiteSpace(link.Label) ? "Open link" : link.Label.Trim();
            var buttonLabel = label.Length > 34 ? label[..31] + "…" : label;
            var width = Math.Clamp(ImGui.CalcTextSize(buttonLabel).X + Ui(26f), Ui(82f), Ui(220f));
            var discord = uri.Host.Equals("discord.gg", StringComparison.OrdinalIgnoreCase) ||
                          uri.Host.EndsWith("discord.com", StringComparison.OrdinalIgnoreCase);
            if (DrawPillButton(
                    buttonLabel,
                    $"{idPrefix}-link-{index}-{linkIndex}-{StableId(link.Url)}",
                    new Vector2(width, Ui(27f)),
                    discord))
            {
                try
                {
                    Process.Start(new ProcessStartInfo(link.Url) { UseShellExecute = true });
                }
                catch (Exception ex)
                {
                    Plugin.Log.Debug(ex, "Omega could not open README link {Url}.", link.Url);
                    operationMessage = "Could not open this project link.";
                }
            }
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(link.Url);
            first = false;
        }

        if (!first)
            ImGui.Dummy(new Vector2(Ui(1f), Ui(5f)));
    }
}

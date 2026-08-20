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
                ImGui.PushTextWrapPos(wrap);
                ImGui.TextWrapped(block.Text);
                ImGui.PopTextWrapPos();
                ImGui.Dummy(new Vector2(Ui(1f), Ui(4f)));
                break;
        }
    }
}

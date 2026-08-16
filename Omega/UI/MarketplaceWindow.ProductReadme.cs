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
        ImGui.TextDisabled("Fetched from the project's public repository.");
        ImGui.Dummy(new Vector2(1f, 5f));
        ImGui.PushTextWrapPos(ImGui.GetCursorPosX() + Math.Max(320f, Math.Min(940f, ImGui.GetContentRegionAvail().X)));
        ImGui.TextWrapped(readme);
        ImGui.PopTextWrapPos();
        ImGui.Unindent(14f);
    }
}

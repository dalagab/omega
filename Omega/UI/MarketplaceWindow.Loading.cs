using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawCatalogLoadingState()
    {
        var available = ImGui.GetContentRegionAvail();
        var origin = ImGui.GetCursorScreenPos();
        var width = MathF.Max(0f, available.X);
        var height = MathF.Max(0f, available.Y);
        var center = origin + new Vector2(width * 0.5f, height * 0.5f);

        const float radius = 15f;
        const float dotRadius = 3.5f;
        const float thickness = 2.25f;
        var draw = ImGui.GetWindowDrawList();
        draw.AddCircle(center, radius, ImGui.GetColorU32(ImGuiCol.TextDisabled), 40, thickness);

        var cycle = (Environment.TickCount64 % 900L) / 900f;
        var angle = cycle * MathF.Tau - (MathF.PI * 0.5f);
        var dot = center + new Vector2(MathF.Cos(angle), MathF.Sin(angle)) * radius;
        draw.AddCircleFilled(dot, dotRadius, ImGui.GetColorU32(ImGuiCol.Text), 16);

        ImGui.Dummy(new Vector2(width, height));
    }
}

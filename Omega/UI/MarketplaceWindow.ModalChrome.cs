using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

/// <summary>
/// Shared chrome for Omega-owned secondary panels. These panels deliberately avoid the host/default
/// ImGui title bar so Settings, screenshots and action dialogs keep the same visual language as the
/// main marketplace window.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private const float OmegaModalHeaderHeight = 42f;
    private const float OmegaModalMarkSize = 20f;

    private bool DrawOmegaModalHeader(string title, string id, bool allowClose = true, bool showMark = true)
    {
        var closeClicked = false;
        ImGui.BeginChild($"omega-modal-header-{id}", new Vector2(0f, Ui(OmegaModalHeaderHeight)), false,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var titleX = Ui(2f);
        if (showMark)
        {
            var iconY = (Ui(OmegaModalHeaderHeight) - Ui(OmegaModalMarkSize)) * 0.5f;
            ImGui.SetCursorPos(new Vector2(Ui(2f), iconY));
            var iconMin = ImGui.GetCursorScreenPos();
            ImGui.Dummy(Ui(OmegaModalMarkSize, OmegaModalMarkSize));
            var texture = omegaIconTexture?.GetWrapOrDefault();
            if (texture is not null)
                ImGui.GetWindowDrawList().AddImage(texture.Handle, iconMin, iconMin + Ui(OmegaModalMarkSize, OmegaModalMarkSize));
            else
            {
                const string glyph = "Ω";
                var glyphSize = ImGui.CalcTextSize(glyph);
                ImGui.GetWindowDrawList().AddText(
                    iconMin + new Vector2((Ui(OmegaModalMarkSize) - glyphSize.X) * 0.5f, (Ui(OmegaModalMarkSize) - glyphSize.Y) * 0.5f),
                    ImGui.GetColorU32(ImGuiCol.Text),
                    glyph);
            }
            titleX = Ui(OmegaModalMarkSize + 14f);
        }

        ImGui.SetCursorPos(new Vector2(titleX, (Ui(OmegaModalHeaderHeight) - ImGui.GetTextLineHeight()) * 0.5f));
        ImGui.TextUnformatted(title);

        if (allowClose)
        {
            ImGui.SetCursorPos(new Vector2(
                Math.Max(titleX + Ui(120f), ImGui.GetWindowWidth() - Ui(AppBarControlSize) - Ui(2f)),
                (Ui(OmegaModalHeaderHeight) - Ui(AppBarControlSize)) * 0.5f));
            closeClicked = DrawApplicationIconButton(FontAwesomeIcon.Times, $"modal-{id}-close", $"Close {title}", true);
        }

        ImGui.EndChild();
        ImGui.Spacing();
        return closeClicked;
    }
}

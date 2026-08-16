using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const string ScreenshotPopupId = "Screenshot###DalagabOmegaScreenshot";

    private void OpenScreenshotViewer(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return;

        selectedScreenshotUrl = url;
        requestScreenshotPopup = true;
    }

    private void CloseScreenshotViewer()
    {
        selectedScreenshotUrl = string.Empty;
        ImGui.CloseCurrentPopup();
    }

    private void DrawScreenshotViewerModal()
    {
        if (string.IsNullOrWhiteSpace(selectedScreenshotUrl))
            return;

        var viewport = ImGui.GetMainViewport();
        var preferredSize = new Vector2(
            Math.Min(1280f, Math.Max(700f, viewport.Size.X * 0.84f)),
            Math.Min(900f, Math.Max(520f, viewport.Size.Y * 0.84f)));
        ImGui.SetNextWindowSize(preferredSize, ImGuiCond.Appearing);

        var keepOpen = true;
        if (!ImGui.BeginPopupModal(
                ScreenshotPopupId,
                ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse))
        {
            if (!keepOpen)
                selectedScreenshotUrl = string.Empty;
            return;
        }

        if (DrawOmegaModalHeader("Screenshot", "screenshot"))
        {
            CloseScreenshotViewer();
            ImGui.EndPopup();
            return;
        }

        var texture = iconCache.GetOrQueue(selectedScreenshotUrl);
        var imageArea = new Vector2(
            Math.Max(120f, ImGui.GetContentRegionAvail().X),
            Math.Max(120f, ImGui.GetContentRegionAvail().Y));

        if (texture is null || texture.Size.X <= 0 || texture.Size.Y <= 0)
        {
            ImGui.BeginChild(
                "screenshot-viewer-loading",
                imageArea,
                true,
                ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
            var text = "Loading screenshot…";
            var size = ImGui.CalcTextSize(text);
            SetCursorCenteredInCurrentContent(size);
            ImGui.TextDisabled(text);
            ImGui.EndChild();
        }
        else
        {
            ImGui.BeginChild(
                "screenshot-viewer-image",
                imageArea,
                true,
                ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
            var contentSize = ImGui.GetWindowContentRegionMax() - ImGui.GetWindowContentRegionMin();
            var scale = Math.Min(contentSize.X / texture.Size.X, contentSize.Y / texture.Size.Y);
            var size = texture.Size * scale;
            SetCursorCenteredInCurrentContent(size);
            ImGui.Image(texture.Handle, size);
            ImGui.EndChild();
        }

        ImGui.EndPopup();

        if (!keepOpen)
            selectedScreenshotUrl = string.Empty;
    }
}

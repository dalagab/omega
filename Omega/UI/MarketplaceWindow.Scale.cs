using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface.Utility;

namespace Dalagab.Omega;

/// <summary>
/// Centralises geometry scaling for Omega's immediate-mode UI. Dalamud scales fonts with the
/// configured global UI scale, but raw ImGui child sizes, cursor offsets and custom-drawn chrome
/// still need to be scaled by the plugin. Keeping those conversions here prevents a 150-200%
/// interface scale from leaving large text trapped inside 100%-sized cards and rows.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private const float MinimumSupportedUiScale = 0.75f;
    private const float MaximumSupportedUiScale = 2.25f;

    private static float OmegaUiScale
        => Math.Clamp(ImGuiHelpers.GlobalScale, MinimumSupportedUiScale, MaximumSupportedUiScale);

    private static float Ui(float logicalPixels)
        => logicalPixels * OmegaUiScale;

    private static Vector2 Ui(float logicalX, float logicalY)
        => new(Ui(logicalX), Ui(logicalY));

    private static Vector2 Ui(Vector2 logicalSize)
        => logicalSize * OmegaUiScale;

    private static Vector2 UiModalSize(float logicalWidth, float logicalHeight)
    {
        var work = ImGui.GetMainViewport().WorkSize * 0.92f;
        var width = Math.Min(Ui(logicalWidth), work.X);
        var height = logicalHeight <= 0f ? 0f : Math.Min(Ui(logicalHeight), work.Y);
        return new Vector2(width, height);
    }

    private static Vector2 ResponsiveDefaultWindowLogicalSize()
    {
        var viewport = ImGui.GetMainViewport();
        var scale = Math.Max(0.01f, OmegaUiScale);
        var physicalLimit = viewport.WorkSize * 0.90f;
        return new Vector2(
            Math.Min(DefaultExpandedWindowSize.X, physicalLimit.X / scale),
            Math.Min(DefaultExpandedWindowSize.Y, physicalLimit.Y / scale));
    }

    private static Vector2 ResponsiveMinimumWindowLogicalSize()
    {
        var viewport = ImGui.GetMainViewport();
        var scale = Math.Max(0.01f, OmegaUiScale);
        var physicalLimit = viewport.WorkSize * 0.84f;
        return new Vector2(
            Math.Min(DefaultExpandedWindowSize.X, physicalLimit.X / scale),
            Math.Min(DefaultExpandedWindowSize.Y, physicalLimit.Y / scale));
    }

    private static int ResponsiveColumns(
        float availableWidth,
        float minimumLogicalCardWidth,
        int maximumColumns,
        float logicalGap)
    {
        if (maximumColumns <= 1)
            return 1;

        var gap = Ui(logicalGap);
        var minimumWidth = Ui(minimumLogicalCardWidth);
        var fitted = (int)MathF.Floor((Math.Max(1f, availableWidth) + gap) / (minimumWidth + gap));
        return Math.Clamp(fitted, 1, maximumColumns);
    }

    private static float ResponsiveCardWidth(
        float availableWidth,
        int columns,
        float logicalGap,
        float minimumLogicalWidth,
        float maximumLogicalWidth = float.MaxValue)
    {
        columns = Math.Max(1, columns);
        var gap = Ui(logicalGap);
        var width = (Math.Max(1f, availableWidth) - (gap * (columns - 1))) / columns;
        var minimum = Ui(minimumLogicalWidth);
        var maximum = maximumLogicalWidth == float.MaxValue ? float.MaxValue : Ui(maximumLogicalWidth);
        return Math.Clamp(width, Math.Min(minimum, width), Math.Max(Math.Min(minimum, width), maximum));
    }
}

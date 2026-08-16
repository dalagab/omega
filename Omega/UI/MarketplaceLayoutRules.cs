namespace Dalagab.Omega;

/// <summary>
/// Pure geometry rules shared by Omega's list and collection surfaces.
/// Keeping these calculations outside the immediate-mode draw code makes the
/// row geometry deterministic and regression-testable without an ImGui runtime.
/// </summary>
internal static class MarketplaceLayoutRules
{
    public const float ControlCornerRadius = 6f;
    public const float LibraryRowHeight = 104f;
    public const float UpdatesRowHeight = 88f;
    public const float CollectionRowHeight = 88f;
    public const float ProductCollectionRowHeight = 36f;
    public const float ProductCollectionImpactLineHeight = 21f;
    public const float InstallSourceRowHeight = 98f;
    public const float RowRightPadding = 12f;

    public static float CenterY(float containerHeight, float itemHeight)
        => MathF.Max(0f, (containerHeight - itemHeight) * 0.5f);

    public static float RightAlignedX(float contentMaxX, float totalWidth, float rightPadding = RowRightPadding)
        => MathF.Max(0f, contentMaxX - totalWidth - rightPadding);

    public static bool FitsTextLines(float rowHeight, float verticalPadding, float lineHeight, int lineCount)
        => lineCount >= 0 && rowHeight >= (verticalPadding * 2f) + (lineHeight * lineCount);
}

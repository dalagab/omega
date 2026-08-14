namespace Dalagab.Omega;

internal readonly record struct StorefrontVisibleRows(
    int FirstRow,
    int LastRowExclusive,
    int TotalRows);

/// <summary>
/// Pure viewport math that limits ImGui submission to visible storefront rows plus a small buffer.
/// </summary>
internal static class StorefrontVirtualization
{
    public static StorefrontVisibleRows Calculate(
        int itemCount,
        int columns,
        float rowHeight,
        float scrollY,
        float viewportHeight,
        float contentStartY,
        int bufferRows = 1)
    {
        if (itemCount <= 0)
            return new StorefrontVisibleRows(0, 0, 0);

        columns = Math.Max(1, columns);
        rowHeight = Math.Max(1f, rowHeight);
        viewportHeight = Math.Max(1f, viewportHeight);
        bufferRows = Math.Max(0, bufferRows);

        var totalRows = (itemCount + columns - 1) / columns;
        var relativeTop = Math.Max(0f, scrollY - contentStartY);
        var relativeBottom = Math.Max(relativeTop, scrollY + viewportHeight - contentStartY);

        var firstRow = Math.Max(0, (int)MathF.Floor(relativeTop / rowHeight) - bufferRows);
        var lastRowExclusive = Math.Min(
            totalRows,
            (int)MathF.Ceiling(relativeBottom / rowHeight) + bufferRows);

        if (lastRowExclusive <= firstRow)
            lastRowExclusive = Math.Min(totalRows, firstRow + 1);

        return new StorefrontVisibleRows(firstRow, lastRowExclusive, totalRows);
    }
}

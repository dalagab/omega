using System.Collections;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace RiftGameDataSemantics;

public sealed class Plugin : IDalamudPlugin
{
    public Plugin(IDataManager data, IPluginLog log)
    {
        var definition = typeof(IDataManager).GetMethods()
            .Single(m => m.Name == "GetExcelSheet" && m.IsGenericMethodDefinition);

        // Use Lumina's core RawRow rather than a separately generated sheet assembly.
        // RawRow lives in the same trusted Lumina
        // assembly as ExcelSheet<T> and satisfies IExcelRow<RawRow>, making this
        // fixture self-contained while still testing the real CLR constraints.
        var luminaAssembly = definition.ReturnType.GetGenericTypeDefinition().Assembly;
        var rawRowType = luminaAssembly.GetType("Lumina.Excel.RawRow", throwOnError: true)!;
        var closed = definition.MakeGenericMethod(rawRowType);

        var sheet = closed.Invoke(data, new object?[] { null, "RiftSynthetic" })
            ?? throw new InvalidOperationException("Rift returned null for constrained GetExcelSheet<T>.");

        var count = (int)(sheet.GetType().GetProperty("Count")?.GetValue(sheet)
            ?? throw new InvalidOperationException("Synthetic sheet does not expose Count."));
        if (count != 0)
            throw new InvalidOperationException($"Synthetic sheet must be empty, got Count={count}.");

        var hasRow = (bool)(sheet.GetType().GetMethod("HasRow")?.Invoke(sheet, new object[] { 116u })
            ?? throw new InvalidOperationException("Synthetic sheet does not expose HasRow."));
        if (hasRow)
            throw new InvalidOperationException("Synthetic sheet reported an unavailable row as present.");

        var tryGetRow = sheet.GetType().GetMethod("TryGetRow")
            ?? throw new InvalidOperationException("Synthetic sheet does not expose TryGetRow.");
        var tryGetArguments = new object?[] { 116u, null };
        if ((bool)tryGetRow.Invoke(sheet, tryGetArguments)!)
            throw new InvalidOperationException("Synthetic sheet returned an unavailable row.");

        var enumerable = sheet as IEnumerable
            ?? throw new InvalidOperationException("Synthetic sheet is not enumerable.");
        if (enumerable.GetEnumerator().MoveNext())
            throw new InvalidOperationException("Synthetic sheet unexpectedly exposed a row.");

        log.Information("RIFT_GAME_DATA empty sheet semantics complete");
    }

    public void Dispose() { }
}

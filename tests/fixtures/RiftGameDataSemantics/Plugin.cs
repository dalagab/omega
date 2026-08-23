using System.Collections;
using System.Reflection;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace RiftGameDataSemantics;

public sealed class Plugin : IDalamudPlugin
{
    public Plugin(IDataManager data, IPluginLog log)
    {
        var rowAssembly = Assembly.Load("Lumina.Excel.Sheets");
        var recipeType = rowAssembly.GetType("Lumina.Excel.Sheets.Recipe", throwOnError: true)!;

        var definition = typeof(IDataManager).GetMethods()
            .Single(m => m.Name == "GetExcelSheet" && m.IsGenericMethodDefinition);
        var closed = definition.MakeGenericMethod(recipeType);

        var sheet = closed.Invoke(data, new object?[] { null, null })
            ?? throw new InvalidOperationException("Rift returned null for constrained GetExcelSheet<T>.");

        var count = (int)(sheet.GetType().GetProperty("Count")?.GetValue(sheet)
            ?? throw new InvalidOperationException("Synthetic sheet does not expose Count."));
        if (count != 0)
            throw new InvalidOperationException($"Synthetic sheet must be empty, got Count={count}.");

        var enumerable = sheet as IEnumerable
            ?? throw new InvalidOperationException("Synthetic sheet is not enumerable.");
        if (enumerable.GetEnumerator().MoveNext())
            throw new InvalidOperationException("Synthetic sheet unexpectedly exposed a row.");

        log.Information("RIFT_GAME_DATA empty sheet semantics complete");
    }

    public void Dispose() { }
}

using System.Reflection;
using System.Runtime.CompilerServices;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Runtime;

/// <summary>
/// Builds deliberately empty Lumina sheet objects that preserve the real closed
/// generic types while never opening or parsing FFXIV game-data files.
/// </summary>
public static class SyntheticGameDataRuntime
{
    public static object CreateEmptySheet(Type closedSheetType, AccessTracker tracker, string operation)
    {
        if (!closedSheetType.IsGenericType)
            throw new ArgumentException($"Expected a closed Lumina sheet type, got {closedSheetType}.", nameof(closedSheetType));

        var definitionName = closedSheetType.GetGenericTypeDefinition().FullName;
        if (definitionName is not ("Lumina.Excel.ExcelSheet`1" or "Lumina.Excel.SubrowExcelSheet`1"))
            throw new ArgumentException($"Unsupported synthetic sheet type {closedSheetType}.", nameof(closedSheetType));

        var ctor = closedSheetType
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance)
            .SingleOrDefault(c => c.GetParameters().Length == 1)
            ?? throw new MissingMethodException(closedSheetType.FullName, ".ctor(rawSheet)");

        var rawSheetType = ctor.GetParameters()[0].ParameterType;

        // The current Lumina typed-sheet constructor stores only its RawSheet.
        // An uninitialized RawExcelSheet has Count == 0 by CLR default. Because
        // the typed enumerator first checks Count, no row/page backing fields are
        // touched for an empty sheet.
        var rawSheet = RuntimeHelpers.GetUninitializedObject(rawSheetType);
        var sheet = ctor.Invoke(new[] { rawSheet });

        var rowType = closedSheetType.GetGenericArguments()[0];
        tracker.Record(
            RuntimeObservationKind.ServiceAccess,
            "IDataManager",
            operation,
            "synthetic_empty",
            message: rowType.FullName,
            parameters: new Dictionary<string, string?>
            {
                ["row_type"] = rowType.FullName,
                ["sheet_type"] = closedSheetType.FullName,
                ["count"] = "0",
                ["real_game_data"] = "false",
            });

        return sheet;
    }
}

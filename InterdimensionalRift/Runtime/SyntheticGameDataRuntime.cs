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
        var rawSheet = CreateEmptyRawSheet(rawSheetType);
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

    private static object CreateEmptyRawSheet(Type rawSheetType)
    {
        var rawSheet = RuntimeHelpers.GetUninitializedObject(rawSheetType);
        SetField(rawSheetType, rawSheet, "_pages", CreateEmptyArrayFieldValue(rawSheetType, "_pages"));
        SetField(rawSheetType, rawSheet, "_rowOffsetLookupTable", CreateEmptyArrayFieldValue(rawSheetType, "_rowOffsetLookupTable"));
        SetField(rawSheetType, rawSheet, "_rowIndexLookupArray", Array.Empty<int>());
        SetField(rawSheetType, rawSheet, "_rowIndexLookupDict", CreateFrozenEmptyDictionary(rawSheetType));
        return rawSheet;
    }

    private static object CreateEmptyArrayFieldValue(Type rawSheetType, string name)
    {
        var field = FindField(rawSheetType, name);
        var elementType = field.FieldType.GetElementType()
            ?? throw new InvalidOperationException($"{field.DeclaringType?.FullName}.{name} is not an array field.");
        return Array.CreateInstance(elementType, 0);
    }

    private static object CreateFrozenEmptyDictionary(Type rawSheetType)
    {
        var fieldType = FindField(rawSheetType, "_rowIndexLookupDict").FieldType;
        var empty = fieldType.GetProperty("Empty", BindingFlags.Public | BindingFlags.Static)?.GetValue(null);
        return empty ?? throw new MissingMemberException(fieldType.FullName, "Empty");
    }

    private static void SetField(Type type, object instance, string name, object value) =>
        FindField(type, name).SetValue(instance, value);

    private static FieldInfo FindField(Type type, string name)
    {
        for (var current = type; current is not null; current = current.BaseType)
        {
            var field = current.GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
            if (field is not null)
                return field;
        }

        throw new MissingFieldException(type.FullName, name);
    }
}

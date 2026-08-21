using System.Diagnostics;
using System.Reflection;

namespace InterdimensionalRift.Instrumentation;

/// <summary>
/// Cheap stack sampler for capturing the call site of a service touch.
/// Filters out framework frames so the output stays readable.
/// </summary>
public static class StackSampler
{
    public static string? SampleForPlugin(int maxFrames = 6)
    {
        var frames = new StackTrace(fNeedFileInfo: false).GetFrames();
        if (frames is null)
        {
            return null;
        }

        var sb = new System.Text.StringBuilder();
        var captured = 0;
        foreach (var frame in frames)
        {
            var method = frame.GetMethod();
            if (method is null) continue;
            var declaring = method.DeclaringType;
            if (declaring is null) continue;
            if (IsIgnored(declaring)) continue;
            if (sb.Length > 0) sb.Append(" <- ");
            sb.Append(declaring.FullName).Append('.').Append(method.Name);
            if (++captured >= maxFrames) break;
        }
        return captured == 0 ? null : sb.ToString();
    }

    private static bool IsIgnored(Type t)
    {
        var name = t.FullName ?? string.Empty;
        return name.StartsWith("System.", StringComparison.Ordinal)
            || name.StartsWith("Microsoft.", StringComparison.Ordinal)
            || name.StartsWith("InterdimensionalRift", StringComparison.Ordinal)
            || name == "Dalamud.Plugin.Services.IPluginLog"
            || name == "Dalamud.Plugin.Services.ISigScanner"
            || name == "Dalamud.Plugin.Services.IGameNetwork"
            || name == "Dalamud.Plugin.Services.IFramework"
            || name == "Dalamud.Plugin.Services.IAddonLifecycle"
            || name == "Dalamud.Plugin.Services.IDataManager"
            || name == "Dalamud.Plugin.Services.IChatGui";
    }
}

using Dalamud.IoC;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace AsyncSamplePlugin;

public sealed class Plugin : IAsyncDalamudPlugin
{
    [PluginService] private static IPluginLog Log { get; set; } = null!;

    public Task LoadAsync(CancellationToken cancellationToken)
    {
        Log.Information("async load completed");
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        Log.Information("async dispose completed");
        return ValueTask.CompletedTask;
    }
}

using Dalamud.Game.Command;
using Dalamud.IoC;
using Dalamud.Plugin;
using Dalamud.Plugin.Ipc;
using Dalamud.Plugin.Services;

namespace RiftPostInitExerciseSemantics;

public sealed class Plugin : IDalamudPlugin
{
    [PluginService] private static IPluginLog Log { get; set; } = null!;
    [PluginService] private static IFramework Framework { get; set; } = null!;
    [PluginService] private static ICommandManager Commands { get; set; } = null!;
    [PluginService] private static IDalamudPluginInterface PluginInterface { get; set; } = null!;

    private readonly ICallGateSubscriber<object?> subscriber;
    private readonly ICallGateProvider<object?> provider;

    public Plugin()
    {
        Framework.Update += OnFrameworkUpdate;
        Framework.Update += OnSelfRemovingUpdate;
        _ = Framework.RunOnFrameworkThread(() => Log.Info("RIFT_EXERCISE deferred framework callback"));
        _ = Framework.RunOnTick(async () =>
        {
            await Task.Yield();
            Log.Info("RIFT_EXERCISE delayed framework tick2 async");
        }, delayTicks: 2);
        _ = Framework.RunOnTick(() => Log.Error("RIFT_EXERCISE DELAYED TICK10 SHOULD NOT RUN"), delayTicks: 10);
        _ = Framework.RunOnTick(() => Log.Error("RIFT_EXERCISE TIMESPAN DELAY SHOULD NOT RUN"), delay: TimeSpan.FromSeconds(1));

        PluginInterface.UiBuilder.OpenConfigUi += OnOpenConfig;
        PluginInterface.UiBuilder.OpenMainUi += OnOpenMain;
        PluginInterface.UiBuilder.Draw += OnDraw;

        Commands.AddHandler("/riftexercise", new CommandInfo(OnCommand)
        {
            HelpMessage = "Rift exercise fixture",
        });

        subscriber = PluginInterface.GetIpcSubscriber<object?>("rift.exercise.subscriber");
        subscriber.Subscribe(OnIpcSubscriber);

        provider = PluginInterface.GetIpcProvider<object?>("rift.exercise.provider");
        provider.RegisterFunc(OnIpcProvider);

        Log.Info("RIFT_EXERCISE startup complete");
    }

    private static void OnFrameworkUpdate(IFramework framework) =>
        Log.Info($"RIFT_EXERCISE framework update in_thread={framework.IsInFrameworkUpdateThread}");

    private static void OnSelfRemovingUpdate(IFramework framework)
    {
        Log.Info("RIFT_EXERCISE self removing framework update");
        Framework.Update -= OnSelfRemovingUpdate;
    }

    private static void OnOpenConfig() => Log.Info("RIFT_EXERCISE open config");
    private static void OnOpenMain() => Log.Info("RIFT_EXERCISE open main");
    private static void OnDraw() => Log.Error("RIFT_EXERCISE DRAW SHOULD NOT RUN IN SAFE PROFILE");

    private static void OnCommand(string command, string arguments)
    {
        var mode = Environment.GetEnvironmentVariable("RIFT_EXERCISE_FIXTURE_MODE");
        if (mode == "throw-command")
            throw new InvalidOperationException("RIFT_EXERCISE synthetic command throw");
        if (mode == "timeout-command")
        {
            Thread.Sleep(1500);
            Log.Error("RIFT_EXERCISE timeout command eventually returned");
            return;
        }
        Log.Info($"RIFT_EXERCISE command {command} args='{arguments}'");
    }

    private static void OnIpcSubscriber() => Log.Info("RIFT_EXERCISE ipc subscriber");

    private static object? OnIpcProvider()
    {
        Log.Info("RIFT_EXERCISE ipc provider");
        return null;
    }

    public void Dispose()
    {
        Framework.Update -= OnFrameworkUpdate;
        Framework.Update -= OnSelfRemovingUpdate;
        PluginInterface.UiBuilder.OpenConfigUi -= OnOpenConfig;
        PluginInterface.UiBuilder.OpenMainUi -= OnOpenMain;
        PluginInterface.UiBuilder.Draw -= OnDraw;
        Commands.RemoveHandler("/riftexercise");
        subscriber.Unsubscribe(OnIpcSubscriber);
        provider.UnregisterFunc();
        Log.Info("RIFT_EXERCISE disposed");
    }
}

using Dalamud.Game.Command;
using Dalamud.IoC;
using Dalamud.Plugin;
using Dalamud.Plugin.Ipc;
using Dalamud.Plugin.Services;
using Dalamud.Utility;
using FFXIVClientStructs.FFXIV.Client.Game;

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
        _ = Framework.RunOnFrameworkThread(() =>
        {
            // Mirrors the KamiToolKit failure discovered by the first published
            // Artisan post-init exercise: framework work must satisfy Dalamud's
            // own ThreadSafety identity, not only IFramework's synthetic property.
            ThreadSafety.AssertMainThread("RIFT_EXERCISE trusted Dalamud main-thread identity missing");
            Log.Info($"RIFT_EXERCISE deferred framework callback main_thread={ThreadSafety.IsMainThread}");
        });
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

    private static unsafe void OnFrameworkUpdate(IFramework framework)
    {
        ThreadSafety.AssertMainThread("RIFT_EXERCISE Framework.Update was not marked as Dalamud main thread");
        var inventoryManager = InventoryManager.Instance();
        if (inventoryManager is null)
            throw new InvalidOperationException("Synthetic InventoryManager.Instance returned null during Framework.Update.");
        if (inventoryManager->Inventories is not null || inventoryManager->NextContextId != 0)
            throw new InvalidOperationException("Synthetic InventoryManager unexpectedly exposed inventory state.");

        Log.Info($"RIFT_EXERCISE framework update in_thread={framework.IsInFrameworkUpdateThread} main_thread={ThreadSafety.IsMainThread} inventory=empty");
    }

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
        // A framework worker can later be reused by the thread pool for this command.
        // If Rift leaks Dalamud's ThreadStatic state, this catches it deterministically
        // whenever that reuse occurs and the log still records the expected false state.
        if (ThreadSafety.IsMainThread)
            throw new InvalidOperationException("RIFT_EXERCISE Dalamud main-thread identity leaked outside framework invocation");

        var mode = Environment.GetEnvironmentVariable("RIFT_EXERCISE_FIXTURE_MODE");
        if (mode == "throw-command")
            throw new InvalidOperationException("RIFT_EXERCISE synthetic command throw");
        if (mode == "timeout-command")
        {
            Thread.Sleep(1500);
            Log.Error("RIFT_EXERCISE timeout command eventually returned");
            return;
        }
        Log.Info($"RIFT_EXERCISE command {command} args='{arguments}' main_thread={ThreadSafety.IsMainThread}");
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

using Dalamud.Hooking;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace RiftGameInteropSemantics;

public sealed class Plugin : IDalamudPlugin
{
    private delegate int TestHookDelegate(int value);
    private readonly Hook<TestHookDelegate> hook;

    public Plugin(IDalamudPluginInterface pi, IGameInteropProvider interop, ISigScanner scanner, IPluginLog log)
    {
        var first = pi.GetOrCreateData("RiftGameInteropSemantics.shared", () => new SharedToken());
        var second = pi.GetOrCreateData("RiftGameInteropSemantics.shared", () => new SharedToken());
        if (!ReferenceEquals(first, second))
            throw new InvalidOperationException("GetOrCreateData did not preserve shared object identity.");
        if (!string.Equals(pi.Manifest.InternalName, "RiftGameInteropSemantics", StringComparison.Ordinal))
            throw new InvalidOperationException($"Manifest InternalName mismatch: {pi.Manifest.InternalName}");
        if (pi.Manifest.AssemblyVersion is null)
            throw new InvalidOperationException("Manifest AssemblyVersion was not populated.");

        var address = scanner.GetStaticAddressFromSig("48 89 1D ?? ?? ?? ?? 48 8B CB FF 15");
        if (address != 0)
            throw new InvalidOperationException("Rift signature scanner must not expose real game memory.");

        hook = interop.HookFromSignature<TestHookDelegate>("AA BB ?? CC", Detour);
        if (hook is null)
            throw new InvalidOperationException("Rift did not return a synthetic Hook<T>.");
        if (hook.IsEnabled)
            throw new InvalidOperationException("Synthetic hook started enabled.");

        hook.Enable();
        if (!hook.IsEnabled)
            throw new InvalidOperationException("Synthetic hook did not track Enable().");
        if (hook.Original(123) != 0)
            throw new InvalidOperationException("Synthetic Original delegate must be inert/default-returning.");
        hook.Disable();
        if (hook.IsEnabled)
            throw new InvalidOperationException("Synthetic hook did not track Disable().");

        interop.InitializeFromAttributes(this);
        log.Information("RIFT_GAME_INTEROP semantics complete");
    }

    private static int Detour(int value) => value + 1;

    private sealed class SharedToken { }

    public void Dispose() => hook.Dispose();
}

using Dalamud.IoC;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace RiftCreateSemantics;

public sealed class Plugin : IDalamudPlugin
{
    public Plugin(IDalamudPluginInterface pi)
    {
        var scoped = new ScopedToken();
        var created = pi.Create<CreatedService>(scoped)
            ?? throw new InvalidOperationException("IDalamudPluginInterface.Create returned null");
        if (!ReferenceEquals(created.Token, scoped))
            throw new InvalidOperationException("Create<T> did not preserve scoped-object identity");
        if (CreatedService.ClientState is null || created.Framework is null)
            throw new InvalidOperationException("Create<T> did not inject PluginService members");

        var asyncCreated = pi.CreateAsync<AsyncCreatedService>().GetAwaiter().GetResult();
        if (asyncCreated.Framework is null)
            throw new InvalidOperationException("CreateAsync<T> did not inject PluginService members");

        CreatedService.Log.Information("RIFT_CREATE semantics complete");
    }

    public void Dispose() { }
}

public sealed class ScopedToken { }

public sealed class CreatedService
{
    [PluginService] public static IClientState ClientState { get; private set; } = null!;
    [PluginService] public static IPluginLog Log { get; private set; } = null!;
    [PluginService] public IFramework Framework { get; private set; } = null!;
    public ScopedToken Token { get; }

    public CreatedService(ScopedToken token) => Token = token;
}

public sealed class AsyncCreatedService
{
    [PluginService] public IFramework Framework { get; private set; } = null!;
}

using Dalamud.Plugin;
using Dalamud.Plugin.Services;
using FFXIVClientStructs.FFXIV.Client.System.Framework;
using FFXIVClientStructs.FFXIV.Client.UI.Agent;

namespace RiftNativeGameStateSemantics;

public sealed unsafe class Plugin : IDalamudPlugin
{
    public Plugin(IPluginLog log)
    {
        var framework = Framework.Instance();
        if (framework is null)
            throw new InvalidOperationException("Synthetic Framework.Instance returned null.");
        if (framework->UIModule is null)
            throw new InvalidOperationException("Synthetic Framework.UIModule returned null.");

        var agentModule = framework->UIModule->GetAgentModule();
        if (agentModule is null)
            throw new InvalidOperationException("Synthetic UIModule.GetAgentModule returned null.");

        var contextAgent = agentModule->GetAgentByInternalId(AgentId.InventoryContext);
        if (contextAgent is not null)
            throw new InvalidOperationException("Synthetic native state unexpectedly exposed an inventory-context agent.");

        log.Information("RIFT_NATIVE_GAME_STATE synthetic empty chain complete");
    }

    public void Dispose() { }
}

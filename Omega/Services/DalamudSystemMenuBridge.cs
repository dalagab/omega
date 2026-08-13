using Dalamud.Hooking;
using Dalamud.Plugin.Services;
using Dalamud.Utility;
using FFXIVClientStructs.FFXIV.Client.UI;
using FFXIVClientStructs.FFXIV.Client.UI.Agent;
using FFXIVClientStructs.FFXIV.Component.GUI;
using FFXIVClientStructs.Interop;

namespace Dalagab.Omega;

/// <summary>
/// Best-effort API-15 bridge that adds an Omega command to FFXIV's ESC/System menu.
/// Dalamud does not expose a public system-menu entry service, so this bridge is intentionally
/// isolated and fails closed if the native shape changes.
/// </summary>
internal sealed unsafe class DalamudSystemMenuBridge : IDisposable
{
    private const int OmegaCommandId = 69422;
    private const int MaxEntries = 20;
    private const int EntryStartIndex = 5;

    private readonly Action openOmega;
    private Hook<AgentHUD.Delegates.OpenSystemMenu>? openSystemMenuHook;
    private Hook<UIModule.Delegates.ExecuteMainCommand>? executeMainCommandHook;

    public bool IsAvailable { get; private set; }

    public DalamudSystemMenuBridge(IGameInteropProvider interop, Action openOmega)
    {
        this.openOmega = openOmega;

        try
        {
            openSystemMenuHook = interop.HookFromAddress<AgentHUD.Delegates.OpenSystemMenu>(
                AgentHUD.Addresses.OpenSystemMenu.Value,
                AgentHudOpenSystemMenuDetour);
            executeMainCommandHook = interop.HookFromAddress<UIModule.Delegates.ExecuteMainCommand>(
                (nint)UIModule.StaticVirtualTablePointer->ExecuteMainCommand,
                UiModuleExecuteMainCommandDetour);

            openSystemMenuHook.Enable();
            executeMainCommandHook.Enable();
            IsAvailable = true;
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega ESC/System menu integration is unavailable on this Dalamud build.");
            Dispose();
        }
    }

    private void AgentHudOpenSystemMenuDetour(AgentHUD* thisPtr, AtkValue* atkValueArgs, uint menuSize)
    {
        var hook = openSystemMenuHook;
        if (hook is null)
            return;

        try
        {
            const int offset = 1;
            var newMenuSize = checked((int)menuSize + offset);
            if (newMenuSize >= MaxEntries)
            {
                hook.Original(thisPtr, atkValueArgs, menuSize);
                return;
            }

            using var values = new RentedAtkValues(EntryStartIndex + (MaxEntries * 2));

            for (var i = 0; i < EntryStartIndex; i++)
                values[i].Copy(&atkValueArgs[i]);

            for (var i = EntryStartIndex; i < EntryStartIndex + menuSize; i++)
            {
                values[i + offset].Copy(&atkValueArgs[i]);
                values[i + offset + MaxEntries].Copy(&atkValueArgs[i + MaxEntries]);
            }

            values[3].SetInt(newMenuSize);
            values[EntryStartIndex].SetInt(OmegaCommandId);

            using var rssb = new RentedSeStringBuilder();
            values[EntryStartIndex + MaxEntries].SetManagedString(rssb.Builder
                .PushColorType(539)
                .Append("Omega")
                .PopColorType()
                .GetViewAsSpan());

            hook.Original(thisPtr, values, (uint)newMenuSize);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not decorate the ESC/System menu; falling back to the original menu.");
            hook.Original(thisPtr, atkValueArgs, menuSize);
        }
    }

    private void UiModuleExecuteMainCommandDetour(UIModule* thisPtr, uint commandId)
    {
        var hook = executeMainCommandHook;
        if (hook is null)
            return;

        if (commandId == OmegaCommandId)
        {
            try
            {
                openOmega();
            }
            catch (Exception ex)
            {
                Plugin.Log.Warning(ex, "Omega failed to open from the ESC/System menu.");
            }

            return;
        }

        hook.Original(thisPtr, commandId);
    }

    public void Dispose()
    {
        IsAvailable = false;

        try
        {
            executeMainCommandHook?.Dispose();
        }
        catch
        {
            // Best effort during unload.
        }

        try
        {
            openSystemMenuHook?.Dispose();
        }
        catch
        {
            // Best effort during unload.
        }

        executeMainCommandHook = null;
        openSystemMenuHook = null;
    }
}

using System.Reflection;
using System.Runtime.InteropServices;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Runtime;

/// <summary>
/// Provides a deliberately tiny FFXIVClientStructs native-state surface inside
/// Rift. It does not initialize the real FFXIVClientStructs resolver, scan a game
/// module, or call game code. Selected generated Address.Value entries and one
/// virtual-table slot are pointed at Rift-owned memory/stubs so plugins can
/// observe an explicitly empty game state instead of crashing on an unresolved
/// singleton address.
/// </summary>
internal static unsafe class SyntheticNativeGameStateRuntime
{
    private static readonly object Gate = new();
    private static bool installed;
    private static AccessTracker? tracker;

    private static nint framework;
    private static nint frameworkPointerCell;
    private static nint uiModule;
    private static nint uiModuleVtable;
    private static nint raptureAtkModule;
    private static nint agentModule;
    private static nint gameObjectManager;
    private static nint inventoryManager;
    private static string? ffxivClientStructsVersion;

    public static void EnsureInstalled(AccessTracker accessTracker)
    {
        tracker = accessTracker;
        if (installed)
        {
            ObserveActiveModel(reused: true);
            return;
        }

        lock (Gate)
        {
            tracker = accessTracker;
            if (installed)
            {
                ObserveActiveModel(reused: true);
                return;
            }

            try
            {
                var ffxiv = DalamudContract.TryResolveTrusted(new AssemblyName("FFXIVClientStructs"));
                if (ffxiv is null)
                {
                    Observe("native_state", "install", "unavailable", new()
                    {
                        ["reason"] = "FFXIVClientStructs assembly not present in frozen contract runtime",
                        ["real_game_memory"] = "false",
                    });
                    return;
                }

                var frameworkType = RequireType(ffxiv, "FFXIVClientStructs.FFXIV.Client.System.Framework.Framework");
                var uiModuleType = RequireType(ffxiv, "FFXIVClientStructs.FFXIV.Client.UI.UIModule");
                var raptureAtkModuleType = RequireType(ffxiv, "FFXIVClientStructs.FFXIV.Client.UI.RaptureAtkModule");
                var atkUnitManagerType = RequireType(ffxiv, "FFXIVClientStructs.FFXIV.Component.GUI.AtkUnitManager");
                var agentModuleType = RequireType(ffxiv, "FFXIVClientStructs.FFXIV.Client.UI.Agent.AgentModule");
                var gameObjectManagerType = RequireType(ffxiv, "FFXIVClientStructs.FFXIV.Client.Game.Object.GameObjectManager");
                var inventoryManagerType = RequireType(ffxiv, "FFXIVClientStructs.FFXIV.Client.Game.InventoryManager");

                framework = AllocateZeroed(SizeOfExplicit(frameworkType));
                uiModule = AllocateZeroed(SizeOfExplicit(uiModuleType));
                raptureAtkModule = AllocateZeroed(SizeOfExplicit(raptureAtkModuleType));
                agentModule = AllocateZeroed(SizeOfExplicit(agentModuleType));
                // A zeroed GameObjectManager is an intentionally empty game-object world:
                // all object pointers and sorted counts remain zero, so callers can
                // conclude that no local player/game objects are present without Rift
                // inventing identities, entities, or backing game memory.
                gameObjectManager = AllocateZeroed(SizeOfExplicit(gameObjectManagerType));
                // InventoryManager is deliberately present but contains no invented
                // containers, slots, items, currency, or character inventory. Its
                // Inventories pointer and all other state remain zero.
                inventoryManager = AllocateZeroed(SizeOfExplicit(inventoryManagerType));

                // Framework.Instance has isPointer:true, so its generated wrapper
                // expects Address.Value to point at a Framework* cell (Framework**).
                frameworkPointerCell = AllocateZeroed((nuint)IntPtr.Size);
                *(nint*)frameworkPointerCell = framework;

                var uiModuleOffset = FieldOffset(frameworkType, "UIModule");
                *(nint*)(framework + uiModuleOffset) = uiModule;

                // UIModuleInterface.GetAgentModule is virtual function slot 37.
                // The inherited UIModuleInterface lives at offset 0, so install only
                // the vtable slot needed by the currently qualified empty-state model.
                const int getAgentModuleSlot = 37;
                const int getRaptureAtkModuleSlot = 7;
                const int vtableSlots = 249;
                uiModuleVtable = AllocateZeroed((nuint)(vtableSlots * IntPtr.Size));
                ((nint*)uiModuleVtable)[getRaptureAtkModuleSlot] = (nint)(delegate* unmanaged<nint, nint>)&GetRaptureAtkModuleStub;
                ((nint*)uiModuleVtable)[getAgentModuleSlot] = (nint)(delegate* unmanaged<nint, nint>)&GetAgentModuleStub;
                *(nint*)uiModule = uiModuleVtable;

                PatchAddress(frameworkType, "Instance", frameworkPointerCell);
                PatchAddress(frameworkType, "GetUIModule", (nint)(delegate* unmanaged<nint, nint>)&GetUIModuleStub);
                PatchAddress(agentModuleType, "GetAgentByInternalId", (nint)(delegate* unmanaged<nint, uint, nint>)&GetAgentByInternalIdStub);
                PatchAddress(atkUnitManagerType, "GetAddonByName", (nint)(delegate* unmanaged<nint, nint, int, nint>)&GetAddonByNameStub);
                // GameObjectManager.Instance is a direct StaticAddress (not
                // isPointer:true), so Address.Value points straight at the zeroed
                // Rift-owned manager rather than at a pointer cell.
                PatchAddress(gameObjectManagerType, "Instance", gameObjectManager);
                // InventoryManager.Instance is likewise a direct StaticAddress in the
                // frozen generated contract, so its Address.Value points at the
                // Rift-owned zeroed manager itself rather than a pointer cell.
                PatchAddress(inventoryManagerType, "Instance", inventoryManager);

                ffxivClientStructsVersion = ffxiv.GetName().Version?.ToString();
                installed = true;
                ObserveActiveModel(reused: false);
            }
            catch (Exception ex)
            {
                Observe("native_state", "install", "unavailable", new()
                {
                    ["reason"] = $"{ex.GetType().Name}: {ex.Message}",
                    ["real_game_memory"] = "false",
                    ["native_call"] = "false",
                });
            }
        }
    }

    private static void ObserveActiveModel(bool reused)
    {
        Observe("native_state", reused ? "reuse" : "install", "synthetic_ready", new()
        {
            ["ffxivclientstructs_model"] = "bounded-empty-v3",
            ["ffxivclientstructs_version"] = ffxivClientStructsVersion,
            ["framework_pointer"] = Hex(framework),
            ["ui_module_pointer"] = Hex(uiModule),
            ["rapture_atk_module_pointer"] = Hex(raptureAtkModule),
            ["agent_module_pointer"] = Hex(agentModule),
            ["game_object_manager_pointer"] = Hex(gameObjectManager),
            ["inventory_manager_pointer"] = Hex(inventoryManager),
            ["reused"] = reused ? "true" : "false",
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
        });

        // Address.Value is process-global inside the loaded FFXIVClientStructs assembly.
        // A later SandboxHost run therefore inherits the already-patched resolver table.
        // Re-emit the active model into the *current* report so each exact-artifact run
        // carries its own provenance instead of depending on which test/plugin installed
        // the model first. These are model-state observations, not claims that the
        // plugin invoked every listed function.
        Observe("FFXIVClientStructs.FFXIV.Client.System.Framework.Framework", "Framework.Instance", "synthetic_singleton", new()
        {
            ["patched_address"] = Hex(frameworkPointerCell),
            ["model_state"] = "active",
            ["reused"] = reused ? "true" : "false",
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
            ["artifact_mutated"] = "false",
        });
        Observe("FFXIVClientStructs.FFXIV.Client.System.Framework.Framework", "Framework.GetUIModule", "synthetic_native_stub", new()
        {
            ["model_state"] = "active",
            ["reused"] = reused ? "true" : "false",
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
            ["artifact_mutated"] = "false",
        });
        Observe("FFXIVClientStructs.FFXIV.Client.UI.Agent.AgentModule", "AgentModule.GetAgentByInternalId", "synthetic_native_stub", new()
        {
            ["model_state"] = "active",
            ["reused"] = reused ? "true" : "false",
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
            ["artifact_mutated"] = "false",
        });
        Observe("FFXIVClientStructs.FFXIV.Client.UI.UIModule", "UIModule.GetRaptureAtkModule", "synthetic_native_stub", new()
        {
            ["model_state"] = "active",
            ["returned_pointer"] = Hex(raptureAtkModule),
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
            ["artifact_mutated"] = "false",
        });
        Observe("FFXIVClientStructs.FFXIV.Component.GUI.AtkUnitManager", "AtkUnitManager.GetAddonByName", "synthetic_native_stub", new()
        {
            ["model_state"] = "active",
            ["returned_pointer"] = "0x0",
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
            ["artifact_mutated"] = "false",
        });
        Observe("FFXIVClientStructs.FFXIV.Client.Game.Object.GameObjectManager", "GameObjectManager.Instance", "synthetic_singleton", new()
        {
            ["patched_address"] = Hex(gameObjectManager),
            ["model_state"] = "active",
            ["world_state"] = "empty",
            ["local_player"] = "absent",
            ["reused"] = reused ? "true" : "false",
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
            ["artifact_mutated"] = "false",
        });
        Observe("FFXIVClientStructs.FFXIV.Client.Game.InventoryManager", "InventoryManager.Instance", "synthetic_singleton", new()
        {
            ["patched_address"] = Hex(inventoryManager),
            ["model_state"] = "active",
            ["inventory_state"] = "empty",
            ["inventory_containers"] = "absent",
            ["items"] = "none",
            ["local_player"] = "absent",
            ["reused"] = reused ? "true" : "false",
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
            ["artifact_mutated"] = "false",
        });
    }

    [UnmanagedCallersOnly]
    private static nint GetUIModuleStub(nint self)
    {
        ObserveNoThrow("Framework", "GetUIModule", "synthetic_pointer", new()
        {
            ["self"] = Hex(self),
            ["returned_pointer"] = Hex(uiModule),
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
        });
        return uiModule;
    }

    [UnmanagedCallersOnly]
    private static nint GetRaptureAtkModuleStub(nint self)
    {
        ObserveNoThrow("UIModule", "GetRaptureAtkModule", "synthetic_pointer", new()
        {
            ["self"] = Hex(self),
            ["returned_pointer"] = Hex(raptureAtkModule),
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
        });
        return raptureAtkModule;
    }

    [UnmanagedCallersOnly]
    private static nint GetAgentModuleStub(nint self)
    {
        ObserveNoThrow("UIModule", "GetAgentModule", "synthetic_pointer", new()
        {
            ["self"] = Hex(self),
            ["returned_pointer"] = Hex(agentModule),
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
        });
        return agentModule;
    }

    [UnmanagedCallersOnly]
    private static nint GetAddonByNameStub(nint self, nint name, int index)
    {
        ObserveNoThrow("AtkUnitManager", "GetAddonByName", "synthetic_absent", new()
        {
            ["self"] = Hex(self),
            ["index"] = index.ToString(),
            ["returned_pointer"] = "0x0",
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
        });
        return 0;
    }

    [UnmanagedCallersOnly]
    private static nint GetAgentByInternalIdStub(nint self, uint agentId)
    {
        ObserveNoThrow("AgentModule", "GetAgentByInternalId", "synthetic_absent", new()
        {
            ["self"] = Hex(self),
            ["agent_id"] = agentId.ToString(),
            ["returned_pointer"] = "0x0",
            ["real_game_memory"] = "false",
            ["native_call"] = "false",
        });
        return 0;
    }

    private static void PatchAddress(Type owner, string fieldName, nint value)
    {
        var addresses = owner.GetNestedType("Addresses", BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"{owner.FullName}.Addresses was not found.");
        var field = addresses.GetField(fieldName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new MissingFieldException(addresses.FullName, fieldName);
        var address = field.GetValue(null)
            ?? throw new InvalidOperationException($"{addresses.FullName}.{fieldName} returned null.");
        var valueField = address.GetType().GetField("Value", BindingFlags.Public | BindingFlags.Instance)
            ?? throw new MissingFieldException(address.GetType().FullName, "Value");
        valueField.SetValue(address, value);
    }

    private static Type RequireType(Assembly assembly, string name) =>
        assembly.GetType(name, throwOnError: true)
        ?? throw new TypeLoadException(name);

    private static nuint SizeOfExplicit(Type type)
    {
        var attr = type.StructLayoutAttribute;
        if (attr is null || attr.Size <= 0)
            throw new InvalidOperationException($"{type.FullName} does not expose an explicit unmanaged size.");
        return (nuint)attr.Size;
    }

    private static int FieldOffset(Type type, string fieldName)
    {
        var field = type.GetField(fieldName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new MissingFieldException(type.FullName, fieldName);
        var attr = field.GetCustomAttribute<FieldOffsetAttribute>()
            ?? throw new InvalidOperationException($"{type.FullName}.{fieldName} does not have FieldOffsetAttribute.");
        return attr.Value;
    }

    private static nint AllocateZeroed(nuint bytes)
    {
        var ptr = (nint)NativeMemory.AllocZeroed(bytes);
        if (ptr == 0)
            throw new OutOfMemoryException($"Rift could not allocate {bytes} bytes for synthetic native game state.");
        return ptr;
    }

    private static string Hex(nint value) => $"0x{unchecked((nuint)value):X}";

    private static void Observe(string component, string operation, string outcome, Dictionary<string, string?> parameters)
        => tracker?.Record(RuntimeObservationKind.NativeGameState, component, operation, outcome, parameters: parameters);

    private static void ObserveNoThrow(string component, string operation, string outcome, Dictionary<string, string?> parameters)
    {
        try { Observe(component, operation, outcome, parameters); }
        catch { /* unmanaged stub must never unwind across the unmanaged boundary */ }
    }
}

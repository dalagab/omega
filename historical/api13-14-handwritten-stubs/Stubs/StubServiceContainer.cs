using Dalamud.Plugin;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;
using IServiceProvider = Dalamud.Plugin.IServiceProvider;

namespace InterdimensionalRift.Stubs;

public sealed class StubServiceContainer : IServiceProvider
{
    public StubServiceContainer(AccessTracker tracker)
    {
        Log = new StubPluginLog(tracker);
        ClientState = new StubClientState(tracker);
        ObjectTable = new StubObjectTable(tracker);
        Framework = new StubFramework(tracker);
        DataManager = new StubDataManager(tracker);
        GameGui = new StubGameGui(tracker);
        ChatGui = new StubChatGui(tracker);
        TextureProvider = new StubTextureProvider(tracker);
        AddonLifecycle = new StubAddonLifecycle(tracker);
        SigScanner = new StubSigScanner(tracker);
        GameNetwork = new StubGameNetwork(tracker);
        PartyFinder = new StubPartyFinder(tracker);
        Condition = new StubCondition(tracker);
        DutyState = new StubDutyState(tracker);
        TextureSubstitution = new StubTextureSubstitution(tracker);
        TitleScreenMenu = new StubTitleScreenMenu(tracker);
        AddonIpcManager = new StubAddonIpcManager(tracker);
        Ipc = new StubIpcManager(tracker);
        UiBuilder = new StubUiBuilder(tracker);
        GameInterface = new StubGameInterface(tracker);
    }

    public IPluginLog Log { get; }
    public IClientState ClientState { get; }
    public IObjectTable ObjectTable { get; }
    public IFramework Framework { get; }
    public IDataManager DataManager { get; }
    public IGameGui GameGui { get; }
    public IChatGui ChatGui { get; }
    public ITextureProvider TextureProvider { get; }
    public IAddonLifecycle AddonLifecycle { get; }
    public ISigScanner SigScanner { get; }
    public IGameNetwork GameNetwork { get; }
    public IPartyFinder PartyFinder { get; }
    public ICondition Condition { get; }
    public IDutyState DutyState { get; }
    public ITextureSubstitution TextureSubstitution { get; }
    public ITitleScreenMenu TitleScreenMenu { get; }
    public IAddonIpcManager AddonIpcManager { get; }
    public IIpcManager Ipc { get; }
    public IUiBuilder UiBuilder { get; }
    public IGameInterface GameInterface { get; }
}

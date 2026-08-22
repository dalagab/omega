using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const string TutorialPopupId = "Welcome to Omega###DalagabOmegaTutorial";

    private readonly record struct TutorialTarget(Vector2 Min, Vector2 Max);
    private readonly record struct TutorialPage(string Target, string Title, string Body);

    private static readonly TutorialPage[] TutorialPages =
    [
        new("", "Welcome to Omega",
            "Omega helps you find, understand, install, update, and manage Dalamud plugins. You do not need to understand every technical detail to use it."),
        new("sidebar-view-Spotlight", "Spotlight",
            "Spotlight is a small pick of plugins worth a look, plus some of the latest additions. It is an easy place to start when you want ideas."),
        new("sidebar-view-Discover", "Discover",
            "Discover is where you can browse the full Omega catalog. Open a plugin to read about it, see what it does, look through screenshots and details, or find its community, project page, and help links."),
        new("filters", "Filters",
            "Filters help you narrow Discover down to what you are looking for. You can filter by things like author, source, category, tags, compatibility, status, and the kinds of findings Omega knows about."),
        new("search", "Search",
            "Search looks through plugin names, descriptions, authors, tags, and documentation. By default it is available everywhere in Omega."),
        new("sidebar-utility-Library", "Library",
            "Library is what you already have installed. This is where you manage plugin state, collections, settings, backups, and removal."),
        new("sidebar-utility-Updates", "Updates",
            "Updates keeps your available updates together. The changelog is there to give you more details without needing you to go to each individual plugin."),
        new("", "What do the little flags mean?",
            "The small ribbons are quick indicators. The symbol tells you what Omega is pointing out, while some ribbon colours tell you how much attention a finding may deserve."),
        new("", "Should I worry?",
            "Omega is built to help you make informed decisions. In Settings you can choose what you are comfortable with. If a plugin you are about to install can do something you said you would rather avoid, Omega will warn you before installing it."),
        new("", "Choose your install permissions",
            "Choose the things you want Omega to stop and ask about before installation. You can change these choices later in Settings whenever your comfort level changes."),
        new("", "You are ready",
            "Omega is here to make finding and managing plugins easier while giving you the information you need when a choice matters. Browse Spotlight for ideas, explore the full catalog in Discover, and open any plugin whenever you want to learn more.\n\nYou can replay this tour at any time from Settings → General. Thank you for trusting Omega to help you navigate the plugin ecosystem — and safe searching."),
    ];

    private readonly Dictionary<string, TutorialTarget> tutorialTargets = new(StringComparer.Ordinal);
    private bool tutorialOpen;
    private bool requestTutorialPopup;
    private int tutorialStep;
    private bool tutorialRibbonLegendReviewed;

    private void RememberTutorialTarget(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return;
        tutorialTargets[key] = new TutorialTarget(ImGui.GetItemRectMin(), ImGui.GetItemRectMax());
    }

    private void StartTutorial()
    {
        settingsOpen = false;
        tutorialStep = 0;
        tutorialRibbonLegendReviewed = false;
        tutorialOpen = true;
        requestTutorialPopup = true;
        ImGui.CloseCurrentPopup();
        ApplyTutorialStepView();
    }

    private void CompleteTutorial()
    {
        tutorialOpen = false;
        configuration.TutorialCompleted = true;
        configuration.Save();
        ImGui.CloseCurrentPopup();
    }

    private void DrawTutorialModal()
    {
        if (!tutorialOpen || !configuration.EulaAccepted)
            return;

        tutorialStep = Math.Clamp(tutorialStep, 0, TutorialPages.Length - 1);
        var page = TutorialPages[tutorialStep];
        TutorialTarget target = default;
        var hasTarget = !string.IsNullOrWhiteSpace(page.Target) && tutorialTargets.TryGetValue(page.Target, out target);

        PositionTutorialPopup(hasTarget ? target : null);
        ImGui.SetNextWindowSize(UiModalSize(620f, 520f), ImGuiCond.Always);
        var keepOpen = tutorialOpen;
        if (!ImGui.BeginPopupModal(
                TutorialPopupId,
                ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse |
                ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse))
        {
            tutorialOpen = keepOpen;
            return;
        }

        if (hasTarget)
            DrawTutorialHighlight(target);

        ImGui.TextColored(new Vector4(0.35f, 0.86f, 0.75f, 1f), $"Omega tour  {tutorialStep + 1}/{TutorialPages.Length}");
        ImGui.TextUnformatted(page.Title);
        ImGui.Separator();
        ImGui.Spacing();

        var footerReserve = Ui(tutorialStep == 7 ? 92f : 62f);
        var bodyHeight = Math.Max(Ui(180f), ImGui.GetContentRegionAvail().Y - footerReserve);
        ImGui.BeginChild("omega-tutorial-scroll-body", new Vector2(0f, bodyHeight), false,
            ImGuiWindowFlags.AlwaysVerticalScrollbar);
        ImGui.TextWrapped(page.Body);

        var ribbonLegendStep = tutorialStep == 7;
        if (ribbonLegendStep)
            DrawTutorialRibbonLegend();
        else if (tutorialStep == 8)
            DrawTutorialDecisionNote();
        else if (tutorialStep == 9)
            DrawTutorialPermissionChoices();

        if (ribbonLegendStep)
        {
            var scrollMax = ImGui.GetScrollMaxY();
            if (scrollMax > Ui(1f) && ImGui.GetScrollY() >= scrollMax - Ui(6f))
                tutorialRibbonLegendReviewed = true;
        }
        ImGui.EndChild();

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        var canAdvance = !ribbonLegendStep || tutorialRibbonLegendReviewed;
        if (ribbonLegendStep && !canAdvance)
        {
            ImGui.TextDisabled("Scroll to the bottom of the flag guide to continue.");
            ImGui.Spacing();
        }

        if (tutorialStep > 0)
        {
            if (ImGui.Button("Back", Ui(92f, 32f)))
                MoveTutorial(-1);
            ImGui.SameLine();
        }

        if (tutorialStep < TutorialPages.Length - 1)
        {
            ImGui.BeginDisabled(!canAdvance);
            if (ImGui.Button("Next", Ui(92f, 32f)))
                MoveTutorial(1);
            ImGui.EndDisabled();
            ImGui.SameLine();
            if (ImGui.Button("Skip tour", Ui(112f, 32f)))
                CompleteTutorial();
        }
        else if (ImGui.Button("Finish", Ui(110f, 32f)))
        {
            CompleteTutorial();
        }

        tutorialOpen = keepOpen && tutorialOpen;
        ImGui.EndPopup();
    }

    private void MoveTutorial(int delta)
    {
        tutorialStep = Math.Clamp(tutorialStep + delta, 0, TutorialPages.Length - 1);
        ApplyTutorialStepView();
    }

    private void ApplyTutorialStepView()
    {
        var next = tutorialStep switch
        {
            1 => MarketplaceView.Spotlight,
            2 or 3 or 4 or 7 => MarketplaceView.Discover,
            5 => MarketplaceView.Library,
            6 => MarketplaceView.Updates,
            _ => activeView,
        };

        // Discover and Filters have separate tour steps. The Discover step highlights the rail
        // destination itself; the following Filters step opens the editor and points at its control.
        filtersOpen = tutorialStep == 3;

        if (next == activeView)
            return;

        activeView = next;
        detailsOpen = false;
        selectedPlugin = null;
        resetStorefrontScroll = true;
    }

    private static void DrawTutorialHighlight(TutorialTarget target)
    {
        var pad = Ui(5f);
        var min = target.Min - new Vector2(pad, pad);
        var max = target.Max + new Vector2(pad, pad);
        var draw = ImGui.GetForegroundDrawList();
        draw.AddRect(min, max, ImGui.ColorConvertFloat4ToU32(new Vector4(0.26f, 0.92f, 0.86f, 1f)), Ui(8f), ImDrawFlags.None, Ui(3f));
        draw.AddRect(min - Ui(2f, 2f), max + Ui(2f, 2f), ImGui.ColorConvertFloat4ToU32(new Vector4(0.26f, 0.92f, 0.86f, 0.34f)), Ui(10f), ImDrawFlags.None, Ui(2f));
    }

    private static void PositionTutorialPopup(TutorialTarget? target)
    {
        var viewport = ImGui.GetMainViewport();
        var workMin = viewport.WorkPos;
        var workMax = viewport.WorkPos + viewport.WorkSize;
        var cardSize = UiModalSize(620f, 520f);
        Vector2 pos;

        if (target is { } value)
        {
            var right = new Vector2(value.Max.X + Ui(26f), value.Min.Y - Ui(20f));
            var below = new Vector2(value.Min.X, value.Max.Y + Ui(22f));
            pos = right.X + cardSize.X < workMax.X ? right : below;
        }
        else
        {
            pos = workMin + (viewport.WorkSize - cardSize) * 0.5f;
        }

        pos.X = Math.Clamp(pos.X, workMin.X + Ui(16f), Math.Max(workMin.X + Ui(16f), workMax.X - cardSize.X - Ui(16f)));
        pos.Y = Math.Clamp(pos.Y, workMin.Y + Ui(16f), Math.Max(workMin.Y + Ui(16f), workMax.Y - cardSize.Y - Ui(16f)));
        ImGui.SetNextWindowPos(pos, ImGuiCond.Always);
    }

    private static void DrawTutorialRibbonLegend()
    {
        ImGui.Spacing();
        if (ImGui.BeginTable("omega-tutorial-ribbon-legend", 2,
                ImGuiTableFlags.SizingStretchProp | ImGuiTableFlags.BordersInnerH))
        {
            ImGui.TableSetupColumn("Indicator", ImGuiTableColumnFlags.WidthFixed, Ui(150f));
            ImGui.TableSetupColumn("Meaning", ImGuiTableColumnFlags.WidthStretch);
            DrawTutorialLegendRow(FontAwesomeIcon.Star, "Star", "Omega found a public source for this plugin.");
            DrawTutorialLegendRow(FontAwesomeIcon.Check, "Check", "This plugin is installed.");
            DrawTutorialLegendRow(FontAwesomeIcon.Folder, "Folder", "This plugin is in one of your collections.");
            DrawTutorialLegendRow(FontAwesomeIcon.Robot, "Robot", "This plugin can automate parts of the game.");
            DrawTutorialLegendRow(FontAwesomeIcon.Lock, "Lock", "This plugin does not support your current Dalamud version.");
            DrawTutorialLegendRow(FontAwesomeIcon.Question, "Question mark", "Omega does not know enough yet, or could not confirm where this copy came from.");
            ImGui.EndTable();
        }

        ImGui.Spacing();
        ImGui.TextUnformatted("What the finding colour means");
        ImGui.TextWrapped("This colour is only a quick summary of what Omega found. It is not a score for whether a plugin is good or bad.");
        ImGui.Spacing();
        DrawTutorialColorRow(new Vector4(0.32f, 0.34f, 0.38f, 1f), "Grey", "Not checked yet, or Omega does not have enough information.");
        DrawTutorialColorRow(new Vector4(0.16f, 0.47f, 0.82f, 1f), "Blue", "Information only.");
        DrawTutorialColorRow(new Vector4(0.78f, 0.58f, 0.14f, 1f), "Gold", "Checked, with nothing serious found.");
        DrawTutorialColorRow(new Vector4(0.91f, 0.76f, 0.13f, 1f), "Yellow", "Minor things worth knowing about.");
        DrawTutorialColorRow(new Vector4(0.91f, 0.43f, 0.10f, 1f), "Orange", "Something deserves your attention.");
        DrawTutorialColorRow(new Vector4(0.78f, 0.10f, 0.14f, 1f), "Red", "Serious findings: read the warning before installing.");
        ImGui.TextWrapped("Green means installed, purple means collection membership, and the blue robot ribbon marks automation. Those are status colours, not finding levels.");
    }

    private static void DrawTutorialLegendRow(FontAwesomeIcon icon, string label, string explanation)
    {
        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        ImGui.TextUnformatted(icon.ToIconString());
        ImGui.PopFont();
        ImGui.SameLine(0f, Ui(10f));
        ImGui.TextUnformatted(label);
        ImGui.TableSetColumnIndex(1);
        ImGui.TextWrapped(explanation);
    }

    private static void DrawTutorialColorRow(Vector4 color, string label, string explanation)
    {
        var start = ImGui.GetCursorScreenPos();
        var size = Ui(14f);
        ImGui.GetWindowDrawList().AddRectFilled(start + Ui(1f, 2f), start + new Vector2(size, size + Ui(1f)),
            ImGui.ColorConvertFloat4ToU32(color), Ui(3f));
        ImGui.Dummy(new Vector2(size + Ui(5f), size + Ui(3f)));
        ImGui.SameLine(0f, Ui(5f));
        ImGui.TextUnformatted(label);
        ImGui.SameLine(0f, Ui(8f));
        ImGui.TextWrapped(explanation);
    }

    private static void DrawTutorialDecisionNote()
    {
        ImGui.Spacing();
        ImGui.TextWrapped("A warning means ‘take a look before installing’, not ‘this plugin is bad’. You stay in control of the final choice.");
    }

    private void DrawTutorialPermissionChoices()
    {
        ImGui.Spacing();
        var changed = false;
        var bot = configuration.WarnOnBotLikeAutomation;
        var camera = configuration.WarnOnCameraControl;
        var chat = configuration.WarnOnChatControl;
        var menu = configuration.WarnOnMenuControl;
        if (ImGui.Checkbox("Stop for gameplay automation", ref bot))
        {
            configuration.WarnOnBotLikeAutomation = bot;
            changed = true;
        }
        if (ImGui.Checkbox("Stop for camera control", ref camera))
        {
            configuration.WarnOnCameraControl = camera;
            changed = true;
        }
        if (ImGui.Checkbox("Stop for chat control", ref chat))
        {
            configuration.WarnOnChatControl = chat;
            changed = true;
        }
        if (ImGui.Checkbox("Stop for menu control", ref menu))
        {
            configuration.WarnOnMenuControl = menu;
            changed = true;
        }
        if (changed)
            configuration.Save();
        ImGui.TextWrapped("You can change these later in Settings → General → Install permissions.");
    }
}

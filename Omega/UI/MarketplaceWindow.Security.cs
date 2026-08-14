using System.Diagnostics;
using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

/// <summary>
/// Presents the repository-side security controls that ship with Omega. "Configured" describes the
/// workflow included in this release; live findings remain GitHub-owned and are opened in-browser.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private bool DrawSettingsNavigationOrSecurity()
    {
        ImGui.Text("Settings");
        DrawSettingsEulaShortcut();

        if (ImGui.Button(settingsPanel == SettingsPanel.Sources ? "[Sources]" : "Sources"))
            settingsPanel = SettingsPanel.Sources;
        ImGui.SameLine();
        if (ImGui.Button(settingsPanel == SettingsPanel.Security ? "[Security]" : "Security"))
            settingsPanel = SettingsPanel.Security;
        ImGui.Separator();

        if (eulaReviewOpen || settingsPanel != SettingsPanel.Security)
            return eulaReviewOpen;

        DrawSecuritySettings();
        return true;
    }

    private void DrawSecuritySettings()
    {
        ImGui.TextDisabled("Project security");
        ImGui.TextWrapped("Omega ships repository workflows for code, dependency, supply-chain, and release provenance checks. Configured means the workflow is present in this source release; GitHub remains the source of truth for live results.");
        ImGui.Spacing();

        if (ImGui.BeginTable("omega-security-features", 3, ImGuiTableFlags.BordersInnerH, new Vector2(860f, 270f), 0f))
        {
            ImGui.TableSetupColumn("Feature", ImGuiTableColumnFlags.WidthFixed, 180f);
            ImGui.TableSetupColumn("State", ImGuiTableColumnFlags.WidthFixed, 105f);
            ImGui.TableSetupColumn("Purpose", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableHeadersRow();
            DrawSecurityFeature("CodeQL", "Configured", "C# static code scanning on pushes, pull requests, and a weekly schedule.");
            DrawSecurityFeature("Dependency review", "Configured", "Checks dependency changes in pull requests for known vulnerabilities.");
            DrawSecurityFeature("OpenSSF Scorecard", "Configured", "Publishes supply-chain posture results and SARIF findings.");
            DrawSecurityFeature("Dependabot", "Configured", "Keeps NuGet packages and GitHub Actions references under update review.");
            DrawSecurityFeature("Build provenance", "Configured", "Release workflow attests the published Omega.zip artifact with GitHub artifact attestations.");
            DrawSecurityFeature("SQLite catalog integrity", updates.ModeLabel, "SHA-256 transport/database validation, SQLite integrity checks, and last-known-good local fallback.");
            ImGui.EndTable();
        }

        ImGui.Spacing();
        ImGui.TextDisabled("Runtime catalog");
        ImGui.TextWrapped(updates.OnlineConfigured
            ? $"Central SQLite catalog endpoint is configured. Current runtime mode: {updates.ModeLabel}."
            : "No online catalog endpoint is configured; Omega is using its packaged/local SQLite catalog.");
        if (!string.IsNullOrWhiteSpace(updates.LastOnlineError))
            ImGui.TextDisabled($"Last online catalog error: {updates.LastOnlineError}");

        ImGui.Spacing();
        if (ImGui.Button("GitHub Security"))
            OpenSecurityUrl("https://github.com/dalagab/omega/security");
        ImGui.SameLine();
        if (ImGui.Button("Actions"))
            OpenSecurityUrl("https://github.com/dalagab/omega/actions");
        ImGui.SameLine();
        if (ImGui.Button("Security policy"))
            OpenSecurityUrl("https://github.com/dalagab/omega/security/policy");
        ImGui.SameLine();
        if (ImGui.Button("Close"))
        {
            settingsOpen = false;
            ImGui.CloseCurrentPopup();
        }
    }

    private static void DrawSecurityFeature(string name, string state, string purpose)
    {
        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        ImGui.TextUnformatted(name);
        ImGui.TableSetColumnIndex(1);
        ImGui.TextColored(new Vector4(0.34f, 0.78f, 0.61f, 1f), state);
        ImGui.TableSetColumnIndex(2);
        ImGui.TextWrapped(purpose);
    }

    private static void OpenSecurityUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not open security URL {Url}.", url);
        }
    }
}

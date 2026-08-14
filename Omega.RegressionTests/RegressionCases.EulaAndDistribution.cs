using System.Text.Json;
using System.Xml.Linq;

namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestEulaFirstUseContract()
    {
        var configuration = File.ReadAllText(Path.Combine(Root, "Omega", "Configuration.cs"));
        Contains(configuration, "public bool EulaAccepted", "EULA acceptance flag is persisted");
        Contains(configuration, "EulaAcceptedAtUtc", "EULA acceptance timestamp is persisted");

        var window = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.cs"));
        Contains(window, "if (!configuration.EulaAccepted)", "catalogue is gated before first-use EULA acceptance");
        Contains(window, "DrawRequiredEulaGate", "required EULA gate owns first-use blocking flow");

        var eulaUi = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Eula.cs"));
        Contains(eulaUi, "EulaAcceptanceDelaySeconds = 15", "first-use agreement has a 15-second reading delay");
        Contains(eulaUi, "Decline / Close Omega", "decline remains immediately available");
        Contains(eulaUi, "configuration.EulaAccepted = true", "acceptance is recorded only after explicit action");
        Contains(eulaUi, "configuration.EulaAcceptedAtUtc = DateTimeOffset.UtcNow", "acceptance timestamp is recorded");
        Contains(eulaUi, "eulaDocumentAvailable && remaining <= 0", "missing EULA document fails closed instead of allowing acceptance");
        Contains(eulaUi, "https://github.com/dalagab/omega", "EULA UI points to the public project site");

        Contains(eulaUi, "View EULA / Risk Disclosure", "Settings can reopen the EULA after acceptance");

        var project = XDocument.Load(Path.Combine(Root, "Omega", "DalagabOmega.csproj"));
        True(project.Descendants("Content").Any(x =>
            string.Equals((string?)x.Attribute("Include"), @"..\EULA.md", StringComparison.OrdinalIgnoreCase)),
            "EULA.md is copied into the Dalamud plugin output");

        var eula = File.ReadAllText(Path.Combine(Root, "EULA.md"));
        Contains(eula, "Omega End User License Agreement and Third-Party Plugin Risk Disclosure", "authoritative EULA document is present");
        Contains(eula, "Routine Omega updates, catalogue updates", "acceptance remains first-use-only across routine updates");
        Contains(eula, "https://github.com/dalagab/omega", "EULA document points to the GitHub project");
    }

    internal static void TestGitHubDistributionDocumentationContract()
    {
        var readme = File.ReadAllText(Path.Combine(Root, "README.md"));
        Contains(readme, "open-source visual marketplace for Dalamud plugins", "GitHub README explains the product");
        Contains(readme, "Install Omega normally through Dalamud", "README keeps installation inside Dalamud");
        Contains(readme, "Install-OmegaRepository.ps1", "README documents the source-registration installer");
        Contains(readme, "does **not** install Omega itself", "README explains the installer trust boundary");
        Contains(readme, @"%APPDATA%\XIVLauncher\dalamudConfig.json", "README identifies the modified Dalamud config file");

        var installer = File.ReadAllText(Path.Combine(Root, "installer", "Install-OmegaRepository.ps1"));
        Contains(installer, "ThirdRepoList", "installer only targets Dalamud custom repositories");
        Contains(installer, "Assert-DalamudIsNotRunning", "installer prevents live config races");
        Contains(installer, "Backup-DalamudConfiguration", "installer creates a rollback copy before writing");
        Contains(installer, "Write-DalamudConfigurationAtomically", "installer uses a bounded atomic-write path");
        Contains(installer, "WhatIfOnly", "installer supports a no-write preview");

        var installerDocs = File.ReadAllText(Path.Combine(Root, "installer", "README.md"));
        Contains(installerDocs, "Functions in `Install-OmegaRepository.ps1`", "installer is documented function by function");
        Contains(installerDocs, "It does **not** copy DLLs", "installer docs enumerate excluded OS changes");

        using var master = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "repository", "pluginmaster.json")));
        var omega = master.RootElement.EnumerateArray().Single();
        Equal("DalagabOmega", RequiredString(omega, "InternalName"), "public repository manifest targets Omega");
        Equal("https://github.com/dalagab/omega", RequiredString(omega, "RepoUrl"), "public repository manifest points back to project source");
        var project = XDocument.Load(Path.Combine(Root, "Omega", "DalagabOmega.csproj"));
        var projectVersion = project.Descendants("Version").Single().Value.Trim();
        Equal(projectVersion, RequiredString(omega, "AssemblyVersion"), "public repository manifest version follows the Omega build");
    }

    internal static void TestGitHubReleaseAndSecurityWorkflowsContract()
    {
        var release = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "release.yml"));
        Contains(release, "v*.*.*.*", "release workflow is tag-driven");
        Contains(release, "dotnet build .\\Omega.sln -c Release", "release workflow builds the complete solution and regression suite");
        Contains(release, "latest.zip", "release workflow consumes the Dalamud.NET.Sdk package");
        Contains(release, "Omega.zip", "stable Dalamud release asset is published under the PluginMaster name");
        Contains(release, "omega-latest", "release workflow refreshes the stable repository endpoint");
        Contains(release, "actions/attest@v4", "release artifact receives GitHub build-provenance attestation");

        var codeql = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "codeql.yml"));
        Contains(codeql, "github/codeql-action/init@v4", "CodeQL advanced workflow is configured");
        Contains(codeql, "build-mode: none", "C# CodeQL analysis does not depend on the game runtime build environment");

        var dependency = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "dependency-review.yml"));
        Contains(dependency, "actions/dependency-review-action@v4", "dependency review is configured for pull requests");

        var scorecard = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "scorecards.yml"));
        Contains(scorecard, "ossf/scorecard-action@v2.4.4", "OpenSSF Scorecard workflow is configured");
        Contains(scorecard, "publish_results: true", "Scorecard results can be surfaced by the public Scorecard service");

        var dependabot = File.ReadAllText(Path.Combine(Root, ".github", "dependabot.yml"));
        Contains(dependabot, "package-ecosystem: nuget", "Dependabot watches NuGet dependencies");
        Contains(dependabot, "package-ecosystem: github-actions", "Dependabot watches workflow action dependencies");

        var securityUi = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Security.cs"));
        Contains(securityUi, "Project security", "Settings exposes the configured project security features");
        Contains(securityUi, "SQLite catalog integrity", "Settings explains runtime catalog integrity protection");
        Contains(securityUi, "GitHub Security", "Settings links to live GitHub security results");

        var availability = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Availability.cs"));
        Contains(availability, "ImGuiCol.Text", "unavailable listings replace white primary text");
        Contains(availability, "0.42f", "unavailable listings use a dark-grey primary text tone");
        Contains(availability, "HasInstallableVariant", "availability styling follows current compatible install candidates");

        var spotlight = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Spotlight.cs"));
        Contains(spotlight, "honse-farm", "missing HonseFarm Spotlight entries request the curated source refresh path");
        Contains(spotlight, "TextDisabled(\"Loading highlighted plugin…\")", "missing Spotlight entries remain visibly unavailable rather than bright white");
    }

}

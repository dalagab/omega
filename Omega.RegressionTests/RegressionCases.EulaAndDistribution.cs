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

        Contains(eulaUi, "View EULA", "Settings can reopen the EULA after acceptance");
        False(eulaUi.Contains("View EULA / Risk Disclosure", StringComparison.Ordinal), "Settings does not relabel the EULA as a risk disclosure");

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
        Equal("Every plugin. One orbit.", RequiredString(omega, "Punchline"), "Dalamud listing uses the Omega product tagline");
        var listingDescription = RequiredString(omega, "Description");
        Contains(listingDescription, "/omega", "Dalamud listing advertises the primary command");
        Contains(listingDescription, "/omg", "Dalamud listing advertises the command alias");
        Contains(listingDescription, "Spotlight", "Dalamud listing sells the storefront experience");
        False(listingDescription.Contains("Definitions database", StringComparison.OrdinalIgnoreCase), "Dalamud listing avoids implementation-oriented database copy");
        Equal("https://github.com/dalagab/omega", RequiredString(omega, "RepoUrl"), "public repository manifest points back to project source");
        var project = XDocument.Load(Path.Combine(Root, "Omega", "DalagabOmega.csproj"));
        var projectVersion = project.Descendants("Version").Single().Value.Trim();
        Equal(projectVersion + ".0", RequiredString(omega, "AssemblyVersion"), "public repository manifest uses the four-part CLR/Dalamud assembly version");
    }

    internal static void TestGitHubReleaseAndSecurityWorkflowsContract()
    {
        var release = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "release.yml"));
        Contains(release, "v*.*.*", "release workflow is tag-driven with three-part versions");
        DoesNotContain(release, "v*.*.*.*", "release workflow does not accept four-part ZipRunner-incompatible tags");
        Contains(release, "dotnet build .\\Omega.sln -c Release", "release workflow builds the complete solution and regression suite");
        Contains(release, "latest.zip", "release workflow consumes the Dalamud.NET.Sdk package");
        Contains(release, "Omega.zip", "stable Dalamud release asset is published under the PluginMaster name");
        Contains(release, "omega-latest", "release workflow refreshes the stable repository endpoint");
        Contains(release, "actions/attest@v4", "release artifact receives GitHub build-provenance attestation");
        Contains(release, "$expectedAssemblyVersion = \"$tagVersion.0\"", "three-part release tags map to four-part CLR/Dalamud assembly versions");
        Contains(release, "Distributed plugin version $distributedVersion does not match repo version $repoVersion", "release refuses to publish a package/repository version mismatch");
        Contains(release, "e_sqlite3.dll", "release package explicitly carries Omega's private SQLite native runtime");
        Contains(release, "SQLitePCLRaw.provider.e_sqlite3.dll", "release verifies the matching e_sqlite3 managed provider is present");

        var productProjectText = File.ReadAllText(Path.Combine(Root, "Omega", "DalagabOmega.csproj"));
        Contains(productProjectText, "SQLitePCLRaw.bundle_e_sqlite3", "production SQLite uses the bundled native e_sqlite3 runtime");
        Contains(productProjectText, "CopyOmegaSqliteNativeToPluginDirectory", "build places the native SQLite runtime beside the plugin assembly");
        Contains(productProjectText, @"runtimes\win-x64\native\e_sqlite3.dll", "build selects the Windows x64 SQLite binary used by FFXIV/Dalamud under Windows or Wine");
        DoesNotContain(productProjectText, "SQLitePCLRaw.provider.winsqlite3", "production SQLite must not depend on Windows' optional winsqlite3 system DLL");
        var sqliteStore = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "SqliteCatalogStore.cs"));
        Contains(sqliteStore, "SQLitePCL.Batteries_V2.Init()", "SQLite bundle provider initialization is explicit and portable under Wine");
        DoesNotContain(sqliteStore, "SQLite3Provider_winsqlite3", "runtime code cannot regress to the host winsqlite3 provider");

        var codeql = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "codeql.yml"));
        Contains(codeql, "github/codeql-action/init@v4", "CodeQL advanced workflow is configured");
        Contains(codeql, "build-mode: none", "C# CodeQL analysis does not depend on the game runtime build environment");

        var dependency = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "dependency-review.yml"));
        Contains(dependency, "actions/dependency-review-action@v5", "dependency review is configured for pull requests");

        var scorecard = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "scorecards.yml"));
        Contains(scorecard, "ossf/scorecard-action@v2.4.4", "OpenSSF Scorecard workflow is configured");
        Contains(scorecard, "publish_results: true", "Scorecard results can be surfaced by the public Scorecard service");

        var dependabot = File.ReadAllText(Path.Combine(Root, ".github", "dependabot.yml"));
        Contains(dependabot, "package-ecosystem: nuget", "Dependabot watches NuGet dependencies");
        Contains(dependabot, "package-ecosystem: github-actions", "Dependabot watches workflow action dependencies");

        var settingsUi = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Security.cs"));
        Contains(settingsUi, "DrawSettingsHeader", "Settings keeps a shared user-facing header");
        False(settingsUi.Contains("Project security", StringComparison.Ordinal), "developer security workflow status stays out of in-game Settings");
        False(settingsUi.Contains("CodeQL", StringComparison.Ordinal), "repository scanner names stay out of in-game Settings");
        False(settingsUi.Contains("Runtime catalog", StringComparison.Ordinal), "catalog implementation state stays out of in-game Settings");
        False(settingsUi.Contains("GitHub Security", StringComparison.Ordinal), "developer security links stay out of in-game Settings");

        var sourcesUi = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Sources.cs"));
        Contains(sourcesUi, "Choose which plugin sources appear in Omega", "Settings explains sources in user-facing language");
        False(sourcesUi.Contains("SQLite catalog:", StringComparison.Ordinal), "source settings do not expose catalog implementation details");

        var scannerWorkflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "security-scanner.yml"));
        Contains(scannerWorkflow, "Omega plugin security scanner", "third-party plugin security scanner workflow is configured");
        Contains(scannerWorkflow, "omega-security-evidence.sqlite.zip", "security scanner enriches the separate server-side evidence database");
        False(scannerWorkflow.Contains("gh release upload catalog-latest", StringComparison.Ordinal), "scanner never publishes a client database directly");

        var availability = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Availability.cs"));
        Contains(availability, "ImGuiCol.Text", "unavailable listings replace white primary text");
        Contains(availability, "0.42f", "unavailable listings use a dark-grey primary text tone");
        Contains(availability, "HasInstallableVariant", "availability styling follows current compatible install candidates");

        var spotlight = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Spotlight.cs"));
        Contains(spotlight, "honse-farm", "missing HonseFarm Spotlight entries request the curated source refresh path");
        Contains(spotlight, "TextDisabled(\"Loading highlighted plugin…\")", "missing Spotlight entries remain visibly unavailable rather than bright white");
    }

}

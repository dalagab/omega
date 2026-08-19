using System.Text.Json;
using System.Text.RegularExpressions;
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

    internal static void TestProductionSourceDistributionContract()
    {
        var runtimeMigration = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "OmegaRepositoryMigrationService.cs"));
        Contains(runtimeMigration, "LegacyRepositoryUrl", "runtime migration recognizes only Omega's exact historical feed");
        Contains(runtimeMigration, "CanonicalRepositoryUrl = OmegaSelfUpdateService.RepositoryManifestUrl", "runtime migration shares the canonical generated feed endpoint");
        Contains(runtimeMigration, "ValidateCanonicalFeedAsync", "runtime migration validates the stable feed before touching Dalamud state");
        Contains(runtimeMigration, "ex.StatusCode == HttpStatusCode.NotFound", "runtime migration quietly waits until the generated stable feed exists");
        Contains(runtimeMigration, "IsSafeCanonicalEntry", "runtime migration validates identity, version, and immutable package linkage");
        DoesNotContain(runtimeMigration, "dalamudConfig.json", "runtime migration never edits Dalamud's configuration file directly");
        DoesNotContain(runtimeMigration, "File.Write", "runtime migration never writes installed plugin or Dalamud files directly");

        var repositoryBridge = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudRepositoryBridge.cs"));
        Contains(repositoryBridge, "MigrateKnownInstalledPluginRepositoryAsync", "Dalamud bridge exposes the bounded self-repository migration operation");
        Contains(repositoryBridge, "Set(localManifest, \"InstalledFromUrl\", canonical)", "migration retargets live update provenance before reloading repositories");
        Contains(repositoryBridge, "if (installedFromLegacy)", "migration retains legacy servicing until a normal Dalamud update persists canonical provenance");
        Contains(repositoryBridge, "context.RepositoryList.Remove(legacySetting)", "migration removes the legacy row after canonical provenance is no longer pending");
        Contains(repositoryBridge, "await RefreshDalamudRepositoriesAsync", "migration asks Dalamud to rebuild repositories only after source/provenance agree");

        using var master = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "repository", "pluginmaster.json")));
        var omega = master.RootElement.EnumerateArray().Single();
        Equal("DalagabOmega", RequiredString(omega, "InternalName"), "public repository manifest targets Omega");
        Equal("Every plugin. One orbit.", RequiredString(omega, "Punchline"), "Dalamud listing uses the Omega product tagline");
        Equal("https://github.com/dalagab/omega", RequiredString(omega, "RepoUrl"), "public repository manifest points back to project source");
        var publicAssemblyVersion = RequiredString(omega, "AssemblyVersion");
        var publicDownload = RequiredString(omega, "DownloadLinkInstall");
        var match = System.Text.RegularExpressions.Regex.Match(publicDownload, @"/releases/download/v(\d+\.\d+\.\d+)/Omega\.zip$");
        True(match.Success, "legacy raw-main manifest points to an immutable tagged Omega.zip");
        Equal(match.Groups[1].Value + ".0", publicAssemblyVersion, "legacy raw-main manifest version matches its immutable package URL");
        Equal(publicDownload, RequiredString(omega, "DownloadLinkUpdate"), "legacy install and update URLs are identical");

        var required = new[]
        {
            "Omega.sln",
            "Omega/DalagabOmega.csproj",
            "Omega.RegressionTests/Omega.RegressionTests.csproj",
            "EULA.md",
            "CHANGELOG.md",
            "README.md",
            "SECURITY.md",
            ".omega/index.json",
            "images/omega-banner.png",
            "catalog/catalog-endpoint.json",
            "sources/curated-sources.json",
            "tools/catalog/sigmascope.py",
            "tools/security/production_sigmascope_v2_pipeline.py",
            ".github/workflows/regression-tests.yml",
            ".github/workflows/catalog-builder.yml",
            ".github/workflows/sigmascope.yml",
            ".github/workflows/release.yml",
        };
        foreach (var relative in required)
            True(File.Exists(Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar))), $"lean production source keeps {relative}");

        var omegaIndex = File.ReadAllText(Path.Combine(Root, ".omega", "index.json"));
        Contains(omegaIndex, "OmegaBannerUrl", "lean production source keeps Omega's scrapeable repository metadata");
        Contains(omegaIndex, "images/omega-banner.png", "Omega self metadata points at the retained repository banner");
        var catalogWorkflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "catalog-builder.yml"));
        Contains(catalogWorkflow, "cron: \"17 2 * * *\"", "Omega repository metadata enters the once-daily catalog snapshot instead of causing update churn");
        False(Regex.IsMatch(catalogWorkflow, @"(?m)^  push:\s*$"), "repository metadata changes do not trigger extra client database publications");
        var websiteScraper = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "scrape_websites.py"));
        Contains(websiteScraper, ".omega/index.json", "daily enrichment still consumes Omega's scrapeable repository metadata");

        var readme = File.ReadAllText(Path.Combine(Root, "README.md"));
        Contains(readme, "Build Omega", "lean production README documents the application build");
        Contains(readme, "Sigmascope", "lean production README documents Sigmascope tooling");
        Contains(readme, ".omega/index.json", "lean production README documents scrapeable Omega metadata");
        DoesNotContain(readme, "Install-OmegaRepository.ps1", "lean production README does not resurrect the retired installer path");

        var securityPolicy = File.ReadAllText(Path.Combine(Root, "SECURITY.md"));
        Contains(securityPolicy, "Reporting a vulnerability", "lean production security policy retains private-reporting guidance");
        Contains(securityPolicy, "Sigmascope", "lean production security policy documents Sigmascope");
        Contains(securityPolicy, "Security Evidence v2", "lean production security policy documents the evidence publication model");
        Contains(securityPolicy, "catalog/catalog-endpoint.json", "lean production security policy documents runtime catalog safety");
        DoesNotContain(securityPolicy, "CodeQL", "lean production security policy does not claim removed CodeQL workflow coverage");

        // ZipRunner publishes source ZIPs as overlays onto an existing checkout. Files removed
        // from the production snapshot can therefore remain on disk from an older build. Do not
        // use workspace absence as the C# contract; clean-checkout/package absence is enforced by
        // tools/tests/test_production_release_hygiene.py. Here we verify that retained production
        // entry points no longer depend on the retired website/installer toolchain.
        var projectText = File.ReadAllText(Path.Combine(Root, "Omega", "DalagabOmega.csproj"));
        var releaseWorkflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "release.yml"));
        var regressionWorkflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "regression-tests.yml"));

        foreach (var retiredReference in new[]
                 {
                     "tools/site",
                     "package.json",
                     "package-lock.json",
                     "Install-OmegaRepository.ps1",
                     "actions/deploy-pages",
                 })
        {
            DoesNotContain(projectText, retiredReference, $"Omega project does not depend on retired website/installer material: {retiredReference}");
            DoesNotContain(releaseWorkflow, retiredReference, $"release workflow does not depend on retired website/installer material: {retiredReference}");
        }

        DoesNotContain(regressionWorkflow, "tools/tests/test_site_contracts.py", "main regression workflow does not depend on website-only tests");
        DoesNotContain(regressionWorkflow, "tools/site", "main regression workflow does not depend on website-only tooling");
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
        Contains(release, "generate_pluginmaster.py", "release workflow generates PluginMaster from the built package");
        Contains(release, "Verify immutable versioned release asset", "release verifies the remotely published immutable package before advancing the stable feed");
        Contains(release, "Publish legacy raw-main PluginMaster compatibility mirror", "release keeps old raw-main repository registrations serviceable without development drift");
        Contains(release, "actions/attest@v4", "release artifact receives GitHub build-provenance attestation");
        Contains(release, "Distributed plugin version $distributedVersion does not match release tag assembly version $expectedAssemblyVersion", "release refuses to publish a package/tag version mismatch");
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

        var settingsUi = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Security.cs"));
        Contains(settingsUi, "DrawSettingsGeneralTab", "Settings keeps update controls in their own General tab");
        Contains(settingsUi, "DrawSettingsLegalTab", "Settings keeps EULA controls in their own Legal tab");
        False(settingsUi.Contains("Project security", StringComparison.Ordinal), "developer security workflow status stays out of in-game Settings");
        False(settingsUi.Contains("CodeQL", StringComparison.Ordinal), "repository analysis-tool names stay out of in-game Settings");
        False(settingsUi.Contains("Runtime catalog", StringComparison.Ordinal), "catalog implementation state stays out of in-game Settings");
        False(settingsUi.Contains("GitHub Security", StringComparison.Ordinal), "developer security links stay out of in-game Settings");

        var sourcesUi = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Sources.cs"));
        Contains(sourcesUi, "Repositories published through Omega Definitions", "Settings explains the separate online Omega source list in user-facing language");
        Contains(sourcesUi, "Repositories configured in Dalamud", "Settings explains the separate local Dalamud source list in user-facing language");
        False(sourcesUi.Contains("SQLite catalog:", StringComparison.Ordinal), "source settings do not expose catalog implementation details");

        var sigmascopeWorkflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "sigmascope.yml"));
        Contains(sigmascopeWorkflow, "Omega Sigmascope continuous worker", "third-party plugin analysis is configured through the continuous Sigmascope worker");
        Contains(sigmascopeWorkflow, "security-evidence-v2", "Sigmascope uses the dedicated detailed evidence snapshot branch");
        Contains(sigmascopeWorkflow, "publish_security_evidence_v2.py", "detailed evidence publication is fail-closed through the v2 publisher");
        Contains(sigmascopeWorkflow, "--skip-marketplace", "continuous Sigmascope never publishes the client Definitions database");
        False(sigmascopeWorkflow.Contains("gh release upload catalog-latest", StringComparison.Ordinal), "continuous security analysis cannot churn the client database");
        var dailyCatalogWorkflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "catalog-builder.yml"));
        Contains(dailyCatalogWorkflow, "gh release upload catalog-latest", "only the daily/manual validated catalog compiler publishes the small client marketplace assets");
        False(sigmascopeWorkflow.Contains("omega-security-evidence.sqlite.zip", StringComparison.Ordinal), "production Sigmascope no longer handles the archived giant v1 evidence bundle");

        var availability = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Availability.cs"));
        Contains(availability, "ImGuiCol.Text", "unavailable listings replace white primary text");
        Contains(availability, "0.42f", "unavailable listings use a dark-grey primary text tone");
        Contains(availability, "HasInstallableVariant", "availability styling follows current compatible install candidates");

        var spotlight = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Spotlight.cs"));
        Contains(spotlight, "honse-farm", "missing HonseFarm Spotlight entries request the curated source refresh path");
        Contains(spotlight, "TextDisabled(\"Loading highlighted plugin…\")", "missing Spotlight entries remain visibly unavailable rather than bright white");
    }

}

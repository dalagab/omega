using Dalagab.Omega;

namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestDependencyResolverRecursiveClosure()
    {
        var a = PlanPlugin(1, 101, "A", "3.4", 15, "ARepo");
        var b = PlanPlugin(2, 201, "B", "2.3", 15, "BRepo");
        var c = PlanPlugin(3, 301, "C", "4.4", 15, "CRepo");
        var d = PlanPlugin(4, 401, "D", "1.8", 15, "DRepo");
        var edges = new Dictionary<long, IReadOnlyList<PluginDependencyEdge>>
        {
            [101] = [Edge(101, 1, "A", 2, "B", ">=2"), Edge(101, 1, "A", 3, "C", ">=4.1")],
            [201] = [Edge(201, 2, "B", 4, "D", ">=1.5")],
        };
        var installed = new Dictionary<string, PluginInstalledState>(StringComparer.OrdinalIgnoreCase)
        {
            ["B"] = new("B", new Version(2, 3), b.SourceUrl),
            ["C"] = new("C", new Version(4, 0), c.SourceUrl),
        };
        var plan = ResolvePlan(a, [a, b, c, d], edges, installed);

        True(plan.IsValid, "recursive required dependency plan is valid");
        Equal(4, plan.Operations.Count, "recursive closure contains root plus three providers");
        Equal(PluginInstallAction.Keep, plan.Operations.Single(x => x.InternalName == "B").Action, "satisfying installed provider is kept");
        Equal(PluginInstallAction.Update, plan.Operations.Single(x => x.InternalName == "C").Action, "installed provider below constraint is updated");
        Equal(PluginInstallAction.Install, plan.Operations.Single(x => x.InternalName == "D").Action, "leaf provider is installed");
        Equal("D", plan.Operations[0].InternalName, "leaf dependency executes first");
        Equal("A", plan.Operations[^1].InternalName, "requested root executes last");
    }

    internal static void TestDependencyResolverConstraintIntersectionAndConflicts()
    {
        var a = PlanPlugin(1, 101, "A", "1.0", 15, "ARepo");
        var b2 = PlanPlugin(2, 201, "B", "2.5", 15, "BRepo");
        var b3 = PlanPlugin(2, 202, "B", "3.4", 15, "BRepo");
        var c = PlanPlugin(3, 301, "C", "1.0", 15, "CRepo");
        var edges = new Dictionary<long, IReadOnlyList<PluginDependencyEdge>>
        {
            [101] = [Edge(101, 1, "A", 2, "B", ">=2"), Edge(101, 1, "A", 3, "C", "")],
            [301] = [Edge(301, 3, "C", 2, "B", ">=3")],
        };
        var plan = ResolvePlan(a, [a, b2, b3, c], edges);
        True(plan.IsValid, "compatible multiple constraints intersect");
        Equal(new Version(3, 4), plan.Operations.Single(x => x.InternalName == "B").TargetVersion, "intersection selects provider satisfying strongest lower bound");
        Contains(plan.Operations.Single(x => x.InternalName == "B").EffectiveVersionConstraint, ">=2", "effective constraint retains first consumer");
        Contains(plan.Operations.Single(x => x.InternalName == "B").EffectiveVersionConstraint, ">=3", "effective constraint retains second consumer");

        var conflicting = new Dictionary<long, IReadOnlyList<PluginDependencyEdge>>(edges)
        {
            [101] = [Edge(101, 1, "A", 2, "B", "<3"), Edge(101, 1, "A", 3, "C", "")],
            [301] = [Edge(301, 3, "C", 2, "B", ">=4")],
        };
        var invalid = ResolvePlan(a, [a, b2, b3, c], conflicting);
        True(!invalid.IsValid, "incompatible intersected constraints invalidate plan");
        True(invalid.Conflicts.Any(x => x.InternalName == "B"), "conflict identifies provider");
    }

    internal static void TestDependencyResolverFailsClosedForMissingUnknownAndCycles()
    {
        var a = PlanPlugin(1, 101, "A", "1.0", 15, "ARepo");
        var missing = ResolvePlan(a, [a], new Dictionary<long, IReadOnlyList<PluginDependencyEdge>>
        {
            [101] = [Edge(101, 1, "A", 9, "Missing", ">=1")],
        });
        True(!missing.IsValid, "missing required provider fails before mutation");
        True(missing.Conflicts.Any(x => x.Kind == PluginInstallConflictKind.MissingProvider), "missing provider conflict kind is explicit");

        var b = PlanPlugin(2, 201, "B", "2.0", 15, "BRepo");
        var unknown = ResolvePlan(a, [a, b], new Dictionary<long, IReadOnlyList<PluginDependencyEdge>>
        {
            [101] = [Edge(101, 1, "A", 2, "B", "^2.0")],
        });
        True(!unknown.IsValid, "unknown version grammar fails closed");
        True(unknown.Conflicts.Any(x => x.Kind == PluginInstallConflictKind.InvalidVersionConstraint), "unknown grammar is reported as invalid constraint");

        var cycle = ResolvePlan(a, [a, b], new Dictionary<long, IReadOnlyList<PluginDependencyEdge>>
        {
            [101] = [Edge(101, 1, "A", 2, "B", ">=1")],
            [201] = [Edge(201, 2, "B", 1, "A", ">=1")],
        });
        True(!cycle.IsValid, "required dependency cycle fails");
        True(cycle.Conflicts.Any(x => x.Kind == PluginInstallConflictKind.RequiredDependencyCycle), "cycle is surfaced explicitly");
    }

    internal static void TestDependencyResolverOptionalAndIpcBoundary()
    {
        var a = PlanPlugin(1, 101, "A", "1.0", 15, "ARepo");
        var b = PlanPlugin(2, 201, "B", "1.0", 15, "BRepo");
        var c = PlanPlugin(3, 301, "C", "1.0", 15, "CRepo");
        var d = PlanPlugin(4, 401, "D", "1.0", 15, "DRepo");
        var edges = new Dictionary<long, IReadOnlyList<PluginDependencyEdge>>
        {
            [101] =
            [
                Edge(101, 1, "A", 2, "B", "", PluginDependencyRelationship.Recommended),
                Edge(101, 1, "A", 3, "C", "", PluginDependencyRelationship.Optional),
                Edge(101, 1, "A", 4, "D", "", PluginDependencyRelationship.Required, sourceKind: "ipc"),
            ],
        };
        var baseline = ResolvePlan(a, [a, b, c, d], edges);
        Equal(1, baseline.Operations.Count, "recommended optional and IPC relationships are not silently installed");
        True(baseline.Suggestions.Any(x => x.ProviderInternalName == "B" && !x.Selected), "recommended provider is presented as suggestion");
        True(baseline.Suggestions.Any(x => x.ProviderInternalName == "C" && !x.Selected), "optional provider is presented as suggestion");
        True(!baseline.Operations.Any(x => x.InternalName == "D"), "IPC never enters package closure");

        var selected = ResolvePlan(a, [a, b, c, d], edges, explicitDependencies: new HashSet<string>(["B"], StringComparer.OrdinalIgnoreCase));
        True(selected.Operations.Any(x => x.InternalName == "B" && x.Reason == PluginInstallReason.ExplicitRecommendedDependency), "recommended dependency enters closure only after explicit selection");
        True(!selected.Operations.Any(x => x.InternalName == "C"), "unselected optional provider remains excluded");
    }

    internal static void TestDependencyResolverCompatibilityAndDeterministicSourceSelection()
    {
        var a = PlanPlugin(1, 101, "A", "1.0", 15, "ARepo");
        var badApi = PlanPlugin(2, 201, "B", "9.0", 16, "NewApiRepo");
        var tooNewDalamud = PlanPlugin(2, 202, "B", "8.0", 15, "NewDalamudRepo", minimumDalamud: "99.0");
        var official = PlanPlugin(2, 203, "B", "3.0", 15, "Dalamud", official: true);
        var community = PlanPlugin(2, 204, "B", "4.0", 15, "Community");
        var edges = new Dictionary<long, IReadOnlyList<PluginDependencyEdge>>
        {
            [101] = [Edge(101, 1, "A", 2, "B", ">=2")],
        };
        var plan = ResolvePlan(a, [a, badApi, tooNewDalamud, community, official], edges);
        True(plan.IsValid, "compatible provider remains selectable");
        Equal("Dalamud", plan.Operations.Single(x => x.InternalName == "B").SelectedVariant.SourceName, "official source wins deterministically before another otherwise valid source");

        var installed = new Dictionary<string, PluginInstalledState>(StringComparer.OrdinalIgnoreCase)
        {
            ["B"] = new("B", new Version(1, 0), community.SourceUrl),
        };
        var update = ResolvePlan(a, [a, community, official], edges, installed);
        Equal("Community", update.Operations.Single(x => x.InternalName == "B").SelectedVariant.SourceName, "installed source is preferred for a compatible dependency update");

        var testingOnly = new MarketplacePlugin
        {
            CatalogPluginId = 2,
            CatalogVariantId = 205,
            Name = "B",
            InternalName = "B",
            AssemblyVersionText = "1.0",
            DalamudApiLevel = 14,
            TestingAssemblyVersionText = "5.0",
            TestingDalamudApiLevel = 15,
            DownloadLinkInstall = "https://example.invalid/b-stable.zip",
            DownloadLinkTesting = "https://example.invalid/b-testing.zip",
            SourceName = "TestingRepo",
            SourceUrl = "https://example.invalid/testing.json",
        };
        var stablePolicy = ResolvePlan(a, [a, testingOnly], edges);
        True(!stablePolicy.IsValid, "testing-only current-API package is not selected when testing preference is off");
        var testingPolicy = ResolvePlan(a, [a, testingOnly], edges, preferTesting: true);
        True(testingPolicy.IsValid, "testing current-API package is eligible only after testing preference is enabled");
        Equal(new Version(5, 0), testingPolicy.Operations.Single(x => x.InternalName == "B").TargetVersion, "testing policy selects advertised testing version");
    }

    internal static void TestDependencyInstallPlanRevisionContract()
    {
        var a = PlanPlugin(1, 101, "A", "1.0", 15, "ARepo");
        var b = PlanPlugin(2, 201, "B", "1.0", 15, "BRepo");
        var plan = ResolvePlan(a, [a, b], new Dictionary<long, IReadOnlyList<PluginDependencyEdge>>
        {
            [101] = [Edge(101, 1, "A", 2, "B", ">=1")],
        });
        Equal("catalog-test", plan.CatalogRevision, "plan freezes catalog revision");
        Equal("plugin-deps-v1-test", plan.DependencyGraphRevision, "plan freezes dependency graph revision");
        True(plan.MatchesRevisions("catalog-test", "plugin-deps-v1-test"), "plan accepts matching revisions");
        var stale = plan.MarkStaleIfRevisionsChanged("catalog-test", "plugin-deps-v1-next");
        True(stale.IsStale && !stale.IsValid, "dependency graph revision change invalidates frozen plan before execution");
        Equal(plan.PlanId, ResolvePlan(a, [a, b], new Dictionary<long, IReadOnlyList<PluginDependencyEdge>>
        {
            [101] = [Edge(101, 1, "A", 2, "B", ">=1")],
        }).PlanId, "same inputs produce deterministic plan id");
    }

    internal static void TestDependencyTransactionExecutionContract()
    {
        var ui = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.InstallPlan.cs"));
        Contains(ui, "Transaction preview", "dependency transaction preview is visible");
        Contains(ui, "Required dependencies are locked into the plan", "required dependencies are not optional checkboxes");
        Contains(ui, "Recommended and optional plugins are never added unless you select them", "non-required dependencies remain explicit");
        Contains(ui, "MarkStaleIfRevisionsChanged", "preview invalidates stale plans");
        Contains(ui, "installTransactions.ExecuteAsync", "validated dependency plan delegates to the OMEGA-3 transaction coordinator");
        Contains(ui, "Review and acknowledge each orange/red repository", "source review remains an explicit transaction gate");

        var transaction = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginInstallTransactionCoordinator.cs"));
        Contains(transaction, "PrepareRepositoryAsync", "all selected repositories are prepared before package mutation");
        Contains(transaction, "TryRevalidateSelectedVariants", "frozen selected variants are revalidated before execution");
        Contains(transaction, "OrderBy(x => x.ExecutionOrder)", "transaction executes the resolver's leaf-first order");
        Contains(transaction, "newlyInstalledDependencies", "rollback tracks only newly auto-installed dependency packages");
        Contains(transaction, "preexisting.Contains(operation.InternalName)", "rollback never removes a pre-existing package");
        Contains(transaction, "ReconcileRootDependencies", "successful root updates release stale ownership edges");
        Contains(transaction, "FindDependencyOwnedOrphans", "transaction completion detects package-manager autoremove candidates");

        var ledger = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginLibraryLedger.cs"));
        Contains(ledger, "SchemaVersion { get; set; } = 2", "ownership ledger schema is versioned");
        Contains(ledger, "InstallReason", "ownership ledger persists manual/dependency reason");
        Contains(ledger, "RequestedBy", "ownership ledger persists root requesters");
        Contains(ledger, "PromoteToManual", "explicitly claimed dependency can become manual");
        Contains(ledger, "ReconcileRootDependencies", "root updates remove no-longer-required ownership edges");

        var uninstall = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.UninstallAndSources.cs"));
        Contains(uninstall, "GetInstalledRequiredDependents", "provider uninstall consults normalized reverse dependencies");
        Contains(uninstall, "requiredDependents.Length == 0", "normal uninstall is blocked while required dependents exist");
        Contains(uninstall, "Remove unused dependencies", "dependency-owned orphans require an explicit autoremove action");
        Contains(uninstall, "Nothing is removed automatically", "autoremove never silently deletes dependency-owned plugins");

        var update = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Update.cs"));
        Contains(update, "TryOpenDependencyUpdatePlan", "plugin updates reuse the normalized dependency solver");
        Contains(update, "var dependencyPlan = ResolveInstallPlan(candidate, currentApi, currentDalamudVersion)", "Update All also consults the dependency solver before direct lifecycle mutation");
        Contains(update, "updateAllSkippedDependencyTransactions", "dependency-changing Update All entries are left for explicit transaction review instead of bypassing the solver");

        var install = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Install.cs"));
        Contains(install, "ContinueInstallSelection(selected, currentApi, currentDalamudVersion)", "repository choice resolves dependency plan before final install");
        Contains(ui, "if (!plan.HasDependencyClosure && plan.Conflicts.Count == 0)", "root without required dependency closure preserves normal install flow");
        Contains(install, "PendingDependencyPlanAllowsSinglePluginExecution", "single-plugin lifecycle cannot bypass a frozen dependency plan");
    }

    internal static void TestMigrationRepositoryProvenancePreferenceContract()
    {
        var known = new MarketplacePlugin
        {
            InternalName = "Lifestream", Name = "Lifestream", SourceName = "NightmareXIV",
            SourceUrl = "https://raw.githubusercontent.com/NightmareXIV/MyDalamudPlugins/main/pluginmaster.json",
            SecuritySourceRepository = "https://github.com/NightmareXIV/Lifestream",
        };
        var owner = new MarketplacePlugin
        {
            InternalName = "Example", Name = "Example", SourceName = "Example author",
            SourceUrl = "https://raw.githubusercontent.com/example-author/plugins/main/repo.json",
            SecuritySourceRepository = "https://github.com/example-author/example-plugin",
        };
        var mirror = new MarketplacePlugin
        {
            InternalName = "Lifestream", Name = "Lifestream", SourceName = "yourShika/AetheryteRepo",
            SourceUrl = "https://raw.githubusercontent.com/yourShika/AetheryteRepo/main/repo.json",
            SecuritySourceRepository = "https://github.com/NightmareXIV/Lifestream",
        };

        True(RepositoryProviderRules.IsSourceOwnerPublisher(known), "recognized owner repository matches plugin source owner");
        True(RepositoryProviderRules.IsSourceOwnerPublisher(owner), "source-owner publisher is detected from GitHub provenance");
        True(!RepositoryProviderRules.IsSourceOwnerPublisher(mirror), "generic mirror is not mistaken for the plugin source owner");
        True(RepositoryProviderRules.PackageProvenancePriority(known) < RepositoryProviderRules.PackageProvenancePriority(owner),
            "recognized provider is preferred before an otherwise valid source-owner feed");
        True(RepositoryProviderRules.PackageProvenancePriority(owner) < RepositoryProviderRules.PackageProvenancePriority(mirror),
            "source-owner feed is preferred before a generic community mirror");

        var details = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Details.cs"));
        var migrationRank = details.IndexOf("OrderBy(x => MigrationCandidatePriority(x.Candidate))", StringComparison.Ordinal);
        var chronologyRank = details.IndexOf("ThenByDescending(x => PluginUpdateRules.NormalizeUnix(x.Candidate.LastUpdate))", StringComparison.Ordinal);
        True(migrationRank >= 0 && chronologyRank > migrationRank, "cross-repository updates rank provenance before chronology/version");
        Contains(details, "return divergent ? 1000 + provenance : provenance", "known divergent migration sources are final-fallback candidates");
        var installRank = details.IndexOf("ThenBy(v => RepositoryProviderRules.PackageProvenancePriority(v))", StringComparison.Ordinal);
        var installVersion = installRank < 0
            ? -1
            : details.IndexOf("ThenByDescending(v => v.AssemblyVersion)", installRank, StringComparison.Ordinal);
        True(installRank >= 0 && installVersion > installRank, "normal repository choice ranks provenance before version within the divergence tier");
    }

    private static PluginInstallPlan ResolvePlan(
        MarketplacePlugin root,
        IReadOnlyList<MarketplacePlugin> variants,
        IReadOnlyDictionary<long, IReadOnlyList<PluginDependencyEdge>> edges,
        IReadOnlyDictionary<string, PluginInstalledState>? installed = null,
        IReadOnlySet<string>? explicitDependencies = null,
        bool preferTesting = false)
    {
        var byName = variants.GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => (IReadOnlyList<MarketplacePlugin>)x.ToArray(), StringComparer.OrdinalIgnoreCase);
        var byPlugin = edges.Values.SelectMany(x => x)
            .GroupBy(x => x.ConsumerPluginId)
            .ToDictionary(x => x.Key, x => (IReadOnlyList<PluginDependencyEdge>)x.ToArray());
        return new PluginDependencyResolver().Resolve(new PluginDependencyResolutionContext
        {
            RootVariant = root,
            RootCatalogPluginId = root.CatalogPluginId,
            RootCatalogVariantId = root.CatalogVariantId,
            CurrentApiLevel = 15,
            CurrentDalamudVersion = new Version(13, 0),
            PreferTestingBuilds = preferTesting,
            CatalogRevision = "catalog-test",
            DependencyGraphRevision = "plugin-deps-v1-test",
            InstalledPlugins = installed ?? new Dictionary<string, PluginInstalledState>(StringComparer.OrdinalIgnoreCase),
            ExplicitDependencyInternalNames = explicitDependencies ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            GetVariants = name => byName.TryGetValue(name, out var found) ? found : [],
            GetDependenciesForVariant = variantId => edges.TryGetValue(variantId, out var found) ? found : [],
            GetDependenciesForPlugin = pluginId => byPlugin.TryGetValue(pluginId, out var found) ? found : [],
        });
    }

    private static MarketplacePlugin PlanPlugin(
        long pluginId,
        long variantId,
        string internalName,
        string version,
        int api,
        string source,
        bool official = false,
        string? minimumDalamud = null)
        => new()
        {
            CatalogPluginId = pluginId,
            CatalogVariantId = variantId,
            Name = internalName,
            InternalName = internalName,
            AssemblyVersionText = version,
            DalamudApiLevel = api,
            DownloadLinkInstall = $"https://example.invalid/{internalName}-{version}.zip",
            SourceName = source,
            SourceUrl = official ? string.Empty : $"https://example.invalid/{source}.json",
            SourceIsOfficial = official,
            MinimumDalamudVersionText = minimumDalamud,
        };

    private static PluginDependencyEdge Edge(
        long consumerVariantId,
        long consumerPluginId,
        string consumerInternalName,
        long providerPluginId,
        string providerInternalName,
        string constraint,
        PluginDependencyRelationship relationship = PluginDependencyRelationship.Required,
        bool installEligible = true,
        string sourceKind = "external-plugin")
        => new(
            consumerVariantId,
            consumerPluginId,
            consumerInternalName,
            string.Empty,
            providerPluginId,
            providerInternalName,
            relationship,
            constraint,
            string.Empty,
            "resolved",
            "compatible",
            "high",
            sourceKind,
            [],
            installEligible);
}

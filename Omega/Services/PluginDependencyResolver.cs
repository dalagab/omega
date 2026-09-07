using System.Security.Cryptography;
using System.Text;

namespace Dalagab.Omega;

/// <summary>
/// Pure dependency/package resolver. It builds a frozen plan and never calls Dalamud or mutates
/// repositories/plugins. Only normalized required + install-eligible catalog edges enter the
/// automatic closure; recommended/optional edges require explicit user selection and IPC never
/// participates in package authority.
/// </summary>
internal sealed class PluginDependencyResolver
{
    private sealed record RequirementContribution(
        string ConsumerKey,
        string ConsumerInternalName,
        PluginDependencyRelationship Relationship,
        string VersionConstraint);

    private sealed class Node
    {
        public required string Key { get; init; }
        public required long PluginId { get; set; }
        public required string InternalName { get; init; }
        public bool IsRoot { get; init; }
        public Dictionary<string, IReadOnlyList<RequirementContribution>> Incoming { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<(string TargetKey, PluginDependencyRelationship Relationship)> Outgoing { get; } = [];
        public MarketplacePlugin? SelectedVariant { get; set; }
        public PluginInstalledState? Installed { get; set; }
        public Version? TargetVersion { get; set; }
        public PluginInstallAction Action { get; set; }
        public string EffectiveConstraint { get; set; } = "any";
        public PluginVersionConstraint ParsedConstraint { get; set; } = PluginVersionConstraint.Any;
        public string SelectionFingerprint { get; set; } = string.Empty;
        public bool Removed { get; set; }
    }

    public PluginInstallPlan Resolve(PluginDependencyResolutionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.RootVariant);

        var nodes = new Dictionary<string, Node>(StringComparer.OrdinalIgnoreCase);
        var conflicts = new Dictionary<string, PluginInstallConflict>(StringComparer.OrdinalIgnoreCase);
        var warnings = new Dictionary<string, PluginInstallWarning>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<string>();
        var queued = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var root = context.RootVariant;
        var rootPluginId = context.RootCatalogPluginId > 0 ? context.RootCatalogPluginId : root.CatalogPluginId;
        var rootVariantId = context.RootCatalogVariantId > 0 ? context.RootCatalogVariantId : root.CatalogVariantId;
        var rootKey = IdentityKey(rootPluginId, root.InternalName);
        var rootNode = new Node
        {
            Key = rootKey,
            PluginId = rootPluginId,
            InternalName = root.InternalName,
            IsRoot = true,
            SelectedVariant = root,
        };
        nodes[rootKey] = rootNode;
        Enqueue(rootKey);

        var guard = 0;
        while (queue.Count > 0 && guard++ < 10000)
        {
            var key = queue.Dequeue();
            queued.Remove(key);
            if (!nodes.TryGetValue(key, out var node) || node.Removed)
                continue;

            if (!node.IsRoot && node.Incoming.Count == 0)
            {
                RemoveOutgoing(node);
                node.Removed = true;
                nodes.Remove(node.Key);
                conflicts.Remove(node.Key);
                continue;
            }

            ResolveNodeSelection(node);
            if (conflicts.ContainsKey(node.Key))
            {
                RemoveOutgoing(node);
                continue;
            }

            var nextFingerprint = SelectionFingerprint(node);
            if (nextFingerprint.Equals(node.SelectionFingerprint, StringComparison.Ordinal))
                continue;
            node.SelectionFingerprint = nextFingerprint;
            RemoveOutgoing(node);
            AddOutgoing(node);
        }

        if (guard >= 10000)
        {
            conflicts["resolver-guard"] = new PluginInstallConflict(
                PluginInstallConflictKind.RequiredDependencyCycle,
                rootPluginId,
                root.InternalName,
                "Dependency resolution did not converge. Omega will not guess at a cyclic or unstable package graph.",
                [root.InternalName],
                []);
        }

        var activeNodes = nodes.Values.Where(x => !x.Removed && x.SelectedVariant is not null).ToDictionary(x => x.Key, StringComparer.OrdinalIgnoreCase);
        DetectInstallCycles(activeNodes, conflicts);

        var suggestions = BuildSuggestions(activeNodes);
        var orderedNodes = TopologicalOrder(activeNodes, rootKey);
        var operations = BuildOperations(orderedNodes, rootKey, rootVariantId);
        var rootRequests = new[]
        {
            new PluginInstallRequest(rootPluginId, rootVariantId, root.InternalName, root, PluginInstallReason.Requested),
        };
        var conflictList = conflicts.Values
            .OrderBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Kind)
            .ToArray();
        var warningList = warnings.Values
            .OrderBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Kind)
            .ToArray();
        var planId = BuildPlanId(context, operations, conflictList, suggestions);
        return new PluginInstallPlan(
            planId,
            context.CatalogRevision ?? string.Empty,
            context.DependencyGraphRevision ?? string.Empty,
            rootRequests,
            operations,
            conflictList,
            warningList,
            suggestions,
            conflictList.Length == 0,
            false);

        void Enqueue(string key)
        {
            if (queued.Add(key))
                queue.Enqueue(key);
        }

        void ResolveNodeSelection(Node node)
        {
            conflicts.Remove(node.Key);
            var contributions = node.Incoming.Values.SelectMany(x => x).ToArray();
            var constraintTexts = contributions.Select(x => x.VersionConstraint).ToArray();
            if (!PluginVersionConstraint.TryIntersect(constraintTexts, out var parsed, out var effective, out var constraintError))
            {
                node.SelectedVariant = null;
                node.TargetVersion = null;
                node.EffectiveConstraint = effective;
                var conflictKind = constraintError.Contains("cannot be satisfied together", StringComparison.OrdinalIgnoreCase)
                    ? PluginInstallConflictKind.UnsatisfiableVersionConstraint
                    : PluginInstallConflictKind.InvalidVersionConstraint;
                conflicts[node.Key] = new PluginInstallConflict(
                    conflictKind,
                    node.PluginId,
                    node.InternalName,
                    constraintError,
                    ConsumerNames(contributions),
                    ConstraintNames(contributions));
                return;
            }
            node.ParsedConstraint = parsed;
            node.EffectiveConstraint = effective;
            context.InstalledPlugins.TryGetValue(node.InternalName, out var installed);
            node.Installed = installed;

            if (node.IsRoot)
            {
                var selected = context.RootVariant;
                if (!TryEffectiveVersion(selected, context.CurrentApiLevel, context.PreferTestingBuilds, out var rootVersion) ||
                    selected.MinimumDalamudVersion is not null && selected.MinimumDalamudVersion > context.CurrentDalamudVersion)
                {
                    node.SelectedVariant = null;
                    node.TargetVersion = null;
                    conflicts[node.Key] = new PluginInstallConflict(
                        PluginInstallConflictKind.RootUnavailable,
                        node.PluginId,
                        selected.InternalName,
                        $"{selected.Name} is no longer compatible with the current Dalamud/API selection.",
                        [selected.InternalName],
                        []);
                    return;
                }
                if (!parsed.Allows(rootVersion))
                {
                    node.SelectedVariant = null;
                    node.TargetVersion = null;
                    conflicts[node.Key] = new PluginInstallConflict(
                        PluginInstallConflictKind.UnsatisfiableVersionConstraint,
                        node.PluginId,
                        selected.InternalName,
                        $"The selected {selected.Name} v{rootVersion} does not satisfy {effective}.",
                        ConsumerNames(contributions),
                        ConstraintNames(contributions));
                    return;
                }
                node.SelectedVariant = selected;
                node.TargetVersion = rootVersion;
                node.Action = DetermineAction(selected, rootVersion, installed, isRoot: true);
                return;
            }

            if (installed is not null && parsed.Allows(installed.Version))
            {
                node.SelectedVariant = SelectMetadataVariantForInstalled(node, installed) ?? SelectBestCandidate(node, allowInstalledVersionFloor: false);
                node.TargetVersion = installed.Version;
                node.Action = PluginInstallAction.Keep;
                if (node.SelectedVariant is null)
                {
                    conflicts[node.Key] = new PluginInstallConflict(
                        PluginInstallConflictKind.MissingProvider,
                        node.PluginId,
                        node.InternalName,
                        $"{node.InternalName} is installed and satisfies {effective}, but Omega no longer has a catalog identity for that provider.",
                        ConsumerNames(contributions),
                        ConstraintNames(contributions));
                }
                return;
            }

            if (installed?.IsDev == true)
            {
                node.SelectedVariant = null;
                node.TargetVersion = null;
                conflicts[node.Key] = new PluginInstallConflict(
                    PluginInstallConflictKind.DeveloperPluginBlocked,
                    node.PluginId,
                    node.InternalName,
                    $"Installed developer plugin {node.InternalName} does not satisfy {effective} and Omega will not replace a dev plugin.",
                    ConsumerNames(contributions),
                    ConstraintNames(contributions));
                return;
            }

            var candidate = SelectBestCandidate(node, allowInstalledVersionFloor: true);
            if (candidate is null)
            {
                var allCandidates = context.GetVariants(node.InternalName) ?? [];
                var effectiveCandidates = EffectiveCandidates(node.InternalName);
                var anyConstraintCandidate = effectiveCandidates.Any(x => parsed.Allows(x.Version));
                var downgradeOnly = installed is not null && anyConstraintCandidate && effectiveCandidates.Any(x =>
                    parsed.Allows(x.Version) && x.Version.CompareTo(installed.Version) < 0);
                var kind = downgradeOnly
                    ? PluginInstallConflictKind.DowngradeRequired
                    : allCandidates.Count == 0
                        ? PluginInstallConflictKind.MissingProvider
                        : PluginInstallConflictKind.UnsatisfiableVersionConstraint;
                var message = downgradeOnly
                    ? $"{node.InternalName} would need to be downgraded from v{installed!.Version} to satisfy {effective}; the current Dalamud update bridge does not perform dependency downgrades."
                    : allCandidates.Count == 0
                        ? $"No Omega package provider is available for required plugin {node.InternalName}."
                        : $"No compatible {node.InternalName} package satisfies {effective} for API {context.CurrentApiLevel}.";
                node.SelectedVariant = null;
                node.TargetVersion = null;
                conflicts[node.Key] = new PluginInstallConflict(
                    kind,
                    node.PluginId,
                    node.InternalName,
                    message,
                    ConsumerNames(contributions),
                    ConstraintNames(contributions));
                return;
            }

            node.SelectedVariant = candidate;
            TryEffectiveVersion(candidate, context.CurrentApiLevel, context.PreferTestingBuilds, out var targetVersion);
            node.TargetVersion = targetVersion;
            node.Action = installed is null ? PluginInstallAction.Install : PluginInstallAction.Update;
        }

        MarketplacePlugin? SelectMetadataVariantForInstalled(Node node, PluginInstalledState installed)
        {
            return (context.GetVariants(node.InternalName) ?? [])
                .Where(IsCandidateCompatible)
                .Where(x => TryEffectiveVersion(x, context.CurrentApiLevel, context.PreferTestingBuilds, out var version) && version.CompareTo(installed.Version) == 0)
                .OrderBy(x => PluginUpdateRules.IsSamePublishingSource(installed.SourceUrl, x.SourceUrl, x.SourceIsOfficial) ? 0 : 1)
                .ThenBy(x => CandidateSourcePriority(x, node.InternalName, installed))
                .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
        }

        MarketplacePlugin? SelectBestCandidate(Node node, bool allowInstalledVersionFloor)
        {
            var installed = node.Installed;
            return EffectiveCandidates(node.InternalName)
                .Where(x => node.ParsedConstraint.Allows(x.Version))
                .Where(x => !allowInstalledVersionFloor || installed is null || x.Version.CompareTo(installed.Version) >= 0)
                .OrderBy(x => CandidateSourcePriority(x.Plugin, node.InternalName, installed))
                .ThenByDescending(x => x.Version)
                .ThenBy(x => x.Plugin.SourceName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => NormalizeUrl(x.Plugin.SourceUrl), StringComparer.OrdinalIgnoreCase)
                .Select(x => x.Plugin)
                .FirstOrDefault();
        }

        IReadOnlyList<(MarketplacePlugin Plugin, Version Version)> EffectiveCandidates(string internalName)
        {
            var result = new List<(MarketplacePlugin Plugin, Version Version)>();
            foreach (var candidate in context.GetVariants(internalName) ?? [])
            {
                if (!IsCandidateCompatible(candidate))
                    continue;
                if (TryEffectiveVersion(candidate, context.CurrentApiLevel, context.PreferTestingBuilds, out var version))
                    result.Add((candidate, version));
            }
            return result;
        }

        bool IsCandidateCompatible(MarketplacePlugin candidate)
        {
            if (candidate.IsHide)
                return false;
            if (candidate.MinimumDalamudVersion is not null && candidate.MinimumDalamudVersion > context.CurrentDalamudVersion)
                return false;
            if (!candidate.SourceIsOfficial && (!Uri.TryCreate(candidate.SourceUrl, UriKind.Absolute, out var sourceUri) || sourceUri.Scheme != Uri.UriSchemeHttps))
                return false;
            return candidate.HasCurrentApiBuild(context.CurrentApiLevel, context.PreferTestingBuilds, out _);
        }

        int CandidateSourcePriority(MarketplacePlugin candidate, string internalName, PluginInstalledState? installed)
        {
            if (installed is not null && PluginUpdateRules.IsSamePublishingSource(installed.SourceUrl, candidate.SourceUrl, candidate.SourceIsOfficial))
                return 0;
            if (context.PreferredSourceUrls.TryGetValue(internalName, out var preferred) &&
                NormalizeUrl(preferred).Equals(NormalizeUrl(candidate.SourceUrl), StringComparison.OrdinalIgnoreCase))
                return 1;
            // After current/preferred source, prefer known-good provider identities, then the
            // repository published by the source-project owner, then generic community mirrors.
            // Security/divergence remains orthogonal and is reviewed in the transaction UI.
            return 2 + RepositoryProviderRules.PackageProvenancePriority(candidate);
        }

        void RemoveOutgoing(Node node)
        {
            foreach (var targetKey in node.Outgoing.Select(x => x.TargetKey).Distinct(StringComparer.OrdinalIgnoreCase).ToArray())
            {
                if (!nodes.TryGetValue(targetKey, out var target))
                    continue;
                if (target.Incoming.Remove(node.Key))
                    Enqueue(target.Key);
            }
            node.Outgoing.Clear();
        }

        void AddOutgoing(Node node)
        {
            if (node.SelectedVariant is null || node.TargetVersion is null)
                return;
            var edges = ReadEdgesForSelectedNode(node);
            foreach (var providerGroup in edges
                         .Where(IsPackageAuthorityEdge)
                         .GroupBy(x => IdentityKey(x.ProviderPluginId, x.ProviderInternalName), StringComparer.OrdinalIgnoreCase))
            {
                var group = providerGroup.ToArray();
                var first = group[0];
                var include = group.Any(edge => edge.Relationship == PluginDependencyRelationship.Required && edge.InstallEligible) ||
                              group.Any(edge => edge.InstallEligible &&
                                  (edge.Relationship is PluginDependencyRelationship.Recommended or PluginDependencyRelationship.Optional) &&
                                  context.ExplicitDependencyInternalNames.Contains(edge.ProviderInternalName));
                if (!include)
                {
                    foreach (var edge in group.Where(x => x.Relationship == PluginDependencyRelationship.Required && !x.InstallEligible))
                    {
                        warnings[$"noninstallable:{node.Key}:{providerGroup.Key}"] = new PluginInstallWarning(
                            PluginInstallWarningKind.NonInstallableRelationship,
                            $"{node.InternalName} has a normalized required relationship to {edge.ProviderInternalName}, but the catalog did not mark it install-eligible; Omega will not guess.",
                            edge.ProviderInternalName);
                    }
                    continue;
                }

                var includedEdges = group.Where(edge =>
                        edge.Relationship == PluginDependencyRelationship.Required && edge.InstallEligible ||
                        edge.InstallEligible &&
                        (edge.Relationship is PluginDependencyRelationship.Recommended or PluginDependencyRelationship.Optional) &&
                        context.ExplicitDependencyInternalNames.Contains(edge.ProviderInternalName))
                    .ToArray();
                if (includedEdges.Length == 0)
                    continue;

                var targetKey = providerGroup.Key;
                if (!nodes.TryGetValue(targetKey, out var target))
                {
                    target = new Node
                    {
                        Key = targetKey,
                        PluginId = first.ProviderPluginId,
                        InternalName = first.ProviderInternalName,
                    };
                    nodes[targetKey] = target;
                }
                else if (target.PluginId <= 0 && first.ProviderPluginId > 0)
                {
                    target.PluginId = first.ProviderPluginId;
                }
                target.Removed = false;
                target.Incoming[node.Key] = includedEdges.Select(edge => new RequirementContribution(
                    node.Key,
                    node.InternalName,
                    edge.Relationship,
                    edge.VersionConstraint)).ToArray();
                foreach (var relation in includedEdges.Select(x => x.Relationship).Distinct())
                    node.Outgoing.Add((targetKey, relation));
                Enqueue(targetKey);
            }
        }

        IReadOnlyList<PluginDependencyEdge> ReadEdgesForSelectedNode(Node node)
        {
            if (node.SelectedVariant is null)
                return [];
            if (node.Action == PluginInstallAction.Keep && node.Installed is not null &&
                (!TryEffectiveVersion(node.SelectedVariant, context.CurrentApiLevel, context.PreferTestingBuilds, out var selectedVersion) || selectedVersion.CompareTo(node.Installed.Version) != 0))
            {
                return (context.GetDependenciesForPlugin(node.PluginId) ?? [])
                    .Where(x => VersionsEqual(x.ConsumerVersion, node.Installed.Version))
                    .ToArray();
            }
            var selectedVariantId = node.IsRoot && rootVariantId > 0
                ? rootVariantId
                : node.SelectedVariant.CatalogVariantId;
            if (selectedVariantId > 0)
                return context.GetDependenciesForVariant(selectedVariantId) ?? [];
            return (context.GetDependenciesForPlugin(node.PluginId) ?? [])
                .Where(x => string.IsNullOrWhiteSpace(x.ConsumerVersion) || VersionsEqual(x.ConsumerVersion, node.TargetVersion!))
                .ToArray();
        }

        IReadOnlyList<PluginInstallSuggestion> BuildSuggestions(IReadOnlyDictionary<string, Node> resolved)
        {
            var suggestionMap = new Dictionary<string, (PluginDependencyEdge Edge, HashSet<string> By)>(StringComparer.OrdinalIgnoreCase);
            foreach (var node in resolved.Values)
            {
                foreach (var edge in ReadEdgesForSelectedNode(node).Where(IsPackageAuthorityEdge))
                {
                    if (edge.Relationship is not (PluginDependencyRelationship.Recommended or PluginDependencyRelationship.Optional or PluginDependencyRelationship.Observed))
                        continue;
                    var suggestionKey = $"{IdentityKey(edge.ProviderPluginId, edge.ProviderInternalName)}:{edge.Relationship}:{edge.VersionConstraint}";
                    if (!suggestionMap.TryGetValue(suggestionKey, out var entry))
                        entry = (edge, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                    entry.By.Add(node.InternalName);
                    suggestionMap[suggestionKey] = entry;
                }
            }
            return suggestionMap.Values
                .Select(entry => new PluginInstallSuggestion(
                    entry.Edge.ProviderPluginId,
                    entry.Edge.ProviderInternalName,
                    entry.Edge.Relationship,
                    entry.Edge.VersionConstraint,
                    entry.By.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
                    entry.Edge.InstallEligible,
                    context.ExplicitDependencyInternalNames.Contains(entry.Edge.ProviderInternalName)))
                .OrderBy(x => x.Relationship)
                .ThenBy(x => x.ProviderInternalName, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
    }

    private static bool IsPackageAuthorityEdge(PluginDependencyEdge edge)
        => !string.IsNullOrWhiteSpace(edge.ProviderInternalName) &&
           !edge.SourceKind.Equals("ipc", StringComparison.OrdinalIgnoreCase);

    private static bool TryEffectiveVersion(MarketplacePlugin plugin, int currentApi, bool preferTesting, out Version version)
    {
        if (!plugin.HasCurrentApiBuild(currentApi, preferTesting, out var testing))
        {
            version = new Version(0, 0);
            return false;
        }
        version = testing ? plugin.TestingAssemblyVersion ?? plugin.AssemblyVersion : plugin.AssemblyVersion;
        return true;
    }

    private static PluginInstallAction DetermineAction(
        MarketplacePlugin selected,
        Version targetVersion,
        PluginInstalledState? installed,
        bool isRoot)
    {
        if (installed is null)
            return PluginInstallAction.Install;
        if (installed.Version.CompareTo(targetVersion) < 0)
            return PluginInstallAction.Update;
        if (installed.Version.CompareTo(targetVersion) == 0 && isRoot &&
            !PluginUpdateRules.IsSamePublishingSource(installed.SourceUrl, selected.SourceUrl, selected.SourceIsOfficial))
            return PluginInstallAction.MigrateSource;
        return PluginInstallAction.Keep;
    }

    private static IReadOnlyList<string> ConsumerNames(IEnumerable<RequirementContribution> values)
        => values.Select(x => x.ConsumerInternalName)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static IReadOnlyList<string> ConstraintNames(IEnumerable<RequirementContribution> values)
        => values.Select(x => (x.VersionConstraint ?? string.Empty).Trim())
            .Where(x => x.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string SelectionFingerprint(Node node)
        => string.Join("\u001f", new[]
        {
            node.SelectedVariant?.CatalogVariantId.ToString() ?? "0",
            node.SelectedVariant?.SourceUrl ?? string.Empty,
            node.TargetVersion?.ToString() ?? string.Empty,
            node.Action.ToString(),
            node.EffectiveConstraint,
        });

    private static string IdentityKey(long pluginId, string internalName)
        => pluginId > 0 ? $"id:{pluginId}" : $"name:{(internalName ?? string.Empty).Trim().ToLowerInvariant()}";

    private static bool VersionsEqual(string text, Version version)
        => Version.TryParse(NormalizeVersionText(text), out var parsed) && parsed.CompareTo(version) == 0;

    private static string NormalizeVersionText(string text)
    {
        var value = (text ?? string.Empty).Trim().TrimStart('v', 'V');
        return value.Count(x => x == '.') == 0 && value.Length > 0 ? value + ".0" : value;
    }

    private static string NormalizeUrl(string? value)
        => (value ?? string.Empty).Trim().TrimEnd('/');

    private static void DetectInstallCycles(
        IReadOnlyDictionary<string, Node> nodes,
        IDictionary<string, PluginInstallConflict> conflicts)
    {
        var state = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var stack = new List<string>();
        foreach (var key in nodes.Keys.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            Visit(key);

        void Visit(string key)
        {
            if (!nodes.TryGetValue(key, out var node))
                return;
            if (state.TryGetValue(key, out var existing))
            {
                if (existing != 1)
                    return;
                var start = stack.FindIndex(x => x.Equals(key, StringComparison.OrdinalIgnoreCase));
                var cycleKeys = start >= 0 ? stack.Skip(start).Append(key).ToArray() : [key, key];
                var names = cycleKeys
                    .Select(x => nodes.TryGetValue(x, out var cycleNode) ? cycleNode.InternalName : x)
                    .ToArray();
                var message = $"Dependency installation cycle: {string.Join(" → ", names)}";
                conflicts[$"cycle:{string.Join("|", cycleKeys)}"] = new PluginInstallConflict(
                    PluginInstallConflictKind.RequiredDependencyCycle,
                    node.PluginId,
                    node.InternalName,
                    message,
                    names,
                    []);
                return;
            }
            state[key] = 1;
            stack.Add(key);
            foreach (var target in node.Outgoing
                         .Select(x => x.TargetKey)
                         .Distinct(StringComparer.OrdinalIgnoreCase)
                         .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                Visit(target);
            stack.RemoveAt(stack.Count - 1);
            state[key] = 2;
        }
    }

    private static IReadOnlyList<Node> TopologicalOrder(IReadOnlyDictionary<string, Node> nodes, string rootKey)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ordered = new List<Node>();
        void Visit(string key)
        {
            if (!visited.Add(key) || !nodes.TryGetValue(key, out var node))
                return;
            foreach (var target in node.Outgoing.Select(x => x.TargetKey)
                         .Distinct(StringComparer.OrdinalIgnoreCase)
                         .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                Visit(target);
            ordered.Add(node);
        }
        Visit(rootKey);
        foreach (var key in nodes.Keys.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            Visit(key);
        return ordered;
    }

    private static IReadOnlyList<PluginInstallOperation> BuildOperations(
        IReadOnlyList<Node> nodes,
        string rootKey,
        long rootVariantId)
    {
        var result = new List<PluginInstallOperation>(nodes.Count);
        for (var index = 0; index < nodes.Count; index++)
        {
            var node = nodes[index];
            if (node.SelectedVariant is null || node.TargetVersion is null)
                continue;
            var contributions = node.Incoming.Values.SelectMany(x => x).ToArray();
            var requiredBy = contributions
                .Where(x => x.Relationship == PluginDependencyRelationship.Required)
                .Select(x => x.ConsumerInternalName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var explicitRecommended = contributions.Any(x => x.Relationship == PluginDependencyRelationship.Recommended);
            var explicitOptional = contributions.Any(x => x.Relationship == PluginDependencyRelationship.Optional);
            var reason = node.IsRoot
                ? PluginInstallReason.Requested
                : node.Action == PluginInstallAction.Update && node.Installed is not null
                    ? PluginInstallReason.DependencyVersionConstraint
                    : requiredBy.Length > 0
                        ? PluginInstallReason.RequiredDependency
                        : explicitRecommended
                            ? PluginInstallReason.ExplicitRecommendedDependency
                            : explicitOptional
                                ? PluginInstallReason.ExplicitOptionalDependency
                                : PluginInstallReason.RequiredDependency;
            var selectedVariantId = node.Key.Equals(rootKey, StringComparison.OrdinalIgnoreCase) && rootVariantId > 0
                ? rootVariantId
                : node.SelectedVariant.CatalogVariantId;
            result.Add(new PluginInstallOperation(
                node.PluginId,
                node.InternalName,
                node.SelectedVariant,
                selectedVariantId,
                node.Action,
                reason,
                requiredBy,
                node.EffectiveConstraint,
                node.Installed?.Version,
                node.TargetVersion,
                index));
        }
        return result;
    }

    private static string BuildPlanId(
        PluginDependencyResolutionContext context,
        IReadOnlyList<PluginInstallOperation> operations,
        IReadOnlyList<PluginInstallConflict> conflicts,
        IReadOnlyList<PluginInstallSuggestion> suggestions)
    {
        var canonical = new StringBuilder()
            .Append(context.CatalogRevision).Append('\n')
            .Append(context.DependencyGraphRevision).Append('\n')
            .Append(context.CurrentApiLevel).Append('\n')
            .Append(context.CurrentDalamudVersion).Append('\n')
            .Append(context.PreferTestingBuilds).Append('\n');
        foreach (var operation in operations)
        {
            canonical.Append(operation.PluginId).Append('|')
                .Append(operation.InternalName).Append('|')
                .Append(operation.SelectedVariantId).Append('|')
                .Append(NormalizeUrl(operation.SelectedVariant.SourceUrl)).Append('|')
                .Append(operation.TargetVersion).Append('|')
                .Append(operation.Action).Append('|')
                .Append(operation.EffectiveVersionConstraint).Append('\n');
        }
        foreach (var conflict in conflicts)
            canonical.Append("conflict|").Append(conflict.Kind).Append('|').Append(conflict.InternalName).Append('|').Append(conflict.Message).Append('\n');
        foreach (var suggestion in suggestions.Where(x => x.Selected))
            canonical.Append("optional|").Append(suggestion.ProviderPluginId).Append('|').Append(suggestion.ProviderInternalName).Append('|').Append(suggestion.Relationship).Append('\n');
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString()));
        return $"omega-plan-v1-{Convert.ToHexString(digest).ToLowerInvariant()[..20]}";
    }
}

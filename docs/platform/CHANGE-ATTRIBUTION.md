# Why did a security result change?

DeltaScope's Compare view separates a changed plugin from a changed security system. A finding can change even when the plugin artifact did not.

## Attribution boundaries

DeltaScope compares retained provenance for the two snapshots:

- artifact SHA-256 and plugin version;
- artifact-analysis revision;
- source-analysis revision;
- scanner/worker revision where retained;
- Definitions revision;
- Stigma-1 rule-set revision;
- advisory revision;
- frozen endpoint-reputation revision.

It then classifies the changed inputs and shows **What has to run?** so the operator can distinguish artifact re-analysis, source follow-up, and retained-evidence reprojection.

Narrow revisions take precedence over umbrella revisions. For example, a new daily reputation snapshot also changes the overall Definitions revision; DeltaScope reports that as **Endpoint threat intelligence changed** rather than incorrectly presenting reputation and Definitions as two unrelated causes. Likewise, a frozen worker SHA may change without changing the narrow artifact/source analysis revisions, so a worker transport change is not automatically described as new scanner semantics.

### Plugin / artifact changed

The installable artifact SHA changed. New or removed findings may therefore be caused by new plugin bytes. If Definitions/scanner inputs changed at the same time, DeltaScope reports a **mixed** cause rather than pretending the plugin alone explains the result.

### SigmaScope observation semantics changed

The artifact can remain byte-for-byte identical while an artifact/source analysis revision advances. That means Omega learned to observe or normalize something differently. A targeted re-analysis may be responsible for new retained observations.

### Definitions / Stigma-1 interpretation changed

The artifact and observation semantics may remain the same while a Definitions or rule-set revision changes. The same retained observations can then produce a different fact/correlation/finding through rule-only reprojection. DeltaScope marks this as **same bytes** when the artifact SHA is identical and explicitly says that artifact re-analysis is not required.

### Advisory intelligence changed

The frozen OSV advisory universe changed. Dependency-advisory relationships can therefore change without a plugin binary rescan; retained dependency evidence can be reprojected against the new advisory snapshot.

### Endpoint threat intelligence changed

The frozen `reputationRevision` changed. The same retained endpoint can resolve/match differently against the new daily threat-intelligence snapshot; SRL can reproject from retained `networkEndpoints` without reopening the plugin artifact.

## Mixed changes

When more than one input boundary changed, DeltaScope says so. It does not claim a single cause unless the retained provenance supports that conclusion.

The **Why did this change?** box in Compare lists the changed inputs and exact revision values. It also reports whether artifact analysis, source follow-up, or retained-evidence reprojection is required. Raw diffs remain available underneath.

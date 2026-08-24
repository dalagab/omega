# Detection coverage and blind spots

DeltaScope can review the health of Omega's detection system itself, not only the plugins that the system has scanned. **Security Researcher → Detection Coverage** projects the current plugin corpus against the observation contracts and narrow analysis revisions published by SigmaScope.

The matrix is read-only. It cannot queue a scan, change a Definition, enable a detector, alter a finding, or publish evidence.

## What “coverage” means

A detection rule can only be as reliable as the observations available to it. DeltaScope therefore treats the retained observation families as first-class security-system dependencies.

For an artifact-backed observation such as `staticPatternMatches` or `managedCallSites`, a current plugin version is covered when:

1. the plugin has a complete current analysis; and
2. that analysis was produced with the current `artifactAnalysisRevision`.

For a source-only observation such as `sourceFiles` or `sourceAttribution`, the denominator is the set of current variants for which attributable source is available. A variant with no attributable source is shown as **outside scope**, not as a failed source scan.

This distinction matters. A collection with zero matching rows can still be complete. For example, a plugin may have a complete `staticPatternMatches` collection with no `Process.Start` row. That is valid negative evidence. DeltaScope never equates “zero positive rows” with “scanner blind spot.”

## Coverage states

**Healthy** means every current variant in the collection's expected scope has a complete analysis at the current narrow producer revision.

**Needs attention** means a small part of the expected scope is stale, incomplete, or lacks the narrow revision identity required to prove current producer coverage.

**Degraded** means the gap is large enough that conclusions depending on this collection should be treated as materially coverage-limited.

**Blind spot** means none of the expected current scope can be shown to have current producer coverage.

The state is about observation availability, not plugin safety.

## Current versions only

The matrix always uses the current active plugin version surface. Historical versions remain valuable archive evidence, but they do not contribute to current coverage totals.

This mirrors the security finding model:

- current version findings contribute to current HIGH/CRITICAL totals;
- archive version findings remain queryable for investigation and comparison;
- archive scans do not make a currently clean version appear risky;
- archive scans do not make a current detection family look better-covered than it is.

## Narrow analysis revisions

Omega deliberately separates the frozen worker identity from narrow analysis semantics.

`artifactAnalysisRevision` changes when artifact observation semantics change in a way that can invalidate previously retained artifact observations. Queue scheduling, UI changes, logging, and other unrelated worker changes do not automatically make every artifact stale.

`sourceAnalysisRevision` provides the equivalent boundary for source-derived observations.

The Detection Coverage matrix uses these narrow revisions so that “needs re-analysis” means the underlying observation producer actually changed, rather than merely that a new worker bundle was frozen.

## Rule dependencies

Each observation row shows the active Stigma-1 rules that declare it in `requires`.

For example:

```yaml
requires: [staticPatternMatches]
```

means the rule cannot be evaluated exactly without that retained collection. When a collection has a coverage gap, DeltaScope can therefore show which deterministic rules are affected by the gap.

Click a rule from the coverage detail to open it in **Security Researcher → Rules**.

## Inspecting exact plugin data

The corpus matrix intentionally avoids downloading every immutable variant descriptor merely to paint a dashboard. Its primary coverage basis is:

- current variant index;
- current scan state;
- source availability;
- narrow artifact/source analysis revisions;
- published observation contract;
- published Definition/rule provenance.

This keeps the view bounded even for thousands of plugins.

When exact retained data matters, select a plugin and use **Inspect selected plugin data** for the observation family. DeltaScope then loads that plugin's immutable collection contract and retained rows lazily.

The per-plugin view can distinguish:

- retained complete observations;
- valid empty observations;
- bounded compatibility evidence;
- absent collections;
- exact typed fields and rows.

## When a rescan is required

Missing raw observation evidence cannot be repaired by changing presentation or rerunning Stigma-1 alone.

If a current variant is stale because its artifact analysis revision differs from the active artifact analysis revision, the normal repair is targeted artifact re-analysis.

If a source-only collection is stale, the normal repair is source follow-up or source re-analysis.

If the raw observation is already current and only a rule or projection changed, reprojection may be sufficient. The matrix therefore does not describe a missing raw observation as something that rule reprojection can fix.

## OSV coverage

The matrix also includes the frozen OSV/NuGet advisory query universe when that metadata is published. Its denominator is **package-version pairs**, not plugin variants.

That row answers a different question:

> Of the NuGet package/version pairs that the frozen advisory collector was expected to query, how many were actually queried?

A gap there normally requires refreshing/fixing advisory Definitions rather than rescanning plugin artifacts.

## Special collections

`developerProfile` is an optional developer-authored declaration. Its coverage row measures whether the source-analysis path that can carry the profile is current; the absence of a profile is not itself a scanner blind spot.

`secondarySecurity` represents bounded supplemental hygiene evidence such as YARA/ClamAV results. The compact current variant index cannot prove that every optional secondary engine was available on every scan, so engine-specific failures should also be reviewed through plugin evidence and Operations/Collectors.

## How to extend detection coverage

When adding a new primitive observation family:

1. add the logical collection to `tools/security/observation_projection.py`;
2. give it a stable schema, backing dataset, semantic class, SRL eligibility, and origin;
3. expose its typed rule fields through `tools/security/rule_author_reference.py` when Stigma-1 may consume it;
4. ensure the correct narrow analysis revision changes when its producer semantics change;
5. retain the collection contract in Security Evidence v2;
6. add regression coverage for complete, empty, stale and missing cases.

Once those contracts exist, DeltaScope can place the collection in the coverage matrix without treating positive detections as a proxy for scanner completeness.

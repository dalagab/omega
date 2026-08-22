# Omega Deep Scan workflow

## Purpose

The Deep Scan pipeline is a separate evidence-acquisition lane for work that should not lengthen the normal coverage-first SigmaScope worker. Stigma-1 can request this lane with a bounded `analysisRequest` outcome.

## Authority boundary

- Stigma-1 rules select only a named profile and provide a reason.
- Rules cannot define executable commands, timeouts, network policy, arbitrary filesystem paths, or runner configuration.
- Deep Scan may acquire evidence; it does not directly rewrite production findings or severity.
- Local DeltaScope rules only preview requests.
- The production queue is derived from exact frozen Definition rules.


## Adaptive scan depth

`analysisRequest` accepts one bounded semantic depth: `standard`, `extended`, or `exhaustive`. A rule does **not** set a raw timeout. The frozen profile contract maps depth to code-owned budgets and analysis families. For `artifact-differential-v1` the current workflow ceilings are 20, 40 and 65 minutes respectively, with smaller worker budgets inside those job ceilings.

If several matched rules request the same candidate/baseline/profile at different depths, SigmaScope creates **one** queue item and keeps the deepest request. All requesting rule IDs, revisions, requested depths and reasons remain attached as provenance. A completed standard result does not satisfy a later extended/exhaustive request because depth is part of the acquisition identity.

The workflow has a read-only selection job that resolves the next queue item and exports its approved timeout/depth. The execution job then runs with that dynamic timeout and passes the exact request ID to the frozen worker. Queue values are clamped to hard code-owned ceilings before they reach the workflow.

Extended/exhaustive artifact differential scans do more work rather than simply waiting longer: they add bounded static member-content/string/URL/entropy summaries on both candidate and baseline. No depth executes plugin code.

## Durable queue

Queue state is published atomically to the dedicated `deep-scan-state` branch. Request identity includes the exact candidate artifact, comparison baseline, deep-scan profile, bounded depth, and profile-set revision. Requesting rule IDs/revisions and reasons are retained as provenance but deliberately do **not** change the acquisition identity: if another rule later requests the same exact evidence, a completed result is reused instead of rerunning the package. Multiple rules requesting the same work coalesce into one scan.

Completed results are retained under `results/<request-id>.json` in that state snapshot.

## Current executable profile

### `artifact-differential-v1`

This profile never executes plugin code. It:

1. downloads candidate and stable-baseline artifacts over HTTPS;
2. verifies both expected SHA-256 identities;
3. inventories their package members;
4. runs the same bounded non-executing SigmaScope static artifact inspection on both sides;
5. emits package member and static-behavior differences.

The result identifies added/removed/changed files, added/removed static rule-hit families, network endpoint differences and dependency differences.

## Reserved sandbox profile

### `sandbox-differential-v1`

The profile contract exists so rules do not need a language redesign later, but it is `available=false`. Omega does not yet have an isolated environment that can safely execute arbitrary Dalamud plugins. The Actions worker fails closed and will not substitute ordinary runner execution.

When a real sandbox is added, both the known baseline and divergent candidate must be run with the exact same sandbox profile before their behavior is compared.

## Workflow lifecycle

1. The normal bounded SigmaScope run reprojects the exact frozen active SRL rules over compatible retained evidence.
2. Matched `analysisRequest` outcomes are materialized in `rule-projections/analysis-requests.json`.
3. SigmaScope projects those requests against the current Evidence-v2 artifact identities and stable-source baseline model into `deep-scan-state/index.json`.
4. A semantic queue change is published to the dedicated state branch. Queue publication is auxiliary and fail-soft with force-with-lease protection; it cannot corrupt or block Security Evidence-v2 publication during a concurrent worker update.
5. SigmaScope best-effort dispatches `.github/workflows/deep-scan.yml` when executable requests are pending.
6. The separate worker checks out the exact frozen Daily Definitions worker, verifies it, selects one pending request, acquires the evidence, writes a result, and atomically publishes the updated queue/results state.
7. The default-branch caller `docs/workflow-callers/deep-scan-main.yml` runs hourly as recovery if a dispatch was missed or unavailable.

The source workflow is rollout-compatible with an older frozen worker: it probes the frozen production pipeline's `--help` output before supplying the new queue arguments. Therefore the workflow source can land before the next Definitions freeze without breaking the existing SigmaScope worker. The feature becomes operational after the next normal Catalog Builder/Definitions freeze copies the deep-scan modules into the worker bundle.

## Stable baseline semantics

`stable-artifact-baseline` reuses Omega's existing stable-publisher classification (Dalamud, Puni.sh, NightmareXIV, Combat Reborn). It does not silently choose an arbitrary community mirror when no stable publisher is present. In that case the request stays `blocked` with an explicit reason. “Stable baseline” is package-provenance terminology, not a claim that the baseline is safe or malware-free.

## DeltaScope authoring

In **Rules → Visual**, select the Emit node to configure **Deep analysis outcome**. The profile list comes from the live Stigma-1 engine reference, so unavailable profiles are visibly marked. Applying the graph converts the outcome back to canonical SRL YAML and recompiles it through Stigma-1. Explain/Test shows the deep-scan request when the rule matches. A rule under My Rules never publishes or enqueues that request.

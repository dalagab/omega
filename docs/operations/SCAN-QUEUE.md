# SigmaScope scan queue causality

DeltaScope's **Operations → Scan Queue** page displays the complete already-published SigmaScope queue in deterministic order. Row **#1** is the next selected item when DeltaScope recognizes the published ordering policy. Selecting a row opens an inspector explaining its plugin/version, lane, priority, attempts, current scan and every published queue reason. It is an inspection surface only: it cannot enqueue work, change priority, run a scan, alter Evidence-v2, or authorize publication.

## Why scanning can appear to start at A again

SigmaScope currently uses the deterministic `coverage-first-v1` selection policy. Pending work is divided into three lanes:

1. **First coverage** — an active artifact variant has no published current scan and has not yet been attempted.
2. **First-coverage retry** — artifact work was attempted, but that active variant is still uncovered.
3. **Covered refresh / follow-up** — the variant already has current artifact coverage and needs re-analysis, source follow-up, advisory refresh, or another bounded revisit.

Lane 1 is exhausted before lane 2, and both are exhausted before lane 3. Reason priority orders work *within* a lane. When two items have the same lane and priority, the queue uses stable deterministic tie-breakers including the current scan timestamp and then plugin `InternalName`. A large new first-coverage wave can therefore visibly return to names beginning with **A** even though older Security Evidence still exists.

This is different from a baseline security rebuild.

## Baseline rebuild versus ordinary catalog rebuild

`baselineSecurityRebuild=true` means the **catalog identity epoch** changed. Variant identities from the previous Evidence-v2 snapshot can no longer be assumed to represent the current catalog identity model, so SigmaScope deliberately establishes a fresh baseline.

`baselineSecurityRebuild=false` means the published queue does **not** claim such an identity reset. An ordinary catalog rebuild may still add/re-identify active variants or expose variants that do not yet have a current Evidence-v2 scan. Those appear as `new_variant` first-coverage work without deleting existing evidence.

The DeltaScope page displays this flag and identity epoch explicitly so operators do not have to infer reset semantics from the alphabetical order of scan logs.

## Common queue reasons

- `new_variant` — no matching published current artifact scan exists for that active variant identity.
- `artifact_version_changed` / `artifact_url_changed` — the selected install target changed.
- `artifact_analysis_changed` — the artifact-analysis producer revision changed; covered variants need selective refresh.
- `source_followup` — artifact analysis completed and source attribution can continue.
- `source_*` — source candidates, observations, or the source-analysis producer changed, or attribution remains unresolved.
- `srl_observation_missing` — an active Stigma-1 rule needs an observation collection absent at the required producer revision.
- `advisory_changed` — the frozen advisory universe changed.
- `failed_retry` — prior work did not complete and is waiting for bounded retry/backoff.
- `baseline_scan` — the catalog identity epoch changed.

Queue reasons describe **why work is due**, not a security verdict on the plugin.

## Ruleset changes are not artifact-scan reasons by themselves

A new Definitions or Stigma-1 ruleset revision changes **interpretation**, not the plugin bytes. Omega should first replay/reproject the retained typed observations against the new frozen ruleset. If those observations satisfy the new rule contract, no plugin artifact scan is needed.

Additional acquisition becomes queue-worthy only when a separate invalidation applies or replay proves that required evidence is missing. The queue reason `srl_observation_missing` is the important boundary: it means an active rule requires an observation collection that is not retained at the required producer revision, so bounded targeted/deep acquisition is justified.

Similarly, `advisory_changed` normally means re-evaluating retained dependency evidence, while `source_*` reasons advance the separate source-attribution stream rather than reopening the shipped artifact. DeltaScope labels these work classes explicitly in the queue inspector.

## Authority boundary

The causality projection is `readOnly=true`, `mutationAuthority=none`, `policyInput=false`, `queueMutationAuthorized=false`, `scanExecutionAuthorized=false`, and `publicationAuthorized=false`. Production queue state remains owned by the SigmaScope workflow.

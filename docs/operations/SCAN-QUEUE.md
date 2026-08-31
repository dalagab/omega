# SigmaScope scan queue causality

DeltaScope's **Operations → Scan Queue** page explains the already-published SigmaScope queue. It is an inspection surface only: it cannot enqueue work, change priority, run a scan, alter Evidence-v2, or authorize publication.

## Why scanning can appear to start at A again

SigmaScope uses the deterministic `plugin-coverage-first-v2` selection policy. Its first goal is not exhaustive variant coverage: it is to establish at least one current artifact-backed security result for every active plugin that has an obtainable artifact.

Pending work is divided into three lanes:

1. **Plugin first coverage** — an artifact candidate belongs to a plugin for which no current variant has a published artifact scan and that candidate has not yet been attempted.
2. **Plugin first-coverage retry/fallback** — that plugin is still uncovered after an attempted candidate; another eligible sibling variant may therefore become its representative.
3. **Covered refresh / depth** — secondary variants for already-covered plugins, artifact re-analysis, source follow-up, advisory refresh, and other bounded revisits.

Within the first two lanes, source provenance is a scheduling preference: **official** sources first, then **curated/known** sources, then other **discovered** sources. Stable artifacts are preferred over testing artifacts. These classes are not security verdicts and do not imply that an official or curated plugin is safe.

As soon as one artifact variant completes successfully, that plugin is considered represented for queue ordering and its remaining variants move behind still-uncovered plugins. A future catalog seed also carries whether a sibling variant already has published current coverage, so a newly discovered secondary variant cannot accidentally make an already-covered plugin look uncovered.

Lane 1 is exhausted before lane 2, and both are exhausted before lane 3. Reason priority and stable deterministic tie-breakers order work inside those constraints. A large first-coverage wave can still visibly revisit earlier names, but it should no longer spend multiple baseline slots on the same plugin while another active plugin remains wholly unrepresented.

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

## Authority boundary

The causality projection is `readOnly=true`, `mutationAuthority=none`, `policyInput=false`, `queueMutationAuthorized=false`, `scanExecutionAuthorized=false`, and `publicationAuthorized=false`. Production queue state remains owned by the SigmaScope workflow.

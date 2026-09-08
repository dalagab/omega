# Operations guide

The Operations perspective answers whether the Omega security platform is collecting, analyzing and publishing data as expected. DeltaScope treats durable orchestration state as the primary health authority for autonomous collection lanes. GitHub Actions remains runner diagnostics and an explicitly controlled dispatch surface; a workflow conclusion by itself is not a collection-health verdict.

## Navigation

- **Overview** — current platform/evidence state, durable orchestration summary and important notifications.
- **Pipelines** — durable collection lanes first, followed by clearly labelled GitHub Actions diagnostics for stages that are not represented by those lanes.
- **Collectors** — what each collector consumes/produces and its durable queue/lease/result/settlement health where a durable lane exists. Runner history is diagnostic detail.
- **Scan Queue** — the separate SigmaScope plugin artifact/source analysis queue: first coverage, retries, artifact refresh and source follow-up. It is not the generic collection-orchestration queue.
- **Evidence** — current publication health, evidence identity and how acquisition backlog affects coverage. Raw tables remain in Security Researcher → Data.
- **Definitions & Gates** — the frozen interpretation set, Stigma-1 production state and explicit authority boundaries.
- **Reports** — derived coverage/readiness summaries.
- **Diagnostics** — authenticated GitHub read capabilities, runner/log visibility, rate budget, last successful acquisition and any stale/backoff reason. Opening it is snapshot-only; refresh is explicit.
- **Documentation** — operational and architecture reference.

## Durable collection health

The autonomous collection plane is reconciled through `security-work-state`. For a mapped lane, DeltaScope derives the primary status from its durable counts:

- **healthy / settled** — completed work exists and there is no pending, leased, blocked or terminal work;
- **running / leased** — a worker currently holds a durable lease;
- **running / queued** — work is pending execution;
- **warning / blocked** — prerequisites or another retained condition block work;
- **failed / terminal work** — one or more work items reached a terminal outcome requiring review.

This prevents an obsolete or parent GitHub Actions failure from overwriting a successfully settled worker result. It also means a successful runner does not prove security correctness: Evidence-v2 and collector contracts remain the evidence authority.

The current generic lanes are catalog discovery, catalog enrichment, website scraping, source-head observation, threat intelligence, OSV advisories and secondary-security definition refresh. Their worker/result branches can change through the published orchestration contract without granting DeltaScope control-plane authority.

## Collector review

Collectors show the durable lane and current worker workflow when one exists. The most recent Actions observation is retained as **runner diagnostic** context. If the two disagree, the UI displays both and explains that durable settlement owns the primary operational state.

Collectors without a durable lane, such as event-driven specialist analysis paths, continue to show bounded runner/evidence diagnostics without pretending that absence of a recent run is failure.

## Pipelines and GitHub Actions

Pipelines starts with the durable collection lanes. Recent Actions components are appended as **Actions diagnostic** stages. Use those stages to answer questions such as which runner failed, which branch ran and where to open logs. Do not infer queue settlement, evidence publication or collector health from an aggregate workflow name.

Use **Operations → GitHub Workflows** when you explicitly need workflow inventory, job/step/artifact/log inspection or a confirmed `workflow_dispatch`/run control action.

## Scan Queue versus collection orchestration

Operations → **Scan Queue** is intentionally still the SigmaScope plugin-analysis queue. It explains why a plugin variant needs first artifact coverage, retry, re-analysis or source follow-up under the coverage-first contract.

The generic collection lanes are different work: refreshing catalog discovery/enrichment, website data, source heads, threat intelligence, OSV and secondary-security definitions. They live under Pipelines/Collectors and the durable work-state board. Keeping the two queue models separate avoids implying that catalog/intelligence refresh work is a plugin artifact scan.

## Gates

A gated state means a production authority is intentionally disabled or waiting for a prerequisite. A gate should remain visible because it changes what the platform is allowed to publish even when all collection lanes are healthy.

## Incident response for platform failures

1. Identify the durable collection lane or non-durable analysis/publication stage.
2. For a durable lane, inspect pending/leased/blocked/terminal counts and the latest retained work-item settlement.
3. Confirm the required revision/result branch and whether a result was settled.
4. Use the linked/recent GitHub Actions runner only to diagnose execution details; do not let an aggregate parent-job failure replace the durable result.
5. For SigmaScope plugin coverage, inspect the separate Scan Queue and current Evidence-v2 revision.
6. Verify whether publication was attempted, gated or preserved as last-known-good.
7. Fix the source of the failure; do not weaken hash, provenance, lease or validation checks just to make publication continue.

## GitHub Workflow Center

Use **Operations → GitHub Workflows** for workflow inventory, selected-workflow acquisition, guided `workflow_dispatch`, run/job/step/artifact/log inspection and explicitly confirmed cancel/rerun controls. Navigation reads the local snapshot only; see [GitHub Workflow Center](GITHUB-WORKFLOW-CENTER.md).

## Retained operations history and correlation

DeltaScope retains only sanitized `omega.actions.telemetry.v1` worker events in a bounded local journal so useful operational context can survive a restart. The journal deliberately excludes raw job logs and credentials, does not become Security Evidence, and keeps the existing operational self-report authority boundary.

When a structured event identifies a plugin or variant, Operations can pivot directly to that exact asset, its exact-variant Detection Coverage projection, or its Evidence view. The same sanitized event identity can be pinned into a local Investigator case as an `operations-event`; casework keeps the operational reference and timestamp without promoting it into a finding or production evidence.

Retained history is local convenience state. Evidence-v2, Definitions, collector contracts and durable orchestration state remain authoritative for security conclusions and platform settlement.

## Operations diagnostics

Use **Operations → Diagnostics** to see what the connected GitHub credential has actually demonstrated. Successful bounded reads can prove Actions, jobs, active-job telemetry/log access and runner inventory visibility. A connected token alone does **not** prove dispatch/cancel/rerun permission: DeltaScope deliberately avoids a mutating permission probe, so those capabilities remain **configured / unverified** until an operator explicitly confirms a real action in GitHub Workflows.

The page also shows the current GitHub rate budget, the last attempted and last successful live acquisition, stale-cache state, and the bounded retry/backoff reason after failures. Normal navigation does not perform a fresh GitHub request; **Refresh diagnostics** explicitly reuses the existing live Operations acquisition path. Credentials and raw job logs are never returned by this diagnostics projection, and none of these operational facts are Security Evidence authority.

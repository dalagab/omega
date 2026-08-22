# DeltaScope security-information workbench

Status: **Phase 11 complete plus DeltaScope 4.6 Stigma-1 expanded rule library and deep-analysis orchestration** on the unreleased SigmaScope 2.15 development line. Slices 1–8 are implemented: the permanent navigation/workspace shell, deterministic backend incident/event/intelligence projections, lazy selected-case composition with normalized retained-evidence timelines, cross-plugin intelligence/Asset relationship navigation, exact active-rule/Definition provenance, read-only Reports/System health projections, and the final URL-only GitHub candidate proposal handoff.

## Purpose

DeltaScope is a read-only investigator workbench over SigmaScope security information. Its information architecture may borrow the useful operator concepts of traditional SIEM consoles, but DeltaScope is deliberately **not** an administrative control plane.

SigmaScope/GitHub remain authoritative. DeltaScope can browse, correlate, explain, replay and experiment locally; it cannot mutate Security Evidence, Definitions, catalog state, scan queues, active rules, severities or production findings.

## Primary navigation

The workbench uses these stable operator concepts:

- **Dashboard** — coverage, queue state, recent/high-priority security activity, revision context, and read-only component/GitHub Actions status.
- **Incidents** — newest current security findings first, followed by correlated/elevated investigation cases. Incident state is derived/read-only; DeltaScope does not assign, close or mutate incidents.
- **Events** — read-only GitHub workflow operations alongside time-oriented Evidence-v2 security observations/scans.
- **Intelligence** — advisory, endpoint, reputation, component and other enrichment that can be pivoted across plugins.
- **Assets** — plugins first, with drill-down into variants, artifacts, source repositories, binaries, dependencies and endpoints.
- **Rules** — unified Stigma-1 / SRL Core workspace: read-only repository System Rules and active frozen provenance plus versioned local My Rules. Local saves never mutate Definitions or production state.
- **Reports** — coverage/revision/replay summaries and exportable read-only reports.
- **Documentation** — allow-listed local Stigma-1/SRL authoring, examples, Definition Pack and security-architecture references.
- **System** — evidence/Definitions revisions, pipeline health, audit status and the advanced raw Evidence-v2 browser.

## DeltaScope 4.6 Stigma-1 rule library + deep-analysis orchestration

Rules can now describe a typed evidence-acquisition outcome. System/frozen rules can feed the durable SigmaScope Deep Scan queue; My Rules only preview the same outcome. The visual Emit node exposes the approved deep-analysis profiles without exposing commands or runner controls. Deep Scan runs as its own GitHub Actions workflow and therefore does not consume the normal bounded SigmaScope scan budget. See `DEEP-SCAN-WORKFLOW.md`.

## DeltaScope 4.3 operational visibility

The dashboard and Events page may query GitHub's public Actions metadata for `dalagab/omega` (or an explicitly configured `owner/name`) so the workbench can answer whether SigmaScope, Omega builds, Catalog/Definitions, DeltaScope, Stigma-1/regression/source-intake workflows are running or recently failed. This is deliberately not a control plane: only GET metadata is used; DeltaScope exposes no dispatch/retry/cancel action. A short in-process cache avoids repeated API calls, and an unavailable/rate-limited GitHub response degrades to an `unavailable` status without affecting Evidence-v2 browsing.

Incidents separately asks the selected Evidence source for a bounded newest-current-finding preview. Modern Evidence-v2 summary counts let the online inspector avoid fetching clean variants; older pre-summary snapshots use a bounded compatibility fallback. Clicking a finding composes the same read-only case projection already used elsewhere.

The Documentation workspace reads exact docs shipped with the checkout via stable document IDs. The server never accepts an arbitrary documentation path. Start rule work with `STIGMA-1.md`, then the rule-author README, SRL language specification, data reference and examples.

## Investigation flow

The intended navigation is bidirectional and preserves context:

```text
incident
 -> finding / correlation
 -> event / observation
 -> plugin asset / artifact / source / component / endpoint
 -> active rule + exact revision/provenance
 -> local Rule Lab replay (optional)
 -> GitHub candidate proposal (optional)
```

No step in that flow modifies authoritative state.

## Mutation boundary

A proposed rule or Definition change follows this path:

```text
DeltaScope local candidate / fixture / replay
             |
             v
candidate export / GitHub proposal
             |
             v
GitHub permission gate -> CI -> review -> PR merge
             |
             v
Daily Definitions freeze
             |
             v
new authoritative SigmaScope/DeltaScope view
```

DeltaScope must never expose direct actions equivalent to Activate Rule, Disable Production Rule, Rewrite Evidence, Change Finding Severity, Modify Queue, or Save Definitions.

## UI principle

The UI should favor dense, comprehensible operator workflows over decorative landing-page design: permanent navigation, clear tables, contextual drill-down, revision/provenance visibility and minimal loss of place. The visual design is modern, but the operator should be able to move quickly among incidents, events, assets and rules in the same way mature security consoles make relationships easy to follow.

## Phase-11 implementation slices

1. **Implemented:** workbench shell + stable primary navigation over existing read-only data.
2. **Implemented:** deterministic read-only incident/event/intelligence navigation objects from current asset/security summaries, with stable IDs/revisions and `mutationAuthority=none`.
3. **Implemented:** selected incident/event composition over current findings, researcher signals, advisory intelligence, bounded retained observation collections and the non-authoritative Phase-10 SRL projection/reanalysis sidecar. `/api/workbench/case` loads this detail lazily for one variant, emits `omega.deltascope.incident-case-projection.v1` plus `omega.deltascope.security-timeline.v1`, and never turns a reprojection/reanalysis relationship into queue or production state.
4. **Implemented:** cross-plugin Intelligence pivots over the published read-only relationship index. Endpoint, component and advisory rows expose affected variants/plugins and can pivot back into Asset investigations without scanning the corpus in the browser. The index is `omega.security-evidence.workbench-relationships.v1`, explicitly `readOnly=true`, `mutationAuthority=none`, and `policyInput=false`.
5. **Implemented:** Asset relationship navigation: plugin -> variant -> artifact/source -> component/endpoint/advisory. `/api/workbench/asset-relations` returns a deterministic `omega.deltascope.asset-relationship-projection.v1` graph; relationship clicks pivot into Intelligence for ecosystem-wide context.
6. **Implemented:** exact active-rule browser backed by the published frozen Definitions provenance sidecar, including Definition Pack/rule revisions, review/provenance metadata, source hashes, fixtures and migration-parity state. It never reads development-tree packs to decide what is active.
7. **Implemented:** deterministic Reports/System projections for coverage, SRL reprojection/reanalysis readiness, queue state, Evidence/Definitions/scanner/SRL revision lineage and explicit production/read-only safety gates. These are derived views only.
8. **Implemented:** GitHub proposal handoff from Rule Lab. DeltaScope validates the candidate plus positive/negative fixtures locally, then opens GitHub's normal `sigmascope-rule-candidate.yml` Issue Form with URL-query prefills. The operator must review and submit the issue in GitHub. No GitHub API write/token/repository credential is used by the proposal path. A conservative URL-size guard falls back to metadata/identity-only prefills and explicit copy buttons for omitted YAML. GitHub then re-fetches/revalidates the submitted issue through the Phase-9 permission/CI/review/normal-PR workflow. `/api/rule-lab/promote` remains absent.

## Relationship-index boundary

Cross-plugin questions must not require DeltaScope to download every variant's deep evidence. Evidence-v2 therefore publishes a small derived `indexes/workbench-relationships.json` navigation index containing endpoint↔variant, component↔variant and advisory↔affected-variant relationships. It is derived from already-published evidence/resolution state, hash-verified by the Evidence-v2 root, bounded during export, and intrinsically rejected if it claims write or policy authority. It is **not** a SigmaScope observation collection, SRL input, finding, queue instruction or production-policy surface.

DeltaScope exposes it through read-only endpoints `/api/workbench/relationships`, `/api/workbench/pivot`, and `/api/workbench/asset-relations`. Older Evidence-v2 snapshots without the index remain browseable and simply show relationship intelligence as unavailable.


## Definition-provenance boundary

Evidence-v2 may publish `indexes/definition-provenance.json` using `omega.security-evidence.definition-provenance.v1`. It is built only after `definition_packs.verify_frozen(...)` succeeds against the exact Daily Definitions root and is hash/size/schema verified by the Evidence-v2 root. It records the authoritative Definitions revision, legacy scanner revision, SRL Definition-Pack/ruleset revisions, exact reviewed packs/rules, rule source hashes, review/provenance metadata, fixtures and migration-parity summary. It explicitly declares `readOnly=true`, `mutationAuthority=none`, and `policyInput=false`; DeltaScope cannot use it to activate a rule or alter policy. A provenance-only semantic revision change is still publication-worthy because stale review/rule lineage is unacceptable in an investigator console. Snapshot timestamp-only churn is excluded from the provenance revision so a no-op Daily freeze does not force publication.

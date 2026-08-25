## 2026-08-25 — Source build and dependency observation expansion

- Add source-only `omega.sigmascope.source-build-intelligence.v1` collection during the existing SigmaScope source-analysis pass; source retrieval still happens once and no build commands or plugin code are executed.
- Retain first-class project/build graph, project-reference edges, build-input identities, SDK/package-policy context, managed dependency declarations/locks and bounded CI/release construction metadata.
- Promote `sourceBuildProjects`, `sourceBuildEdges`, `sourceBuildInputs`, `sourceBuildEnvironment`, `sourceDependencyDeclarations` and `sourceReleaseWorkflows` into replayable Evidence-v2/SRL observation collections, including exact empty collections only when the new source-build contract was actually collected.
- Keep release-workflow metadata as developer-authored source context only: it does not prove that a workflow or observed source revision produced the distributed plugin artifact; exact build proof remains the future Rebuilder boundary.
- Avoid retaining arbitrary CI `run:` command bodies or NuGet credential material; package-source URLs are stripped of user-info, query and fragment data before they enter retained evidence.
- Keep the artifact-analysis revision unchanged. Only the source-analysis revision changes, so this pass schedules source follow-up work rather than restarting artifact coverage.
- Keep SigmaScope 2.15.0 and finding/severity semantics unchanged.

## 2026-08-25 — First-class ELF and Mach-O structural collectors

- Activate `omega.collector.sigmascope.native-structure` as a broker-dispatchable, non-executing specialist collector for `elfBinaryStructure` and `machOBinaryStructure`.
- Retain bounded ELF loader/dependency/hardening structure including interpreter, `DT_NEEDED`, RPATH/RUNPATH, PIE, RELRO, bind-now, executable-stack state, writable+executable segments and bounded dynamic symbol inventories.
- Retain bounded Mach-O load-command structure including dylib dependencies, rpaths, architecture/slice identity, entry offset, build/minimum OS metadata, encryption flag, code-signature **presence** and concrete initial writable+executable segment state; code-signature presence is not trust validation.
- Route native-structure observation requests through a dedicated Ubuntu collector lane using the existing content-addressed collector-result, collector-only Evidence-v2 adapter and independent publication audit.
- Extend neutral collector coverage policy so retained native ELF/Mach-O classifications request their matching structural observations automatically.
- Bound generic collector string-array fields to 4,096 values in addition to the existing per-string and row ceilings.
- Keep SigmaScope 2.15.0 and existing artifact/source analysis revisions; this pass adds replayable specialist observations rather than changing static finding semantics.

## 2026-08-25 — First-class Authenticode collector and generic collector results

- Activate `omega.collector.sigmascope.authenticode` as the first specialist SigmaScope collector lane.
- Add a Windows-native, non-executing Authenticode probe over exact broker-bound artifacts; retain PE signer, digest, chain, timestamp and platform-validation observations without assigning a security verdict; Windows trust reuse is TTL-bound for seven days rather than treated as permanently immutable.
- Add content-addressed `omega.collector-result.v1` envelopes with per-collector and per-observation contract revisions, bounded rows/errors, exact subject binding and tamper detection.
- Add a generic collector-to-Evidence-v2 adapter plus an independent collector-only publication audit; collector updates may change Evidence-v2 evidence revision but must not change catalog/security revision or static scan evidence.
- Extend Evidence-v2 observation contracts, observation inventory and SRL replay to consume registered external collector observations while keeping core SigmaScope observations exactly reproducible.
- Add neutral collector coverage reconciliation: retained native-PE classifications request `binarySignatureTrust` automatically, while managed-only PE artifacts are not queued.
- Route Authenticode requests to a dedicated `windows-latest` lane and add a Windows regression smoke job for the native trust probe.
- Keep SigmaScope 2.15.0 and the existing artifact/source analysis revisions; this pass adds a separate observation collector rather than changing static scanner semantics.

## 2026-08-25 — Post-split SigmaScope regression ownership fix

- Remove stale SigmaScope tests that required the physically separated DeltaScope workflow/CLI to remain present on the `sigmascope` branch.
- Keep equivalent producer-side coverage for SRL compilation, fixture evaluation, typed collector bundles, retained Evidence-v2 replay, and published author-reference contracts.
- Strengthen the branch-split regression to require DeltaScope runtime/workflow files to be absent from the SigmaScope tree.
- No scanner, SRL language, Evidence-v2, or publication semantics change.

## 2.15.0 — DeltaScope source-tree extraction boundary

- Physically separate the DeltaScope application/consumer SDK from the SigmaScope security-services source package.
- Replace the production Evidence-v2 dependency on `deltascope_provenance` with SigmaScope-owned `definition_provenance`.
- Make the reputation collector read the published Evidence-v2 relationship contract directly instead of importing the DeltaScope inspector.
- Keep execution-topology/component/collector/capability/SRL contracts as the supported consumer boundary.

## 2.15.0 — DeltaScope 4.21.7 / consumer SDK + execution-topology separation

- Extract a bundled non-authoritative `deltascope_sdk` containing DeltaScope's deterministic SRL parser/evaluator, observation/Definition-Pack compatibility contracts, and registry readers; primary DeltaScope runtime modules no longer import the production Stigma/SigmaScope copies directly.
- Allow the consumer SDK to bind hash-verified published component, collector/provider and capability registry **data** at runtime, so future component kinds and rule-eligible observation types can become visible/authorable without remote code loading or DeltaScope ID-specific cases.
- Add `omega.execution-topology.v1` as a frozen Definitions platform contract describing execution nodes, component ownership and workflow/job/step correlation without launch/policy authority.
- Make DeltaScope Operations derive workflow history targets from the published execution topology; unknown future execution nodes render generically even without a custom metrics parser.
- Download/hash-verify the execution topology when the descriptor is present, while retaining a bundled read-only rollout fallback for older published Definitions.
- Expose consumer-SDK and execution-topology state through `/api/platform-contracts` and `sync-resources`.
- Preserve Python, offline last-known-good resource behavior, local-only rule/case writes, and the strict ban on downloading `definitions/worker/**` or any executable scanner code.
- No change to SigmaScope artifact/source analysis revisions, Security Evidence authority, Stigma production gating, broker/dispatcher authority, or Rift execution.

## 2.15.0 — DeltaScope 4.21.6 / published-contract separation pass

- Give DeltaScope its own `deltascope/requirements.txt`; the root launcher no longer inherits `tools/requirements-security.txt`, so future scanner dependencies do not leak into the local workbench runtime.
- Add a verified read-only published-resource cache over `catalog-data/definitions`: online DeltaScope materializes frozen SRL pack sources/fixtures, the compiled SRL ruleset, and component/collector/capability registries as data.
- Verify every child payload against the SHA-256 pinned by the published Definitions/SRL indexes, store immutable revision snapshots, and reuse only the last verified snapshot when refresh is unavailable.
- Explicitly exclude the frozen `definitions/worker/**` SigmaScope bundle from DeltaScope resource synchronization; this is data/contract consumption, not remote scanner-code loading.
- Add `sync-resources`, `--definitions-base-url`, `--offline-resources`, and stale-cache controls for explicit consumer synchronization/diagnostics.
- Feed published Definition Pack sources into the Rule Library/Rule Workspace in online mode instead of requiring the repository copy to be current. Local repository packs remain a fail-soft development fallback.
- Overlay the published component registry on the Components & Actions dashboard and expose the published collector/provider registry generically, so newly registered components/providers can appear without DeltaScope-specific ID cases.
- Add `/api/platform-contracts`, `deltascope/runtime-contract.json`, and `docs/DELTASCOPE-SEPARATION.md` to make the consumer boundary inspectable.
- Keep Python and the bundled SRL compatibility/evaluator layer for now; production findings, queues, Definitions, Evidence-v2 and dispatcher authority remain unchanged.

## 2026-08-25 — DeltaScope relationship-capacity hotfix

- Fixed production Sigmascope launcher failure `32782612429`: the existing Evidence-v2 relationship projection was already at 198,846 / 200,000 component edges before the batch, so normal scan growth crossed the obsolete fixed ceiling.
- Suppress exact duplicate component relationship rows before DeltaScope transport counting/writing.
- Replace the fixed 200,000 relationship guard with a catalog-scaled bounded ceiling: minimum 250,000, 512 edges per represented current variant, absolute maximum 2,000,000.
- Publish relationship-capacity and duplicate-suppression diagnostics in the read-only workbench relationship manifest.
- Preserve the existing 8 MiB compressed shard target and 32 MiB per-file Evidence-v2 publication ceiling.
- No main-branch dispatcher change and no narrow SigmaScope artifact/source analysis semantic change.

## 2026-08-25 — Closed-loop Stigma evidence acquisition

- Added production `omega.observation-inventory.v1` materialization from current Evidence-v2 and compatible Discovery observations, including immutable/static and TTL freshness semantics.
- Added hash-pinned Stigma `observation-requests.json` projections with explicit broker-only evidence-acquisition mutation authority and no production finding write-back.
- Added deterministic/idempotent Stigma → Analysis Broker reconciliation for typed observation requests and compatible retained-observation replay gaps.
- Added stable exact-subject broker request identities; repeated reconciliation does not create duplicate work.
- Extended Analysis Broker enqueue/resolve to consume the production inventory and safely re-resolve already-compiled requests.
- Updated the default-main dispatcher v4 ordering to `reconcile → reserve → asynchronous workers`.
- Updated the missing-components roadmap: Stigma→Broker ingestion and observation-inventory materialization are implemented; remaining work is explicitly ranked.
- Final workflow audit removed a duplicate `allowed_components` input declaration from the batch-claim reusable workflow, added the same explicit allow-list to manual dispatch, and added a regression assertion for duplicate-key recurrence.
- No Rift implementation changes and no change to narrow SigmaScope artifact/source analysis revisions.

## 2026-08-24 — Generic SigmaScope request adapter and roadmap

- Added generic Analysis Broker → SigmaScope request adaptation into the existing canonical scan queue.
- Added exact canonical queue-key execution for broker-bound work and post-run Evidence-v2 observation verification.
- Marked SigmaScope broker-dispatchable with `maxConcurrent: 1`; parallel Evidence-v2 writers remain prohibited.
- Added rollout-safe dispatcher `allowed_components` handling so older main runners cannot lease newly enabled component work.
- Added main SigmaScope dispatcher worker template.
- Added `docs/platform/MISSING-COMPONENTS.md`, documenting missing deployable components, missing SigmaScope collectors and remaining control-plane/Evidence/DeltaScope work.
- No Rift implementation changes.

# Rift Evidence-v2 production adapter v1

- Activate `omega.collector.rift.runtime` as a typed runtime-observation provider.
- Add `riftRuntimeEvents`, `riftRuntimeExercise`, `riftRuntimeBoundary`, and optional `riftComponentSecurity` observation contracts.
- Add broker-bound `omega.rift.execution-request.v1` generated from current Evidence-v2 variant/artifact identity.
- Add production `rift.supervisor-attestation.v2` overlay binding request ID, variant ID and distributed artifact SHA-256 to the trusted supervisor report digest.
- Add fail-closed Rift runtime contract validation, Evidence-v2 adapter, independent ingestion audit, and reusable/manual ingestion workflow.
- Retain exact runtime-report bytes and broker/attestation/typed-observation documents under bounded per-variant derived Rift evidence.
- Preserve standalone Rift attestation v1 compatibility while prohibiting it from production Evidence-v2 publication.
- Keep existing deep-scan worker static/non-executing; dynamic broker routing/download capture/fresh reruns remain deferred.
- Preserve SigmaScope 2.15.0, DeltaScope 4.21.5, and unchanged narrow artifact/source analysis revisions.

# First-class collector observations / Omega Discovery

- Promote the independent six-hour discovery plane into **Omega Discovery** (`omega.discovery`) with stable collector IDs and typed observation contracts.
- Add `omega.collector-registry.v1` and `omega.collector-observation-bundle.v1`, including deterministic provider registration, per-row collector/provenance metadata and fail-closed provider/type validation.
- Add bounded project-page/README candidate reuse, rotating GitHub repository-tree manifest inspection, Omega issue hints and optional configured Brave Web Search queries to discovery.
- Keep canonical-known source URLs skip-first and preserve reusable normalized novel-feed shards for the daily builder.
- Register SigmaScope static/source/secondary observation producers in the shared provider vocabulary; reserve Rift runtime collection as planned/inactive.
- Let Stigma-1 consume rule-eligible external collector observations without changing Evidence-v2 collection contracts.
- Add non-executable `observationRequest` outcomes that name only a logical collection; resolve provider candidates with orchestration-only execution authority and reject implementation `collectorId` binding.
- Let DeltaScope evaluate a local rule against a typed collector bundle and display the new discovery workflow without losing legacy source-discovery operational history.
- Add Omega Discovery/collector architecture documentation and a shipped discovery rule/fixture.

## 2.15.0 — fresh Omega client projection + independent catalog discovery

- Change the Omega marketplace projector to **1.7.0** and build every downloadable client SQLite database from a new empty allow-listed schema (`client_projection_mode=fresh-allowlist-v1`). The client receives only `catalog_meta`, reduced `sources`, reduced changelog-capable `plugins`/`plugin_variants`, the frozen current `runtime_plugin_variants` table, and `catalog_changelog` when present. Raw manifests, scraper state, source/identity working tables and detailed security tables cannot cross this boundary.
- Add `client_database_audit.py` and a catalog publication gate that reports table/page usage, rejects prohibited server-side tables, caps the client DB at 48 MiB, and rejects >20% unexplained growth versus the previous release when available.
- Stop using yesterday's downloadable client DB as the builder cache. Manifest and website conditional-fetch hints are materialized from the previous canonical `catalog-data` snapshot instead.
- Add independent `catalog-discovery` snapshots. The reusable worker searches public JSON candidates, checks open Omega source-submission/follow-up issues, skips canonical source URLs without fetching them, validates only genuinely novel PluginMaster feeds, and classifies entries as new-plugin or new-source-variant facts without assigning catalog identity.
- Persist each freshly validated novel feed as a bounded normalized discovery shard. The next daily enrichment run reuses that shard directly while it is fresh (24-hour default), so discovery does not immediately pay for a second download/parse of the same JSON source.
- Make the daily catalog collector preserve the entire current canonical source inventory, overlay a fresh discovery snapshot, and skip duplicate GitHub code search while that snapshot is fresh. A missing/stale discovery snapshot falls back to the existing live search.
- Add an Evidence-v2 storage audit that measures bytes by artifacts/current variants/history/queue/derived areas and exact duplicate SHA groups. This pass is measurement-only: no security evidence/history is deleted or rewritten.
- Add a default-branch discovery launcher (every 6 hours) plus reusable `sigmascope` worker. The discovery branch is an orphan/replaceable non-authoritative snapshot, not a second catalog database.

## 2.15.0 — DeltaScope 4.21.5 / deterministic developer review plan

- Add `omega.deltascope.developer-review-plan.v1`, a bounded read-only **Next actions** projection for the selected Plugin Developer dossier.
- Prioritize exact existing pivots for elevated findings, sibling divergence/coverage gaps, source attribution/source-to-artifact gaps, incomplete secondary engines, frozen advisories, retained history and temporary immutable-dataset transport failures.
- Keep the plan deterministic and bounded to eight actions; each cue routes to an existing dossier tab and never executes scans or mutates production state.
- An empty plan means only that no compact current cue requires a specific follow-up; it is never a clean/safe verdict.
- Add dedicated unit coverage for guidance priority/authority/routing and keep the broader DeltaScope regression suite passing.

## DeltaScope 4.21.4 — logical-plugin cross-source divergence and Overview runtime repair

- Restore the scanned-plugin `dossierOverviewHtml()` browser renderer accidentally dropped during the 4.21.3 compatibility refactor; add a regression contract that requires the runtime Overview function to exist.
- Add read-only `omega.deltascope.logical-plugin-divergence.v1` beneath the selected logical-plugin context so a collapsed My Plugins row explains whether current source/build siblings actually align.
- Surface partial Evidence-v2 coverage, version/API skew, and source multiplicity without treating ordinary release/repository skew as suspicious.
- Escalate only same-version + same-API artifact-hash or compact security-summary differences into explicit review cues. Those cues are navigation/explanation only and never SigmaScope findings or source-trust verdicts.
- Carry compact per-sibling artifact SHA-256 plus finding-count summaries in both online Evidence-v2 and local SQLite logical-plugin context; no N-sibling detailed-evidence fan-out is added.
- Put the selected variant first and current-compatible siblings ahead of legacy siblings in the variant matrix, while retaining exact variant identity and direct Inspect variant pivots.
- Keep 4.21 as the main DeltaScope line; subsequent refinements continue as 4.21.5, 4.21.6, etc. until an explicit main-version advance.

## DeltaScope 4.21.3 — current-compatible My Plugins and legacy visibility

- Make Plugin Developer **My Plugins** current-compatible by default: stable variants matching the selected Dalamud API target are shown normally, while API-unknown catalog identities remain visible rather than being silently discarded.
- Add a browser-local **Show old / unsupported** preference plus a browser-local current Dalamud API target (default **15**). These settings affect DeltaScope display/navigation only and never change Omega install policy, Catalog identity, SigmaScope coverage, findings, queues or Evidence-v2.
- Classify logical plugins and sibling variants as `current`, `unknown`, `testing-current`, `outdated`, `future`, `hidden`, or `retired`, and show the reason directly in the picker and selected-plugin variant matrix.
- Prefer a current-compatible sibling as the logical picker representative when one exists, even if an older sibling is the only variant with current security evidence. Security evidence remains independently attributed per variant.
- Preserve the full logical catalog model behind the filter. Enabling legacy visibility restores old/unsupported/historical identities without changing their catalog `plugin_id` grouping.
- Align online Evidence-v2 and local SQLite mode: inactive logical plugins expose their historical sibling variants and retained API/hidden metadata instead of local mode silently dropping them.
- Keep **4.21** as the main DeltaScope line; subsequent refinements continue as `4.21.4`, `4.21.5`, etc. until an explicit main-version advance.

## DeltaScope 4.21.2 — logical plugin variant/source coverage matrix

- Keep **My Plugins** at one row per canonical catalog `plugin_id`, while making the active source/build/version variants underneath that logical identity directly inspectable from the selected-plugin Overview.
- Add read-only `omega.deltascope.logical-plugin-context.v1` to selected plugin dossiers in both online Evidence-v2 mode and local SQLite mode.
- Show every active catalog variant with its source identity, assembly version/API, repository context, exact current Evidence-v2 presence, scan ID and highest severity.
- Distinguish partial coverage at the logical-plugin boundary: an unscanned selected variant can show that a sibling variant is covered without treating either state as a verdict for the other.
- Add **Inspect variant** actions so Plugin Developer can drill into a specific source/build variant without reintroducing duplicate logical rows in the global My Plugins picker.
- Keep sibling coverage lightweight: online detail loads one selected catalog plugin shard and overlays sibling state from the already-loaded compact current Evidence-v2 index; it does not fan out into one evidence-payload request per sibling.
- Preserve security authority boundaries: catalog grouping/context is navigation and coverage explanation only; Investigator/Security Researcher remain variant-oriented and no scanner, queue, finding, severity, Definitions, Evidence-v2 publication or catalog mutation semantics change.
- Keep **4.21** as the main DeltaScope line; subsequent refinements continue as `4.21.3`, `4.21.4`, etc. until an explicit main-version advance.

## DeltaScope 4.21.1 — logical My Plugins and full catalog inventory

- Change the global **My Plugins** picker from Evidence-v2 variant rows to one row per canonical Omega catalog `plugin_id`; repository/build/version variants remain separately inspectable in Investigator and Security Researcher security views.
- Read the verified current `catalog-data/catalog/plugins/index.json` logical-plugin inventory in online mode and overlay matching current Evidence-v2 coverage, so catalog-known plugins no longer disappear merely because security evidence is pending.
- Keep assembly name/version as display and diagnostic context only. They are **not** merge authority, preventing unrelated plugin IDs that happen to ship the same assembly name from being collapsed together.
- Gate current coverage by the catalog's active variant IDs: evidence from an old/inactive variant cannot make a current catalog variant look scanned.
- Allow catalog-only selections to open a read-only **Known catalog plugin · security coverage pending** dossier, lazily fetching only that plugin's verified catalog shard. `UNSCANNED / NO CURRENT EVIDENCE` is explicitly not a clean/security verdict.
- Keep the existing security workbench variant-oriented; no SigmaScope queue, scanner, finding, severity, Definitions, Evidence-v2 publication or catalog mutation semantics change.
- Keep **4.21** as the main DeltaScope version line; subsequent refinements continue as `4.21.2`, `4.21.3`, etc. until an explicit main-version advance.

## DeltaScope 4.21.0 — Investigator case reference health and timeline

- Upgrade local Investigator Cases from passive pin lists into a bounded casework workspace with **Pins / Timeline / Notebook** views.
- Resolve up to 250 pinned references per case against the current verified evidence snapshot, caching by variant so repeated pins do not create duplicate dossier fetches.
- Distinguish exact current references, retained historical snapshots, findings re-observed on a newer scan, changed references, unresolved pivots and missing variants without silently substituting current evidence for an unproven historical target.
- Reopen retained finding/observation/snapshot pins through the exact retained snapshot path when scan/artifact identity can be proven.
- Build a chronological local investigation timeline from case creation, evidence timestamps, pins and investigator notes.
- Keep the projection read-only/local-only with zero security/finding/policy/Definitions/Evidence/queue/publication/repository authority.
- Keep **4.21** as the main DeltaScope version line; follow-up refinements should use 4.21.1, 4.21.2, and so on rather than advancing to 4.22 immediately.

## 2.15.0 — DeltaScope 4.20.0 / scan queue causality and coverage-first explainability

- Add **Operations → Scan Queue** as a dedicated read-only workspace instead of routing queue inspection through generic Reports.
- Project the published SigmaScope queue as `omega.deltascope.scan-queue-causality.v1`, with explicit first-coverage, first-coverage-retry, and already-covered refresh/follow-up lanes.
- Explain `baselineSecurityRebuild` and the catalog identity epoch separately from ordinary `new_variant` coverage work, so an alphabetical return to A is not mistaken for deleted Evidence or a full security reset.
- Preview the next bounded queue items using the exact published `coverage-first-v1` ordering contract, including the deterministic `InternalName` tie-break. If a future selection policy is unknown, DeltaScope refuses to claim exact order.
- Expand queue reasons into human-readable causes (`new_variant`, artifact/source analysis changes, source follow-up, advisory refresh, failed retry, baseline scan, and Stigma-1 observation requirements).
- Keep queue causality explanation-only: `mutationAuthority=none`, `policyInput=false`, and no queue mutation, scan execution, Definitions, Evidence-v2, or publication authority.
- Add the Operations manual `docs/operations/SCAN-QUEUE.md` explaining coverage-first behavior and the identity-epoch boundary.

# DeltaScope finding lineage

- Add clickable **Trace lineage** actions to current plugin findings, latest findings, and Investigator case findings.
- Add read-only `omega.deltascope.finding-lineage.v1` projections that connect producer/collector → retained collection/observation → Stigma-1 selector/fact/rule (when published provenance permits exact replay) → current finding → published Security Evidence.
- Exact Stigma-1 replay is claimed only when all required collection rows are loaded under complete `retained` observation-contract semantics. Bounded or missing observation transport keeps the lineage structural and explicitly non-exact.
- Findings that do not resolve to a rule in the published Definitions provenance receive a bounded SigmaScope static lineage instead of substituting current repository/My Rules as false historical authority.
- Collection nodes open the collection inspector; Stigma-1 rule nodes open the System Rule. Historical plugin versions remain archive-only and never enter current finding lineage.
- Document the endpoint-reputation boundary: endpoint classifications are deterministic static context and the frozen reputation set currently has no third-party URL/IP reputation feed.
- Document DLL coverage: bundled `.dll`, `.exe`, `.so`, and `.dylib` members are hashed/classified and statically analysed; YARA scans bounded safe member targets. Runtime-only external DLL bytes are not scanned unless separately acquired as evidence.
- Finding lineage remains explanation only (`mutationAuthority=none`, `policyInput=false`) and cannot alter findings, queues, Definitions, scans or published Evidence.

# DeltaScope collector health and trends

- Operations → Collectors now separates the newest runner outcome from a bounded operational trend state.
- Collector trend projections include recent success/failure rate, step duration and recent median baseline, parsed throughput/output-volume history, learned freshness/cadence, and collector-specific quality ratios where the runner emits both numerator and denominator.
- Stable-universe collectors can flag sharp throughput drops and successful zero-result anomalies. Workload-driven SigmaScope batches are not penalized for naturally smaller batches; selected-versus-completed work is evaluated instead.
- Recent GitHub Actions history is expanded to eight runs while log downloads stay bounded to collector-relevant jobs in the newest four runs. Older runs contribute outcome/timing history without log downloads.
- Collectors now show mini trend plots, current-vs-baseline values, explicit anomaly explanations, duration and throughput in recent-run history, and top-level degrading/warning/stale summaries.
- Collector trend state remains read-only diagnostic context and has no security-policy or production mutation authority.

## 2.15.0 — DeltaScope 4.19.0 / local Investigator notebooks and cases

- Add a bounded local Investigator case store under `~/.omega/deltascope/investigator/v1` with `OMEGA_DELTASCOPE_CASE_HOME` / `--case-home` override.
- Investigator **Cases** now supports local titles/status/labels, notes, plugin bookmarks, pinned finding and retained-observation references, saved intelligence pivots, and Evidence-v2 snapshot references.
- Preserve useful variant/scan/Evidence/Definitions/rule-set/artifact-hash identity in pins when available so a later publication refresh does not erase the investigator's original context.
- Expose pin actions only in the Investigator perspective and keep published findings/incidents as a separate read-only route.
- Every local case and item is explicitly non-authoritative: no finding, severity, policy, queue, Definitions, Evidence-v2, publication, repository or production write-back.

## 2.15.0 — DeltaScope 4.15.0 / Detection Coverage and blind-spot matrix

- Add **Security Researcher → Detection Coverage**, a current-version matrix that audits whether SigmaScope has complete/current observation producer coverage across the active plugin corpus.
- Keep coverage semantically distinct from positive detections: a complete empty observation collection is valid negative evidence, not a blind spot.
- Use narrow artifact/source analysis revisions and scan completeness to classify current variants as covered, stale, incomplete, or outside the applicable source scope. Historical plugin versions remain archive evidence and never inflate current coverage denominators.
- Connect every observation family to its producer, backing dataset, typed contract, current producer revision, active Stigma-1 rules that require it, bounded gap preview, and remediation guidance.
- Add OSV/NuGet coverage using the frozen package-version query universe rather than plugin count; advisory coverage gaps call for Definitions/advisory refresh rather than plugin rescans.
- Keep exact retained collection rows lazy: the matrix is an index/revision contract audit, while **Inspect selected plugin data** opens the existing collection inspector for exact current-plugin observations.
- Coverage remains read-only (`mutationAuthority=none`, `policyInput=false`) and cannot rescan plugins, mutate queues, change findings, or publish Definitions/Evidence.

## 2.15.0 — DeltaScope 4.14.0 / automatic verified published-state refresh

- Follow online published Security Evidence and frozen Definitions automatically: check immediately when the workbench opens and every 60 seconds while it remains open.
- Treat Evidence revision/plugin-index changes, Definitions revision changes, active rule-set changes, and Definitions-provenance changes as refreshable publication state.
- Verify the candidate root, current plugin index, and Definitions provenance before swapping the live workbench snapshot. Raw-GitHub publication races retry from one immutable Git commit without weakening SHA-256 validation.
- Make snapshot replacement transactional: a failed refresh retains both the previous logical root and its transport pin as last-known-good state.
- Preserve perspective, workspace, selected plugin/tab, and rule-authoring context across refresh. If a plugin advances to a new current variant, follow it automatically while keeping the older version as archive evidence.
- Preserve unsaved My Rules and revalidate them after Definitions refresh; System Rules are reopened against the refreshed frozen library and disappearing rules become an actionable warning.
- Coalesce successful publication updates into one informational, already-read event instead of stacking unread Definitions/Evidence notifications. Refresh failures remain one retryable attention item.
- No scanner, queue, finding, Definitions, Evidence-v2, GitHub, or production mutation authority is added to DeltaScope.

## 2.15.0 — DeltaScope 4.13.2 / inspectable SRL collections

- Make Stigma-1 `requires` collections first-class inspectable objects instead of dead identifiers.
- Clicking a collection such as `staticPatternMatches` from rule context/flow/compiled semantics opens its producer, backing dataset, scope, observation schema, typed fields, completeness, and notes.
- When a plugin is selected, the collection inspector shows a bounded preview of the retained rows from the current plugin version only. Archive versions remain available elsewhere but do not become current rule inputs.
- System Rules allow direct single-click inspection of collection tokens in the read-only YAML editor; editable My Rules use double-click so ordinary cursor/edit behavior is preserved.
- Add a read-only `/api/rule-lab/collection` projection with `mutationAuthority=none` and `policyInput=false`.

## 2.15.0 — DeltaScope 4.12.0 / coherent online snapshots and current-version security totals

- Recover from raw GitHub Evidence-v2 branch races by pinning the retry to the branch's immutable Git commit when a variant/index SHA-256 mismatch is observed; SHA verification remains mandatory and the mutable branch is still used for update discovery.
- Reload the lightweight Evidence-v2 index graph on race recovery even when the published root token is unchanged, covering CDN/edge propagation where adjacent files briefly disagree.
- Add a **Plugin versions** block to the selected plugin dossier: the current version is explicit, older retained scans are shown as archive evidence, and archive rows are clearly excluded from current security totals.
- Make SQLite headline finding/high/critical totals join through `plugin_security_current`, so old risky versions remain investigable without keeping historical HIGH/CRITICAL counts alive on Dashboard/Reports. Online Evidence-v2 totals already derive from `currentVariants` and now expose the same current-only contract explicitly.
- Preserve old scans/superseded snapshots for comparison and investigation; this changes DeltaScope projection semantics only and does not delete archive evidence or modify SigmaScope findings.

## 2.15.0 — DeltaScope 4.11.5 / startup null-safety

- Fix DeltaScope startup after the OpenShift shell cleanup: the removed Definitions header pill is now an optional presentation target instead of an unconditional DOM write.
- Add a regression guard so removing optional shell widgets cannot reintroduce this `Cannot set properties of null` failure.

## 2.15.0 — DeltaScope 4.11.5 / OpenShift rail and rule-authoring workspace refinement

- Move **TONI** into the lower-left navigation rail, replacing the repetitive production read-only note. TONI remains a deterministic/read-only guide and retains Coverage, Queue, and Selected shortcuts.
- Replace letter badges in perspective navigation with inline SVG icons and render navigation groups as OpenShift-style collapsible sections.
- Replace the permanently wide header plugin dropdown with a compact **plugin picker icon** at the right side of the global header. The picker opens a temporary searchable plugin list and preserves selected-plugin context.
- Keep the notification bell and nine-dot Omega application switcher at the far right of the global header.
- Simplify Rules chrome by removing the large rule-summary/authority boxes and compacting the selected-rule header.
- Add a collapsible Rule Library. When collapsed, Context intelligence, Outline/symbols, and Rule flow move into a vertical companion pane to the left of the editor instead of remaining below it.
- Restore the Stigma-1 YAML authoring surface to a dark editor inside the otherwise light Carbon/OpenShift workbench.
- Presentation/local-authoring ergonomics only: no scanner, Evidence-v2, Definitions, finding severity, queue, Stigma-1 production activation, or Rift behavior changes.

## 2.15.0 — DeltaScope 4.11.3 / Omega application switcher

- Add an OpenShift-style nine-dot **Omega applications** switcher to the global header beside notifications.
- Add launch tiles for **Support & feedback** (GitHub Issues), the **dalagab/omega GitHub repository**, and **Add rule**.
- Add rule switches into the Security Researcher perspective, opens the Stigma-1 Rules workspace, and creates a new local rule draft; production promotion remains GitHub-reviewed and has no direct activation authority.
- Keep the application switcher mutually exclusive with the notification drawer and close it when clicking outside the panel.

## 2.15.0 — DeltaScope 4.11.2 / shell alignment

- Remove the unused 16px strip between the 48px global header and the application shell by aligning the fixed viewport grid to the actual 48px header height.
- Stack **OMEGA** over **DELTASCOPE** in the global product masthead while retaining the Omega mark to the left.
- No scanner, Evidence-v2, Definitions, queue, rule-authority or plugin-profile semantics changed.

## 2.15.0 — DeltaScope 4.11.1 / developer single-plugin workspace

- Plugin Developer perspective now uses only the plugin selected in the global **My plugin** selector.
- Removed the corpus-wide Plugins/research queue from all developer-scoped asset panels, including Security Review, Journey, Changes, Omega Profile, and Source & Build.
- Investigator and Security Researcher perspectives retain the corpus plugin list for discovery and cross-plugin work.
- Presentation/navigation-only change; no scanner, Evidence-v2, Definitions, Stigma-1 authority, queue, or Rift behavior changes.

## 2.15.0 — DeltaScope 4.11.0 / OpenShift-style shell navigation

- Moved the perspective switch out of the global header and into the first full-width row of the dark left navigation, matching the OpenShift Administrator/Developer perspective pattern.
- Added a top-left hamburger button that collapses/restores the left navigation; browser-local state remembers the operator preference.
- Kept the global header focused on Omega branding, the selected plugin/subject, global search and notifications.
- Removed the duplicated perspective heading/description from the navigation body; the perspective selector now defines the active workbench.
- Expanded the empty Plugin Developer overview into a useful dashboard-style starting page with developer tasks and indexing context instead of a mostly blank canvas.
- Presentation/read-only navigation only: no scanner, Definitions, queue, Evidence-v2 publication, Stigma-1 authority or Rift behavior changed.

# Omega Security Services changelog

## 2.15.0 — DeltaScope 4.10.0 / Carbon-inspired shell and notification center

- Rework DeltaScope toward an IBM Carbon-style visual shell: dark fixed navigation/header, white/light main investigation canvas, square low-shadow panels, Carbon-like blue focus/selection accents, and denser information hierarchy.
- Make the header navigation-only: Omega/DeltaScope identity, perspective selector, current plugin selector, global search, and notifications. Source mode, SigmaScope version, Evidence revision, latest analysis time, Definitions revision, refresh and audit controls move into Dashboard/Overview content.
- Add a top-bar **My plugin** selector. Plugin Developer uses it as the primary subject selector; selecting a plugin updates the persistent subject and developer overview without requiring a separate subject strip. The current corpus selector now supports up to 2,000 variants so the present catalog fits in the header chooser.
- Add a notification bell and read-state drawer for important read-only signals: new Evidence-v2 publication, Definitions revision changes, failed/gated production checks, source problems, and critical findings. The Dashboard mirrors the highest-priority active notifications in a **Needs attention** panel.
- Add a Dashboard **Security platform overview** panel containing the source, SigmaScope, Evidence, latest analysis, Definitions, and production-authority state that previously crowded the header. Plugin Developer Overview also exposes a smaller **Omega indexing context** panel for the exact scanner/evidence context behind the selected plugin review.
- Keep notification state browser-local only. Notifications do not mutate Evidence-v2, scanner state, Definitions, queues, findings, or GitHub.

## 2.15.0 — DeltaScope 4.9.0 / OpenShift-style perspectives and Plugin Developer workflow

- Replace the former presentation-only lens with four real workbench perspectives: **Plugin Developer**, **Investigator**, **Security Researcher**, and **Operations**. Each perspective has its own left navigation, landing page, primary actions and terminology while consuming the same read-only Security Evidence v2 state.
- Make **Plugin Developer** a first-class workflow for answering what Omega found, which observed capabilities are still unexplained, what source/build coverage is missing, and how a developer can improve the explanatory context shipped with the plugin.
- Add an **Omega Profile** builder for `.omega/plugin.yaml`. It starts from the retained developer profile when available, compares declarations with observed capabilities/destinations, and generates YAML through SigmaScope's existing `plugin_profile` validator. Output is browser copy/download only; developer declarations remain untrusted context and cannot suppress or downgrade scanner evidence.
- Turn Journey's **Explain this step** action into a stage-specific inline explanation for the selected plugin: purpose, plugin-specific result, why the recorded state is shown, outputs produced, next step, and narrow evidence pivots. Raw technical evidence remains optional instead of being the explanation itself.
- Add developer-oriented source/build guidance that distinguishes source attribution from source-to-artifact verification and gives actionable steps without claiming reproducibility that has not been established.
- Repair the Reports frontend path by implementing the missing `renderReports()` projection renderer, and surface `gated`/`fail` production-authority checks prominently on the Dashboard while retaining full System Health detail.
- Keep all new perspective/profile/Journey behavior outside production authority: no scanner behavior, Definitions, finding severity, queue state, Evidence-v2 publication, Stigma-1 production activation or Rift execution semantics are changed.

## 2.15.0 — DeltaScope 4.7.0 / per-plugin Asset Journey

- Add a **Journey** tab as the default selected-asset view in DeltaScope. It renders the plugin's recorded path vertically from catalog discovery through artifact acquisition, package/manifest inspection, source attribution, SigmaScope, secondary engines, normalized observations, Stigma-1/SRL projection, optional deep analysis, Evidence-v2 publication and the current DeltaScope view.
- Build the graph from a new deterministic read-only `omega.deltascope.asset-journey.v1` backend projection (`/api/workbench/journey`) rather than a fixed decorative pipeline. Stages are explicitly marked complete, partial, failed, skipped, not recorded, not requested, needs evidence, requested or current according to retained evidence.
- Keep absent source and optional Deep Scan stages visible without pretending they ran. Artifact-only plugins therefore show source attribution as skipped; variants with a frozen Stigma-1 analysis request show the approved profile/depth/reason as requested.
- Extend the existing hash-verified SRL projection-sidecar reader to expose the selected variant's `analysisRequest` from `analysis-requests.json` alongside reanalysis requests. This does not grant production finding write-back or arbitrary queue authority.
- Add regression coverage for deterministic Journey reconstruction, missing-source/deep-scan honesty, the read-only Journey HTTP endpoint, and retrieval of typed Stigma-1 analysis requests.

## 2.15.0 — DeltaScope 4.6.3 / root launcher

- Add root-level `deltascope.py`, `deltascope.cmd`, and `deltascope.sh` launchers so DeltaScope can be started from the SigmaScope checkout without remembering the internal tool path.
- The Python launcher creates a repository-local `.deltascope-venv`, installs only the pinned `tools/requirements-security.txt` dependencies on first use or when the requirements digest changes, then reuses that isolated runtime.
- Default root launch opens the published Evidence-v2 online workbench; normal DeltaScope commands and flags pass through unchanged.
- Add `.deltascope-venv/` to `.gitignore` and regression coverage for launcher discovery, default command routing, and requirement-change invalidation.
- No scanner, Stigma-1, Definitions, Evidence-v2, queue, Deep Scan, or publication semantics changed.

## 2.15.0 — DeltaScope 4.6.2 / sharded workbench relationship transport

- Replace the single `indexes/workbench-relationships.json` transport object with a small hash-pinned `indexes/workbench-relationships/index.json` manifest plus deterministic bounded JSONL+gzip datasets for endpoints, components and advisories.
- Keep the global Evidence-v2 32 MiB per-file ceiling unchanged. Relationship shards target 8 MiB compressed files, so growth in DeltaScope navigation data no longer requires weakening publication safety limits.
- Advance the relationship schema to `omega.security-evidence.workbench-relationships.v2`; DeltaScope remains backward-compatible with existing v1 monolithic snapshots.
- Intrinsic Evidence-v2 validation now verifies every relationship shard SHA-256/size, record count, semantic record digest, edge counts and aggregate relationship revision while preserving `readOnly=true`, `mutationAuthority=none`, `policyInput=false`.
- DeltaScope fetches the v2 manifest during relationship navigation and loads hash-pinned shards only when the relationship workbench is first used, rather than loading relationship data at application startup.
- This fixes SigmaScope run `32603107402`, whose candidate reached validation after all 20 selected scans but was rejected because the old monolithic relationship index reached 34,013,367 bytes, exceeding the 33,554,432-byte Evidence-v2 ceiling.

## 2.15.0 — DeltaScope 4.6.1 / Stigma-1 analysis-request sidecar validation fix

- Fix Evidence-v2 intrinsic validation for the new hash-pinned `rule-projections/analysis-requests.json` sidecar. The 4.6 materializer correctly indexed the file, but the snapshot validator still only recognized variant projections plus `reanalysis-requests.json`, so a valid deep-analysis request sidecar was incorrectly reported as an orphan.
- Extend `rule_reprojection.verify_projection_set()` to verify the Stigma-1 analysis-request sidecar SHA-256/size, schema, bounded `deep-scan-evidence-acquisition-only` queue scope, record count, and `productionFindingsWriteBack=false` boundary.
- Preserve compatibility with pre-Deep-Scan projection sets that legitimately have no `analysisRequests` descriptor.
- Add regression coverage for successful intrinsic snapshot validation and tamper detection of `analysis-requests.json`. No rule Definitions changed in this hotfix.

## 2.15.0 — DeltaScope 4.6 / adaptive Stigma-1 Deep Scan

- Add bounded `analysisRequest.depth: standard|extended|exhaustive`. Rules can say “look harder” but cannot set raw timeouts, commands, runner options or arbitrary resource values.
- The durable Deep Scan queue coalesces same artifact/baseline/profile requests and automatically keeps the **deepest requested depth** while retaining every requesting rule/reason.
- Split the Deep Scan Actions workflow into selection and execution jobs. The selection job reads the queue and supplies a code-owned dynamic workflow timeout (20/40/65 minutes) plus worker budget to the execution job.
- `artifact-differential-v1` now performs additional bounded member-content/literal inspection at extended/exhaustive depth while still never executing plugin code.
- Add `experimental.deep-scan.divergent-artifact-high-risk`: divergence plus execution/dynamic-code and network capability requests exhaustive differential analysis. The ordinary divergent-artifact example requests extended depth.
- Source Definition library is now **6 packs / 55 rules / 15 fixtures** (16 reviewed production-tier + 39 experimental).

## 2.15.0 — DeltaScope 4.5 / expanded Stigma-1 definitions

- Expand the source Definition library from **2 packs / 7 rules / 6 fixtures** to **6 packs / 54 rules / 14 fixtures** so DeltaScope has a meaningful rule corpus to browse, learn from, fork and replay.
- Promote the remaining literal-backed legacy static-pattern primitives into the reviewed core migration pack: **14 primitive rules + 2 compound rules = 16 reviewed production-tier definitions**. Production SRL finding writeback remains separately gated.
- Expand migration parity to **147 primitive cases + 32 compound combinations**, all using scanner-retained observations and preserving fail-closed old-vs-Stigma semantics.
- Add **38 experimental rules** in four packs: managed-call/game capabilities, network endpoint classifications, source-provenance facts, and higher-order research correlations. Experimental trust-tier rules freeze deterministically but are never production-active merely by being present.
- Add `experimental.deep-scan.divergent-artifact` as an authoring/reference example of the Stigma-1 `analysisRequest` outcome. It requests `artifact-differential-v1` against `stable-artifact-baseline` but remains experimental until cross-source divergence is exposed as a legal first-class Stigma input/fact.
- Keep the 4.4 durable Deep Scan queue/worker contract unchanged: reviewed frozen rules may request bounded Omega-owned analysis profiles; local My Rules only preview requests; arbitrary commands/runner controls remain impossible.

## 2.15.0 — DeltaScope 4.4 / Stigma-1 deep-analysis queue

- Added typed Stigma-1 `analysisRequest` outcomes with strict profile/reason/comparison schema; arbitrary commands, paths, timeouts, network policy and runner controls are rejected.
- Added durable `deep-scan-state` queue projection from matched exact frozen rules. Requests coalesce by exact candidate artifact + stable baseline + profile revision while retaining all requesting-rule provenance. Completed evidence is reused when another rule later asks for the same work.
- Added separate reusable/manual `Omega Deep Scan worker` workflow plus a thin default-branch hourly recovery caller. Normal SigmaScope publishes queue state and best-effort dispatches the worker without making deep analysis part of its bounded scan budget.
- Added `artifact-differential-v1`, a non-executing equal-profile comparison of candidate and stable baseline package inventory plus SigmaScope static behavior observations.
- Reserved `sandbox-differential-v1` as unavailable until a genuine isolated executor exists; the Actions worker never substitutes direct plugin execution.
- Added DeltaScope visual Emit-node controls and Explain/Test visibility for deep-analysis outcomes. Local rules remain preview-only and cannot mutate the production queue.
- Added rollout compatibility so a newly updated `sigmascope.yml` continues to work with an older frozen worker until the next Catalog/Definitions freeze.
- Added deep-scan documentation, workflow contract tests, stable-baseline fail-closed tests and cross-rule completed-result reuse tests.

## 2.15.0 — DeltaScope 4.3 findings, operations and documentation

- Put **Latest security findings** at the top of Incidents. The preview is derived only from current published findings, sorted by newest scan time and severity, and opens the existing read-only incident/case investigation when selected.
- Add a read-only **Components & Actions** dashboard panel plus **Operations / Actions** event stream backed by bounded GitHub Actions metadata for `dalagab/omega`. SigmaScope, Omega builds, Catalog / Definitions, DeltaScope, Stigma-1, security regression and source intake get explicit component rows, including running/healthy/failed/unknown state and direct links to GitHub runs. DeltaScope never starts, cancels or retries Actions.
- Add a local **Documentation** workspace. It exposes an allow-listed set of shipped documentation only, headed by the new `docs/STIGMA-1.md` quick start, rule-authoring guide, SRL language reference, examples/fixtures, Definition Pack contract and security architecture. Arbitrary filesystem paths are not accepted.
- Keep the DeltaScope 4.1 fixed-viewport contract: these new pages/panels scroll internally and do not restore browser/main-window scrolling.
- GitHub status is fail-soft and cached for 60 seconds. Public repositories work without credentials; an optional server-side `OMEGA_GITHUB_TOKEN`, `GITHUB_TOKEN` or `GH_TOKEN` only raises API limits and is never exposed to the browser.

## 2.15.0 — DeltaScope 4.2 Stigma-1 component identity

- Name the shared SRL Core component **Stigma-1**. `tools/security/srl.py` remains the stable implementation/import used by frozen and compatibility paths; new `tools/security/stigma1.py` is the canonical developer-facing facade and re-exports the exact same parser, validator, compiler, evaluator and visual-graph bridge. No second rule implementation is introduced.
- Expose Stigma-1 identity in the SRL engine/reference contract (`component=Stigma-1`, `technicalName=SRL Core`, `componentId=omega.stigma-1`) while preserving the existing SRL schemas and the `srlCore` API field as an explicit compatibility alias.
- Update DeltaScope Rules UI and documentation to present **Stigma-1 · SRL Core**, and bump DeltaScope to **4.2**.
- Repair the stale SigmaScope branding regression: DeltaScope is no longer globally read-only because My Rules are intentionally local/versioned; the test now verifies the precise boundary instead (developer-only, never scans/publishes, published state read-only, local SRL writes only).

## 2.15.0 — DeltaScope 4.1 fixed-viewport workspaces

- Remove document/main-interface vertical scrolling from every DeltaScope page. The browser document, application main area and active workspace are now fixed to the available viewport below the header.
- Keep Dashboard, Incidents, Events, Intelligence, Assets, Rules, Reports and System framing stationary; long content scrolls only inside the panel that owns it (tables, case/evidence panes, rule tree/editor/canvas, report rows, raw Evidence browser, SQL output).
- Make the Rules workspace consume the remaining viewport instead of extending the page: the System/My Rules tree and YAML/Visual/Explain-Test work area stay visible together, while the visual canvas and property editor use bounded internal scrolling.
- Convert Assets and raw Evidence browsing to true height-bounded split panes, preventing large plugin details or database rows from pushing the navigation/header off screen.
- This is a DeltaScope browser-layout change only. It changes no SigmaScope scanner/evidence/rule semantics, requires no Definitions update and requires no security rescan.

## 2.15.0 — DeltaScope 4.0 unified SRL Core workspace

- Extract the shared rule-language authoring boundary into **SRL Core** (`tools/security/srl.py`): SigmaScope and DeltaScope use the same parser, validator, compiler/evaluator model, and DeltaScope's visual authoring graph must round-trip through that core before YAML is accepted. The graph is never an executable production rule format.
- Replace the separate Definition-library inspector and Rule Lab surfaces with one Rules workspace. The left tree now shows **System Rules** from repository Definition Packs and versioned **My Rules** side by side; selecting either rule uses the same YAML / Visual / Explain-Test work area.
- Add a bounded local rule store at `~/.omega/deltascope/rules/v1` (override: `OMEGA_DELTASCOPE_RULE_HOME`). Local saves are atomic, immutable-revisioned and validated by SRL Core; generated internal paths are used instead of arbitrary filesystem paths.
- System Rules remain read-only and can be explicitly **Forked to My Rules**. Local/new rules can save revisions without any write path to `security-definitions/`, frozen Definitions, Evidence-v2, scanner queues or production activation.
- Add the first functional SRL visual composer: collection/fact selectors, ALL/ANY/NOT/COUNT logic, Emit nodes, drag positioning, explicit node connections and typed property editing. Existing YAML is rendered into the graph; graph edits compile back to canonical SRL YAML through SRL Core.
- Add `/api/workbench/rule-workspace`, local-rule load/save/fork/new endpoints, and YAML↔authoring-graph endpoints. Existing compile/evaluate/replay/fixture/export/GitHub-proposal boundaries remain unchanged.
- No repository Definition content or production rule-evaluation semantics change in this pass; a future Definitions freeze may naturally receive a new frozen worker transport hash because the shared SRL source file changed.

## 2.15.0 — terminal-history lifecycle validation repair

- Fix candidate Evidence-v2 publication when an inactive variant already has a retained terminal snapshot and a different current descriptor must replace it. The older terminal descriptor is now converted to an immutable `superseded` historical snapshot instead of being copied into `history/variants` while still labelled `retired`.
- This directly fixes validation failures such as `historicalSnapshots variant 507 lifecycle state is not superseded` and variant 965 from the bounded production SigmaScope-v2 worker.
- Preserve the current terminal descriptor as `retired`; only the displaced older descriptor becomes `superseded`, with `terminal=true`, `rescanEligible=false`, and a `supersededBy` identity pointing at the replacement.
- Add a regression that recreates the terminal-replacement path and asserts the terminal/history lifecycle split. No scanner, rule, artifact-analysis, source-analysis, Definitions, or queue identity changes are required.

## 2.15.0 — DeltaScope 3.9 Definition library tree

- Make the Rules workspace useful even when the selected Evidence-v2 snapshot publishes no frozen Definition provenance: DeltaScope now exposes the source-controlled `security-definitions/packs` tree separately from active production state.
- Add a left-hand Definition library tree with pack overview, individual SRL rules, rule source files and fixtures, plus search and expand/collapse controls. The current package exposes 2 repository packs, 7 reviewed SRL rules and 6 fixtures immediately.
- Selecting a repository rule opens a learning-oriented inspector showing retained collections/facts consumed, selector symbols, condition structure, emitted fact/finding, severity/confidence/category, normalized single-rule YAML, the exact containing source file and compiled semantics/revision.
- Add **Load a copy into Rule Lab** so an existing rule can become local scratch input without editing the repository, Definitions, Evidence-v2 or production activation state. Rule Lab is collapsed by default and opens when a source example is copied into it.
- Keep exact frozen active-rule provenance in a distinct collapsed snapshot section. The UI explicitly explains why repository source can contain rules while a historical/current Evidence snapshot legitimately reports `0 active rules`.
- Add `omega.deltascope.definition-library.v1` and `/api/workbench/rule-library`; the payload is `readOnly=true`, `mutationAuthority=none`, `policyInput=false`, `sourceAuthority=repository-source-only`. The full Definition Pack set is compiled/validated before it is presented.

## 2.15.0 — optional ClamAV freeze isolation

- Make the daily catalog ClamAV refresh genuinely optional: package-install, FreshClam, asset-build, release-create and release-upload failures no longer block the Definitions/catalog publication path.
- Build new ClamAV transport metadata into a pending manifest and promote it only after the content-addressed release ZIP uploads successfully, preventing a frozen Definitions snapshot from referencing an unpublished asset.
- On refresh/publication failure, retain only a previously frozen ClamAV transport that passes the intrinsic asset-manifest validator; if none exists, freeze the revision without ClamAV instead of publishing a dangling descriptor.
- Separate mandatory YARA compilation support from optional ClamAV installation in the fresh `publish` runner. The Definitions freezer now gets an explicit real-YARA install instead of inheriting it incidentally from the ClamAV step.
- Add regression coverage for valid previous-asset retention, clean no-previous fallback, invalid-transport rejection, atomic pending-manifest promotion, and nonblocking optional workflow behavior. Scanner/artifact/source identities are unchanged.

## 2.15.0 — operational Discord notice panels

- Make Discord embeds data-first instead of decorative: catalog notices now report active catalog size/source count plus exact added/updated/removed plugin counts and at most two deterministic pseudo-random representative plugin names.
- Definitions notices now report frozen pack/rule counts, capability/category counts, OSV package coverage, source-observation health, and representative changed Definition Pack names.
- Evidence notices now report current finding totals/severity mix plus added/cleared deltas and representative finding names. Security notices report the new high/critical count, current finding state and representative findings.
- Resolve reviewed SRL finding IDs through the exact frozen Definitions pack index and link incidents directly to the source rule YAML pinned to the Definitions `builtFromDevCommit`, including an exact line anchor when available. Legacy findings without reviewed SRL YAML are labelled explicitly instead of receiving a misleading link.
- Preserve deterministic TONI voice selection, mention sanitisation, webhook isolation and presentation-only authority.

## 2.15.0 — dynamic TONI Discord voice

- Replace the small fixed Discord voice pools with a deterministic compositional grammar: six openings × six observations × six closers = **216 natural voice combinations per notice family**, or **864 base TONI voices** across security, catalog, Definitions and evidence.
- Keep wording stable for the same event identity while allowing different revisions/plugins to naturally select different combinations; no random source, AI, network call or generated runtime copy is involved.
- Add deterministic title variants plus event-aware detail wording: catalog notices react differently to new plugins, updated plugins or metadata-only revisions; security notices state the number of newly introduced high/critical findings; evidence/Definitions notices vary their headings without changing semantics.
- Preserve mention sanitisation, bounded Discord fields, webhook isolation and `allowed_mentions={parse: []}`. Notification personality remains presentation-only and has no scanner/rule/evidence authority.

## 2.15.0 — catalog Definitions freezer dependency fix

- Install the pinned security Python requirements inside the **catalog-builder `publish` job**, which is a fresh GitHub runner and therefore cannot inherit PyYAML installed by `preflight` or SigmaScope worker jobs.
- Add an explicit pre-freeze PyYAML import/version smoke check so dependency setup fails at the correct boundary instead of later inside `definitions_snapshot.py`.
- Add a workflow regression contract requiring the publish-job dependency install and smoke check to occur before `Freeze daily Definitions and OSV data`.
- Scanner, Evidence-v2, observation, SRL and analysis identities are unchanged; this is publication orchestration only and does not require a rescan.

## 2.15.0 — DeltaScope 3.8 smart SRL editor

- Replaced Rule Lab's plain candidate textarea with a self-contained syntax-highlighted SRL editor shell with line numbers, status line, live diagnostics and keyboard-first editing.
- Added `/api/rule-lab/intelligence`, backed by the same safe SRL parser/compiler and frozen typed collection registry. It recognizes rules, selectors, facts, findings, retained collections, typed fields and legal operators even while YAML is partially incomplete.
- Added context-sensitive completion, caret help, symbol outline/go-to-line navigation and a live collection→selector→fact/finding rule-flow projection. No editor intelligence becomes an SRL input or gains write authority.
- Added typo suggestions for near-miss SRL operators/fields/collections plus one-click local replacement, canonical safe YAML formatting via `/api/rule-lab/format`, Ctrl/Cmd+Space completion, Ctrl/Cmd+Enter validation, Shift+Alt+F formatting and optional browser prose spellcheck.
- Production SRL evaluation/write-back remains disabled and `/api/rule-lab/promote` remains absent.

## 2.15.0 — SRL cutover-readiness gate

- Added `tools/security/srl_cutover_readiness.py`, a read-only full-corpus audit over the exact frozen Daily Definitions and published Security Evidence v2 snapshot.
- Cutover readiness now requires intrinsic Definitions/Evidence integrity, exact frozen SRL identity, complete current-variant coverage, zero retained-evidence audit errors, zero hard-coded-vs-SRL mismatches, zero targeted observation re-analysis requirements, complete rule-only reprojection, and replay/reprojection classification agreement.
- A clean audit means only `ready-for-human-review`; the report permanently declares `manualApprovalRequired=true`, `activationAuthorized=false`, `hardCodedBaselineRemovalAuthorized=false`, `productionWriteBack=false`, and `queueMutationAuthorized=false`.
- Added exact re-analysis reason summaries and requests so an incompatible 2.14/early-2.15 corpus can be repaired selectively instead of being mistaken for a negative result or forcing a blind mass rescan.
- Added a read-only GitHub workflow that checks out `sigmascope`, `catalog-data`, and `security-evidence-v2`, writes only an Actions artifact, and can optionally fail unless the complete corpus is mechanically ready. The default-branch caller reference is `docs/workflow-callers/srl-cutover-readiness-main.yml`.
- Added regression coverage for compatible, zero-hit, missing-observation, baseline-mismatch, filtered/limited diagnostic, CLI fail-closed, and workflow authority cases. Production SRL evaluation remains disabled.

## 2.15.0 — Phase 11 slice 8 · DeltaScope 3.7 GitHub proposal handoff

- Complete Phase 11 with a Rule Lab **Propose on GitHub** action that only constructs/opens a normal GitHub Issue Form URL; DeltaScope never submits an issue or performs a GitHub API write.
- Canonically map the Phase-9 Issue Form element IDs into query-string prefills for pack identity, candidate SRL YAML, positive/negative fixtures, rationale, false-positive expectations, provenance and license.
- Reuse the authorization-independent candidate validator before URL generation so both fixture polarities must already satisfy the Phase-9 semantic contract; GitHub still re-fetches/revalidates from scratch and remains authoritative for pack collisions and promotion.
- Add a conservative 7,500-byte complete-prefill limit with deterministic metadata/identity/template fallbacks and explicit copy actions for omitted YAML; never silently truncate candidate data.
- Extend Rule Lab export to produce deterministic GitHub-ready bundles containing both `positive-fixture.yaml` and `negative-fixture.yaml`.
- Add an exact default-branch Issue Form reference under `docs/workflow-callers/` and regression-check its IDs against the URL-prefill contract.
- Keep `/api/rule-lab/promote` absent and preserve `productionRuleEvaluationEnabled=false`, `productionWriteBack=false`, and the GitHub permission/CI/review/normal-PR mutation boundary.

## 2.15.0 — Phase 11 slices 6–7 · DeltaScope 3.6 Rules provenance + Reports/System

- Publish `indexes/definition-provenance.json` from the exact verified frozen Daily Definitions snapshot so DeltaScope never infers active rules from development-tree YAML.
- Record exact Definition/pack/SRL revisions, pack/rule review and provenance metadata, source hashes, fixtures and migration-parity status in `omega.security-evidence.definition-provenance.v1`; intrinsically enforce `readOnly=true`, `mutationAuthority=none`, `policyInput=false`.
- Make provenance-only semantic revision changes publication-worthy so active-rule lineage cannot remain stale when artifact/security semantics are otherwise unchanged; timestamp-only Daily snapshot churn does not move the provenance revision.
- Add deterministic read-only Active Rules, Reports and System projections/APIs. Rules shows authoritative frozen lineage; Reports summarizes coverage, SRL reprojection/reanalysis and queue state; System shows Evidence/Definitions/scanner/SRL revisions plus explicit production/write-back/queue-authority gates.
- Keep Rule Lab scratch-only and preserve the GitHub permission/CI/review/normal-PR boundary; `/api/rule-lab/promote` remains absent.
- Add deterministic/tamper/fail-closed/HTTP coverage and complete regression accounting at 438 tests across 47 modules.

## 2.15.0 — Phase 11 slices 4–5 · DeltaScope 3.5 Intelligence + Asset relationships

- Add a bounded, deterministic Evidence-v2 `indexes/workbench-relationships.json` navigation index derived from published endpoint, dependency/component and advisory state. It is hash/size/schema verified and explicitly `readOnly=true`, `mutationAuthority=none`, `policyInput=false`.
- Add cross-plugin Intelligence catalog/pivots for observed endpoints, shared components and advisory matches without requiring the browser to crawl every deep variant dataset.
- Add deterministic Asset relationship graphs covering plugin→variant→artifact/source→component/endpoint/advisory navigation, with pivots back into ecosystem Intelligence.
- Keep the relationship layer outside the SigmaScope observation/SRL boundary: it cannot create findings, change severity, queue work, activate rules or become a production policy input.
- Preserve older Evidence-v2 compatibility: snapshots without the relationship index remain readable and show the ecosystem relationship surface as unavailable.
- Add relationship-index determinism, intrinsic read-only-boundary, backend projection, HTTP/UI and DeltaScope contract regressions.

## 2.15 Phase 9 — authorization-gated GitHub rule candidates

## 2.15.0 — Phase 10 reprojection + Phase 11 DeltaScope workbench shell

- Add deterministic SRL rule-only reprojection from retained legal observations, independent of legacy finding payloads.
- Add targeted queue reasons for variants missing exact required observation collections while keeping `srlRuleSetRevision` separate from the hard-coded scanner `ruleSetRevision`.
- Publish an optional non-authoritative Evidence-v2 `rule-projections/` sidecar and intrinsically validate hashes, sizes, schemas, revisions, non-production flags and orphan cleanup.
- Add DeltaScope `rule-reproject` inspection/export support.
- Advance DeltaScope to 3.3 with the first read-only security-information workbench shell: Dashboard, Incidents, Events, Intelligence, Assets, Rules, Reports and System.
- Add deterministic backend workbench projections (`omega.deltascope.security-workbench.v1`) for incident/event/intelligence navigation, stable IDs/revision, and explicit no-mutation authority; the browser now consumes `/api/workbench` rather than deriving those objects ad hoc.
- Keep Rule Lab scratch-only and GitHub as the sole authoritative mutation/promotion boundary; no direct incident/rule/evidence/queue/Definitions write path is added.


- Add `tools/security/rule_candidate.py` as a network-free candidate-data boundary: bounded issue-section parsing, hardened SRL compilation, positive/negative fixture validation, candidate-wide positive coverage, cross-pack rule/fact collision checks, and transactional reviewed Definition Pack materialization.
- Treat candidate YAML/fixtures as inert data. YAML anchors/aliases/tags, path-like pack IDs, existing-pack overwrite, disabled/deprecated promotion status, failing fixtures, and duplicate identities fail closed. Candidate/issue author identity and self-declared status/reviewer text never grant authority.
- Add the `SigmaScope rule candidate` issue form requiring pack identity, candidate YAML, positive/negative fixtures, rationale, false-positive expectations, external provenance and license.
- Add reusable `.github/workflows/rule-candidates.yml`: validation has no contents-write permission; promotion checks the triggering GitHub actor's repository collaborator permission before checkout/re-fetch, then revalidates from scratch and opens a normal PR without auto-merge or `pull_request_target`.
- Add `docs/workflow-callers/rule-candidates-main.yml` as the exact thin default-branch event caller for the companion `main` overlay. The `/promote-sigmascope-rule` command only routes the event; the reusable workflow performs the decisive permission check.
- Keep DeltaScope Rule Lab read-only and production SRL evaluation disabled. A merged reviewed pack still requires normal CI/review and the later Daily Definitions freeze.
- Add 23 Phase-9 candidate/workflow contract tests; complete regression accounting is 394/394 tests across 43/43 modules, plus all five product self-tests.

# Omega security services changelog

## 2.15.0 — Migration checkpoint: capability vocabulary, developer profiles, behavior consistency, observation replay

### Phase 8 DeltaScope Rule Lab

- Add `tools/security/rule_lab.py` as the local/experimental authoring backend over the exact production SRL compiler/evaluator.
- Add visual Rule Lab to DeltaScope 3.2 with YAML import/editing, structured compile diagnostics, selected Evidence-v2 plugin dry-run, selector/evidence explorer, candidate-scoped baseline diff, bounded set/corpus replay, fixture creation/edit/test, and deterministic candidate ZIP export.
- Preserve replay integrity: missing required observations are `rescanRequired`/not evaluated rather than inferred negative, and baseline findings remain comparison-only inputs.
- Scope baseline comparison to candidate-owned finding IDs so observation-only candidates never appear to remove unrelated production findings.
- Export deterministic fixed-metadata ZIP bundles with exact SHA-256 manifest, candidate descriptor, optional passing fixture, `productionWriteBack=false`, and no promotion authority.
- Add no production mutation surface: Rule Lab has no promote/publish/Definitions/Evidence write endpoint. Production SRL evaluation remains disabled.

### Phase 7b retained static-observation replay

- Retain rule-neutral `dependencyIntelligence.staticPatternMatches` rows for legacy static literal matches; rows contain origin/pattern/evidence location only and never a legacy rule ID, severity, capability or finding conclusion.
- Add `staticPatternMatchContractVersion=1` so a new zero-hit scan can prove an explicitly empty complete observation set, while historical reports without the marker remain distinguishable as missing.
- Add reviewed `omega-core-static-primitives` Definition Pack producing `network.http`, `network.socket`, `process.launch`, `shell.powershell`, and `credential.api` facts from retained observations.
- Extend migration parity to **59 primitive literal cases + 32 compound combinations**, using scanner-produced observations rather than parity-only injected facts.
- Add retained Evidence-v2 SRL replay (`srl_evidence_replay.py`) and DeltaScope `rule-replay`; old findings are comparison baseline only and never recursive evaluator inputs.
- Treat historical 2.14 variants without the new complete observation as `rescanRequired` for targeted re-analysis; never fabricate negative evidence or facts from an absent dataset.
- Advance narrow artifact/source analysis identities because observation-retention semantics changed. The legacy hard-coded scanner/queue `ruleSetRevision` remains a separate identity (not repurposed as the SRL ruleset), but it also advances because `sigmascope.py` itself changed.
- Keep production SRL evaluation disabled and retain the hard-coded primitive/compound implementation until a real compatible 2.15 corpus has replayed cleanly and cutover is reviewed.


- Bump Omega Security Services / SigmaScope engine to **2.15.0** for the first implemented behavior-transparency architecture phases.
- Add source-controlled `omega.sigmascope.capability-registry.v1` with stable canonical capability IDs, categories, labels, descriptions, migration aliases, attributes and deprecation/replacement metadata.
- Freeze the capability registry as a first-class Definitions payload with exact SHA-256/revision/count metadata while also carrying it inside the immutable worker bundle.
- Project existing SigmaScope capability/permission/automation outputs onto canonical `capabilityIds` without changing the underlying finding/severity model.
- Add bounded optional `.omega/plugin.yaml` (`omega.plugin-profile.v1`) ingestion from attributable public source, preferring a plugin-project-local profile in monorepositories and then repository root.
- Preserve exact profile path/SHA-256/byte count/validation status and capability-registry revision in `omega.plugin-profile-observation.v1`.
- Allow developers to explain expected or explicitly-not-expected capabilities, reasons, expected destinations, services, native components, IPC integrations, profile links/text and media references. These remain untrusted developer claims/context only.
- Reject developer attempts to declare safety/trust/verdict/severity/suppression/allowlisting, YARA/ClamAV overrides, review coverage, attribution confidence, artifact hashes, or source-to-artifact verification. Invalid `.omega` enrichment is fail-soft and never removes a plugin or suppresses independent evidence.
- Harden YAML parsing: 64 KiB maximum, UTF-8, bounded depth/nodes/tokens/lists, SafeLoader, and no aliases/anchors/explicit tags/merge keys/duplicate mapping keys/includes/templates/environment expansion.
- Carry normalized developer-profile data through source analysis, compact Evidence-v2, marketplace projection and DeltaScope with explicit developer-provided labelling.
- Advance the narrow **source** analysis revision for the new source input while preserving the existing narrow artifact code-analysis revision (`artifact-analysis-v1-bfac8f5fece4c94e`). Release-version identity is no longer treated as an analysis semantic for legacy ledger/due decisions.
- Add DeltaScope `capabilities` and `rule-schema` commands. `rule-schema` emits `omega.deltascope.rule-author-reference.v1` over the real current SigmaScope collections/fields and explicitly reports that production SRL evaluation is not yet enabled.
- Add comprehensive in-branch documentation for plugin developers and future rule authors under `docs/plugin-developers/` and `docs/rule-authors/`, plus the architecture/security/rule-language/Rule-Lab documents.
- Preserve YARA/ClamAV/OSV as separate specialist security-hygiene systems. Future SRL remains a bounded typed behavior/capability/correlation language and does not replace them.
- Add `omega.sigmascope.behavior-consistency.v1`, a deterministic derived projection comparing canonical observed capabilities and concrete network destinations with developer declarations without changing native findings/severity.
- Distinguish `observed-no-profile` from `observed-undeclared`; absence of `.omega` is not treated as a developer omission.
- Prevent developer metadata from proving itself: `.omega/plugin.yaml` is no longer fed through normal source-text security scanning, and historical endpoint rows originating from that file are filtered from destination comparison.
- Carry bounded behavior-consistency detail through Evidence-v2, marketplace security projection and DeltaScope. DeltaScope labels developer text explicitly and may use mismatches only as developer-research priority hints.
- Keep `behaviorConsistency` presentation-only for future SRL authoring: production rules must consume independent observations plus `developerProfile` directly to avoid conclusion-on-conclusion recursion.
- Implement Phase 4 observation/projection separation with `omega.sigmascope.observation-contract.v1`, `omega.sigmascope.observation-collection.v1`, `omega.sigmascope.projection-contract.v1` and `omega.sigmascope.projection-replay-audit.v1`.
- Register 18 stable logical input collections and classify legacy `findings`, permission and automation datasets as projection-only/non-SRL while keeping their physical Evidence-v2 transport backward compatible during migration.
- Promote already-produced report-only native imports, full endpoint rows, source files, binary classifications, developer profile/provenance, artifact/manifest identity and secondary-security results into first-class immutable observation datasets for new 2.15 analysis exports without reopening plugin bytes.
- Add historical 2.14 compatibility adaptation: active variants can receive observation/projection descriptors from retained immutable datasets plus compact report during candidate synchronization without artifact/source re-analysis. Historical bounded endpoint transport is explicitly marked insufficient for exact full-collection replay.
- Add deterministic replay auditing so future rules declare required logical collections; compatible retained evidence reprojects without rescan, while missing/bounded collections produce a targeted re-analysis reason and derived recursive inputs are rejected.
- Add DeltaScope `observation-schema` and document the Phase-4 input/completeness contract for rule authors. The existing Definitions `sourceObservationRevision` remains a separate source-ref identity and is not repurposed.
- Implement Phase 6 Definition Pack v1 compiler/freezer in `tools/security/definition_packs.py` with `core`, `reviewed`, `experimental`, and `local` trust tiers, bounded manifest/file loading, compatibility checks, per-pack/per-rule provenance/license/reviewer metadata, duplicate rule/fact prevention, exact content hashes, and mandatory fixture execution for production-tier packs.
- Freeze Definition Pack inventory plus the exact compiled active SRL ruleset into Daily Definitions under `srl/`; parent Definitions now carry a separate `srlDefinitionPacks` descriptor with deterministic `definitionPackRevision` and SRL `ruleSetRevision`.
- Preserve the existing top-level scanner `ruleSetRevision` as the current hard-coded analysis/queue identity during migration. SRL pack-only changes alter Definitions/SRL identities but do not silently trigger artifact rescans.
- Add a verified frozen-ruleset loader that never reads source pack YAML at worker runtime, plus DeltaScope `definition-packs --definitions-root ...` provenance inspection. Production SRL projection remains disabled through the Phase-7 migration until a compatible 2.15 retained corpus replays cleanly and cutover is explicitly reviewed.
- Start Phase 7 with the first reviewed production-tier SRL pack, `omega-core-compound`, preserving the existing `compound.network-execute` and `compound.credential-network` finding IDs and user-visible payload semantics.
- Add `omega.sigmascope.srl-migration-parity.v1`: compare the reviewed SRL correlations directly against the current hard-coded `finding_payload` implementation over all 32 combinations of the five primitive rule inputs.
- Add DeltaScope `rule-parity` for deterministic migration auditing. Primitive hard-coded rule IDs are converted to typed initial facts only inside this parity harness; current finding/permission/automation projections remain forbidden SRL observations.
- Make Daily Definitions fail closed when the migrated compound rules are partial or drift from the hard-coded baseline; freeze/hash-verify `srl/migration-parity.json` alongside the compiled SRL ruleset.
- Keep `productionRuleEvaluationEnabled=false` and retain the hard-coded primitive/compound logic until a compatible 2.15 retained corpus has replayed cleanly and cutover is explicitly reviewed.
- At this migration checkpoint, preserve the then-live 2.14 data collection unchanged while the 2.15 retained-corpus cutover and remaining architecture phases were completed.

## 2.14.1 — Plugin-scoped source follow-up reconciliation

- Consolidate public-source follow-up tracking to one managed GitHub issue per Dalamud `InternalName` instead of one issue per catalog mirror/feed.
- On each reconciliation pass, keep the oldest unresolved managed issue as canonical, refresh it with all currently affected mirrors and feed-scoped override keys, and close duplicate legacy mirror issues as consolidated.
- When current SigmaScope evidence successfully inspects public source for a plugin, close all managed source-discovery issues for that `InternalName`, even if some mirror variants still have no source attribution of their own. Closing source discovery never claims artifact-to-source equivalence; that evidence remains per variant.
- A validated repository reply on the consolidated issue now persists the source override to every affected feed-scoped mapping listed on the issue instead of fixing only one mirror.
- Advance the source-followup projection document to `omega.source-scan-followups.v3` with plugin-level counts/resolution names while retaining feed-specific rows for auditability.
- This is worker/human-follow-up orchestration only. SigmaScope detection engine remains **2.14.0** and narrow artifact/source analysis revisions must remain unchanged. A Daily Catalog/Definitions freeze is required before production workers use the new reconciliation code.

## 2026-08-21 - DeltaScope metric wiring hotfix

- Restored the `wireMetricCards` browser helper used by both focused and expanded metric-card groups.
- Added a regression asserting that the helper is defined before `init()` and wired to both card containers.
- No SigmaScope scanner, queue, Definitions, artifact-analysis, or source-analysis semantics changed.


## 2.14.0 — Coverage-first queue + DeltaScope focus/source/cache hotfix

- Change SigmaScope queue selection to **coverage-first-v1**: untouched artifact work for never-scanned active variants first, then retries for still-uncovered artifacts, then already-covered rescans/source-followups/advisory work. Existing typed reason priorities still order work inside each lane.
- Publish queue summary coverage counters (`unscannedVariantsPending`, `unscannedRetryVariants`, `coveredWorkPending`) so operators can see breadth progress explicitly.
- Keep artifact/source analysis revisions unchanged; this is queue scheduling semantics, not scanner evidence semantics. A fresh Catalog freeze is required to distribute the queue policy.
- Replace DeltaScope's mirrored Evidence-v2 HTTP cache paths with short deterministic revision/path hashes, preventing Windows Store Python cache prefixes from triggering `WinError 206` on deep immutable analysis paths while preserving strict remote SHA-256 verification.
- Simplify DeltaScope's top area to four research-focused cards: results available, never scanned, needs review, and queue retry. Full counters remain exact-click drill-downs under a collapsed **Metrics & coverage** drawer.
- Make evidence coverage explicit everywhere: research-queue rows now say **SOURCE CODE** or **ARTIFACT ONLY**, and selected cases show ARTIFACT / SOURCE CODE / SOURCE↔ARTIFACT status before the research tabs, including attribution confidence and source→binary verification state.
- Keep TONI deterministic/read-only and focused on coverage, queue progress, source availability, malware-engine state, and strongest review signals.

## 2.14.0 — DeltaScope security researcher workbench + snapshot coherency

- Reframe DeltaScope around a security-research workflow rather than a database browser: **Triage → Malware → Findings → Network → Code & native → Supply chain → Immutable evidence**.
- Demote generic Evidence-v2/SQLite table traversal to an **Advanced** escape hatch while preserving exact metric drill-downs and relationship navigation.
- Add deterministic researcher signals for incomplete scans/secondary engines, ClamAV/YARA matches, high/critical static findings, network+execution compounds, low source-attribution confidence, unverified source→binary correspondence, undetermined network destinations, and intelligence truncation. These signals guide review only; they do not change SigmaScope severity or publication.
- Add managed-call search plus direct access to permission, automation, import/PInvoke and reachability evidence from the Code & native tab.
- Expand endpoint presentation to show URL, host, classification, purpose, origin, confidence and concrete-destination status.
- Fix `/api/plugin` / `/api/snapshot` failures when the moving `security-evidence-v2` branch publishes between loading the root index and opening a variant. DeltaScope keeps SHA verification fail-closed, refreshes the atomic root/index snapshot after a SHA/404 race, then retries once.
- Optional immutable manifest/dataset-catalog loading now fails soft in the compact research case so a transient shard race cannot hide the already-integrity-checked current scan report.
- Server-side 500s now print a traceback with the failing DeltaScope request for researcher diagnostics.
- DeltaScope remains developer-only/read-only and outside `artifactAnalysisRevision`, `sourceAnalysisRevision`, scanner scoring, queue decisions and publication.

## DeltaScope TONI + metric drill-down UX hotfix

- Replace the Omega glyph in DeltaScope with a compact **O mark with a red center dot**; no image/font asset or network dependency is required.
- Add **TONI** as a deterministic, read-only evidence guide. TONI only narrates already-loaded DeltaScope evidence and never scans, scores, changes, or publishes security conclusions.
- Make every headline metric a drill-down. `Immutable analyses` now opens one row per immutable analysis with exact artifact/analysis/manifest identity; aggregate finding cards open contribution rows showing how their totals are summed; queue-state cards open the exact queue items for that state.
- Add direct immutable-analysis manifest browsing from the row inspector.
- Refresh the browser styling with a self-contained Tailwind-inspired slate/card layout while preserving offline/local operation and avoiding a Tailwind CDN dependency.

## 2.14.0 — Reviewed Omega Core YARA and bounded archive-member scanning

- Bump Omega Security Services / SigmaScope engine to **2.14.0** because artifact-analysis and secondary-evidence semantics change materially.
- Enable the first production Omega Core YARA set: 14 first-party compound rules across credential/exfiltration, execution/injection/security-tamper, persistence, and contextual anomaly classes.
- Keep broad primitives such as HTTP, P/Invoke, Discord URLs, filesystem access, `Process.Start`, PowerShell strings, obfuscation or entropy insufficient by themselves; YARA remains supplemental evidence only.
- Scan YARA against the exact downloaded artifact container plus a bounded generated view of ZIP members instead of only the outer archive.
- Bound YARA member materialization to 256 members, 16 MiB per member and 64 MiB total; reject unsafe/encrypted/suspicious-ratio members and skip large media/font resources.
- Attribute YARA matches back to the original archive member path, member SHA-256 and byte count without ever using the untrusted path for extraction.
- Add `omega.sigmascope.yara-scan-scope.v1` and advance new artifact scans to secondary-security Evidence contract **v3**.
- Fix source-only artifact replay so materialized Evidence-v2 workers preserve the exact artifact-bound secondary-security payload/contract instead of emitting a stale half-contract.
- Preserve historical contract-v2 secondary evidence during source-only reuse; old artifact evidence cannot be falsely upgraded to v3.
- Advance YARA policy/metadata to v2 with exact `reviewedRuleSha256`, reviewer, rule class and confidence; require metadata rule names to exactly match declarations and reject cross-file duplicate rule identifiers.
- Compile-check every enabled YARA file at the Definitions boundary and retain frozen executable identity verification in continuous workers.
- Make regression CI trigger on `security-definitions/**` and install real YARA before tests so rule-only changes are compile-checked.
- Hotfix the daily Catalog preflight and manual compaction workflows to install real YARA before their full repository regression suites; enabled Definitions fixtures intentionally compile-check production rules and therefore require the compiler at test time.
- Add an upstream review queue for YARA Forge/signature-base/embee-style rules without importing any third-party pack wholesale; future accepted rules require exact upstream provenance/license and independent local review.
- Preserve immutable ClamAV transport, artifact/source attribution, lifecycle/requeue, native PE, endpoint and component-summary contracts.
- Replace the continuous worker's hard one-item queue clamp with bounded multi-item processing: up to 20 queue work items per runner while preserving per-item work type, provenance, retry/backoff, source-followup and last-known-good failure retention.
- Reserve the last 300 seconds of the existing 3,300-second batch budget for advisory refresh, Evidence-v2 validation/audit and atomic publication so long scans do not consume the publication window.
- Expose batch diagnostics (`selectedCount`, selected items, budget stop state, invocation count, and aggregate per-plugin elapsed seconds) without persisting runtime timings into semantic Evidence-v2 or changing artifact/source analysis identities.
- Fix source-projection persistence exposed by the first 20-item batch: immutable normalized finding rows are now rebuilt from the final combined source+artifact finding set instead of artifact rows plus only direct source findings. This preserves newly derived endpoint/automation findings and keeps immutable scan counters reproducible.
- Keep the independent developer audit fail-closed; the failed 20-item batch published nothing after it detected five mirrored ActionTimelineReborn source projections with 21/10 recorded caution/informational counts but only 19/9 normalized rows.
- Modernize DeltaScope as a first-class read-only browser for current Evidence-v2: lifecycle/history snapshots, artifact groups/analysis manifests, queue/revision state, source attribution/provenance, endpoint/component/native summaries, ClamAV/YARA evidence and dynamic immutable forensic datasets are now directly browsable.
- Keep DeltaScope online access lazy and backward compatible: compact plugin indexes load first, large forensic shards are fetched only on demand, pre-summary Evidence-v2 remains readable, and the legacy SQLite developer mode is preserved. DeltaScope gains no scanner, publication or write-back capability.

## 2.13.0 — Native structural evidence, endpoint intelligence and component summaries

- Compatibility hotfix: validate pre-lifecycle Evidence-v2 plugin summaries using their historical lifecycle-contract-0 field set instead of recomputing them with lifecycle-contract-v1 fields. This repairs incremental startup against existing published snapshots without rewriting or deleting evidence.
- Keep lifecycle-aware production snapshots on contract v1; terminal/superseded validation remains fail-closed and unchanged.
- This is publication/validation compatibility only and does not change SigmaScope artifact/source scanning semantics or require an engine-version bump.
- Bump Omega Security Services / SigmaScope engine to **2.13.0** because artifact-analysis and Evidence-v2 transport semantics change materially.
- Advance the binary-classification contract to **v2**. PE classification now records bounded loader/security characteristics, COFF timestamp, entry-point/image metadata, section permissions/entropy and certificate-table presence without claiming Authenticode verification.
- Add bounded caution evidence for native PE sections marked both writable and executable; high entropy remains contextual metadata only and does not become a malware verdict.
- Expand static endpoint evidence to `omega.sigmascope.endpoint-evidence.v2` with explicit origin type, evidence confidence and concrete-destination semantics.
- Retain low-confidence URL strings from compiled binaries while filtering certificate/revocation infrastructure, source references and navigation/community literals out of concrete-destination findings.
- Preserve secret safety by stripping URL credentials/query/fragment and redacting Discord webhook/secret-like path components before evidence persistence.
- Add `omega.sigmascope.endpoint-summary.v1` with bounded host/classification/origin counts and explicit network-capability-with-undetermined-destination state.
- Add `omega.sigmascope.component-summary.v1` over the existing authoritative dependency graph, keeping NuGet/plugin/IPC/managed/native families separate.
- Correlate managed/native imports with bundled native libraries and Windows platform libraries; retain unresolved/runtime-resolved native dependencies explicitly.
- Mark direct compiled IL calls to P/Invoke targets in native component relationships as very-high-confidence static call evidence without claiming runtime execution.
- Carry bounded endpoint/component summaries through Evidence-v2 transport while retaining detailed normalized dependency/call datasets as the authoritative evidence.
- Bind component-summary and endpoint/native semantics into narrow artifact/source analysis revisions so stale analysis cannot be silently reused.
- Preserve 2.12 terminal lifecycle/typed requeue, 2.11 immutable ClamAV/reviewed-YARA and 2.10 artifact/source-attribution contracts unchanged.

## 2.12.0 — Variant lifecycle, event-driven requeueing and native binary classification

- Bump Omega Security Services / SigmaScope engine to **2.12.0** because Evidence-v2 lifecycle and artifact-analysis semantics change materially.
- Preserve inactive catalog variants as explicit `retired` terminal snapshots instead of deleting their descriptors and garbage-collecting their last immutable artifact analysis.
- Keep terminal variants out of `currentVariants` and out of scan-queue candidates, so historical evidence does not become normal client or worker state.
- Preserve the previous artifact descriptor as a `superseded` historical snapshot when an active variant ID moves to different artifact bytes. Source-only refreshes do not create fake artifact history.
- Add lifecycle contract v1 to Evidence-v2 indexes and fail-closed validation for active, retired and superseded descriptors, including immutable analysis hash/digest validation.
- Replace coarse artifact/source change labels with typed event reasons that declare their allowed work type and invalidated evidence layers.
- Distinguish artifact URL changes, artifact version changes, artifact-analysis semantic changes, advisory changes, source-candidate changes, source observations, source-analysis changes and retry work.
- Preserve the invariant that advisory-only work cannot cause artifact/source scans and source-only events cannot cause binary rescans.
- Add a bounded non-executing PE/ELF/Mach-O classifier. PE records architecture, bitness, role, managed/native status, subsystem, section metadata and bounded import tables.
- Feed native PE imports through the existing SigmaScope rule/capability engine, allowing concrete imported APIs to become high-confidence static evidence without loading the DLL/executable.
- Bind the binary-classifier implementation into `artifactAnalysisRevision`, so parser-semantic changes invalidate artifact-analysis cache identities.
- Retain the 2.11 immutable ClamAV/reviewed-YARA contracts and the 2.10 artifact/source-attribution contracts unchanged.

## 2.11.0 — Immutable ClamAV transport and reviewed YARA provenance

- Bump Omega Security Services / SigmaScope engine to **2.11.0** because secondary-engine execution identity and Evidence-v2 semantics now change materially.
- Add deterministic content-addressed large-definition asset tooling for ClamAV CVD/CLD databases; official databases no longer need to be committed to `catalog-data`.
- Freeze asset URL, SHA-256, byte count, per-database SHA-256/size, and exact `clamscan` executable identity at the daily Definitions boundary.
- Make continuous workers materialize only the exact frozen ClamAV asset. They never run FreshClam, and database/executable mismatches report ClamAV as unavailable instead of falling back to live/system definitions.
- Keep ClamAV supplemental: its availability and matches cannot alter SigmaScope severity or source-review coverage by themselves.
- Add `omega.sigmascope.yara-policy.v1` with fail-closed reviewed metadata sidecars for every YARA rule: rule names, status, provenance, license, review time, scope, false-positive expectation and notes.
- Require a frozen YARA executable identity whenever any rule is enabled; no production YARA rules are enabled in 2.11.0 yet.
- Preserve YARA rule provenance/license/scope/false-positive context into bounded Evidence-v2 match records.
- Advance the secondary-security Evidence contract to v2 for new artifact scans while retaining validation compatibility with legacy 2.10 contract-v1 evidence.
- Bind secondary asset transport, executable identities, policy and metadata into secondary/artifact analysis revisions so cache reuse remains truthful.
- Add dedicated large-asset, tamper, executable-mismatch and unreviewed-YARA regression coverage plus workflow contracts for the Definitions/worker split.

## 2.10.0 — Artifact identity and secondary-security foundation

- Bump the SigmaScope scanner engine to **2.10.0** for the first semantic scanner-model pass after the 2.9.x transport/stability releases.
- Bind new artifact analyses to an explicit `omega.sigmascope.artifact-identity.v1` contract containing SHA-256, package byte count, resolved artifact URL, catalog/artifact versions, and embedded manifest identity.
- Persist a stable `omega.manifest-observation.v1` identity for the exact catalog observation that selected the scanned artifact.
- Validate the 0/40/70/95/100 source-attribution ladder by recomputing it from provenance; hand-authored confidence/coverage values are rejected by the Evidence-v2 validation contract.
- Keep source-only follow-ups backward compatible: they may add current manifest/source attribution to legacy evidence without claiming the old artifact bytes were revalidated.
- Record exact artifact-pinned source commits when a manifest/artifact origin supplies a verified 40-hex commit; reserve 100% coverage for reproducible source-to-artifact proof.
- Add bounded local YARA and ClamAV adapters as **supplemental evidence only**. No plugin bytes are executed, no shell is used, output/time/match counts are bounded, and artifact SHA-256 is verified before secondary scanning.
- Freeze secondary-security definition descriptors into daily Definitions and bind their revision into `artifactAnalysisRevision`, so signature changes invalidate artifact-analysis cache identities.
- Keep secondary engines disabled when no frozen definitions exist. No production YARA rule set is enabled yet. ClamAV database transport remains intentionally disabled until an immutable large-signature mechanism exists rather than committing oversized databases to `catalog-data`.
- Pass `OMEGA_SECONDARY_SECURITY_ROOT` from the continuous worker to the frozen daily Definitions tree.
- Keep DeltaScope outside the production scanner decision/publication path and preserve last-known-good Evidence-v2 behavior.

## 2.9.8 — TONI notification language

- Keep SigmaScope neutral in Discord notices: the scanner reports findings and evidence; personality belongs to TONI.
- Replace the harsh verdict wording with the calmer invitation: `Review the findings if you want to know more.`
- Use factual notification titles such as `New security findings for <plugin>` and `Omega catalog updated`.
- Stop calling a publication the `daily catalog` in TONI messages; use `latest catalog snapshot` so extra manual/test runs read naturally.
- Refresh TONI's fixed deterministic voice pools while preserving the irritated-security, wealthy-catalog, happy-Definitions, and cocky-evidence personalities.
- No scanner, scoring, catalog, Evidence-v2, or Discord routing semantics changed.

## 2.9.7 — Frozen Definitions OSV audit accounting

- Pass the frozen daily `osv-advisories.json` directly into the independent developer audit.
- Verify the exact `queriedPackageVersionPairs` universe independently against the working NuGet dependency set.
- Keep count-only legacy coverage fail-closed: `0/N` queries still fails when no exact frozen query universe is supplied.
- Treat NuGet versions discovered after the daily Definitions freeze as an explicit warning (`osv.coverage.frozen_gap`) instead of a false failure; no live mid-day OSV lookup is introduced.
- Fail if the frozen advisory payload's declared query count disagrees with its exact package/version list, or if the working projection disagrees with the frozen query count.
- Scanner rule/scoring semantics remain SigmaScope engine 2.9.0.

## 2.9.6 — Catalog / Sigmascope mutual exclusion

- Give catalog publication and the continuous Sigmascope worker the same GitHub Actions concurrency group.
- Catalog and Sigmascope can no longer execute simultaneously, including manual catalog runs.
- Keep `cancel-in-progress: false`: an already-running operation finishes and the other waits rather than being killed.
- Add a workflow regression contract for the shared lock.

## 2.9.5 — TONI notification identity

- Discord publication notices now use exactly `TONI` as the visible webhook sender name.
- Message content, routing, sanitisation, retry behaviour, and scanner/catalog semantics are unchanged.

## 2.15 historical migration checkpoint

### Phase 5 SRL compiler/evaluator

- Implement bounded non-executable `omega.sigmascope.rule.v1` and `omega.sigmascope.ruleset.v1` compilation/evaluation for local DeltaScope authoring only.
- Type-check selectors against the registered Phase-4 observation field registry; forbid current findings/permission/automation/behavior-consistency projections as recursive rule inputs.
- Add exact/CI equality/membership/contains/prefix/suffix, existence/missing, numeric comparisons, boolean conditions and bounded count thresholds.
- Enforce same-record matching and repeated-array same-element matching so unrelated observation/profile rows cannot be joined accidentally.
- Keep the evaluation graph one-directional: observations/classifications emit typed facts; correlations may consume observations/facts but cannot emit facts or consume findings.
- Add deterministic semantic `ruleRevision` / `ruleSetRevision`, stable output ordering and bounded evidence/fact/finding limits.
- Add `omega.sigmascope.rule-fixture.v1`, DeltaScope `rule-compile`, `rule-test`, and `rule-eval`, and shipped positive/negative rule-author examples.
- Keep `productionRuleEvaluationEnabled=false`; Definition Pack compilation/freezing is Phase 6 and no live 2.14 scanner/evidence/catalog state is changed.

- Document the planned behavior-transparency architecture: independent security-hygiene evidence, SigmaScope capabilities, behavior-consistency comparison, and provenance instead of one opaque risk model.
- Specify optional source-controlled `.omega/plugin.yaml` developer profiles with capability reasons, services/destinations, native-component/IPC explanations, explicit `not-expected` declarations, strict sanitisation, and a non-authoritative trust boundary.
- Specify a shared capability registry plus a bounded, non-executable Sigma-inspired YAML SigmaScope Rule Language and reviewed Definition Packs compiled/frozen at the Daily Catalog boundary.
- Specify a DeltaScope Rule Lab for local/experimental YAML validation, selector tracing, dry-run/replay against immutable evidence, fixture generation, baseline diffs, and candidate export.
- Specify an authorization-gated GitHub candidate-rule workflow that treats issue YAML as inert data, revalidates before promotion, creates a normal reviewed PR, and never auto-trusts a self-declared author.
- Plan an observation/rule/projection identity split so compatible rule-only Definition changes can re-project retained observations without automatically redownloading/rescanning plugin artifacts.


## 2.9.4 — Evidence source-cache transport integrity

- Preserve an unchanged variant's published source-analysis cache descriptor and bytes when the disposable working database has no materialized cache row.
- Continue materializing source-analysis cache datasets for fresh successful variants whose derived files are not yet present in the candidate tree.
- Add a regression reproducing the prior 3-byte `[]` overwrite against a retained non-empty descriptor.
- Scanner rule/scoring semantics remain SigmaScope engine 2.9.0.

## 2.9.3 — Discord delivery compatibility

- Send the Discord HTTP API a valid `DiscordBot (...)` User-Agent instead of Python urllib's default identity, avoiding Cloudflare/API 403 rejection.
- Add an explicit `Accept: application/json` header and preserve `Content-Type: application/json`.
- Include a bounded Discord error response body in failures without logging webhook URLs or secrets.
- Add regression coverage for the exact isolated delivery request headers.
- No scanner, scoring, catalog, or Evidence semantics changed.

## 2.9.2 — Discord publication notifications

- Add isolated Discord notifications for daily catalog publication and SigmaScope Evidence v2 publication.
- Keep webhook credentials out of the notice-building process; delivery runs in a separate `discord-public` environment job.
- Add deterministic fixed voice-line pools: irritated security, wealthy catalog growth, happy Definitions updates, and cocky/satisfied evidence reviews.
- Add eight notification regression tests covering sanitisation, routing, revision comparisons, deterministic wording, and tone selection.
- Preserve the catalog migration retention guard and marketplace protocol v2 validation while merging the adapted notification workflow.
- No SigmaScope scanner decision/scoring semantics changed.

- Split repository-side catalog/security implementation from the Omega C# client branch.
- Keep the SigmaScope scanner engine at **2.9.0**; the branch split does not change scanner semantics by itself.
- Add explicit `tools/security/deltascope.py` developer entry point over the existing read-only evidence browser/auditor.
- Convert catalog, SigmaScope, source-submission and legacy-compaction workflows to reusable workflows owned by `sigmascope`.
- Require service workflows to explicitly check out `sigmascope` when invoked by thin default-branch callers.
- Keep DeltaScope manual/read-only and outside the production evidence publication path.

## DeltaScope antivirus/YARA visibility hotfix

DeltaScope now exposes a permanent top-level **Antivirus & YARA** panel and moves per-plugin ClamAV/YARA results directly below the selected plugin overview. Clean/no-match results are shown explicitly; scans without secondary-security evidence are labelled as unrecorded rather than implied clean. This is developer-view-only and does not alter SigmaScope analysis or publication semantics.

## DeltaScope UI documentation/editor maintenance

- Render the platform manual as Markdown in the Documentation workspace.
- Keep a dark icon rail when global navigation is collapsed.
- Remove the tile border/background from the Omega masthead mark.
- Add explicit undo/redo history for editable local rule YAML.
- Expand Visual rule authoring with side properties and a Focus canvas mode.


## Analysis Dispatcher v1

- Added `omega.analysis-dispatcher` as a first-class control-plane component.
- Added lease-based one-item queue claims with expired-runner recovery and bounded retries.
- Added exact claim-token settlement so stale runners cannot settle a later retry.
- Added reusable claim/settle broker-state workflows sharing the broker concurrency boundary.
- Added a five-minute default-branch dispatcher template with explicit static routing for `omega.discovery`; queue data cannot select workflow paths.
- Kept SigmaScope on its canonical scan queue and made no Rift implementation changes.

## Analysis Dispatcher worker-pool refinement

The generic dispatcher is now a short-lived parallel runner rather than a one-job synchronous chain. SRL/Stigma-1 observation requests become broker work; `analysis-dispatcher-batch-claim.yml` atomically persists leases before launch, with a default four-job global pool and component-specific `maxConcurrent` limits. The default-main runner then starts allow-listed worker workflows asynchronously, so a later dispatcher immediately sees existing `running` leases and can reserve different work. Omega Discovery is capped at one concurrent full refresh. In the current tree SigmaScope is also generic-broker dispatchable through the canonical scan-queue adapter, with `maxConcurrent: 1` until scan execution is separated from serialized Evidence-v2 merge/publication. No Rift implementation is changed by these SigmaScope passes.

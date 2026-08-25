# Omega security platform — missing components and remaining work

This document is the implementation roadmap for the component/collector/broker architecture. It distinguishes a **missing deployable component** from a **missing collector inside an existing component** and from **control-plane work**. Registration alone never means a component is runnable.

## Current platform baseline

The following platform boundaries are implemented on the SigmaScope side:

- `omega.component-registry.v1` describes deployable/trust-boundary components and launch contracts.
- `omega.collector-registry.v1` describes typed observation providers owned by those components.
- Stigma-1/SRL can express implementation-neutral hard `observationRequest` dependencies.
- retained Stigma rule projections now publish hash-pinned `observation-requests.json`, and the production broker reconciliation bridge idempotently converts those dependencies (plus replay gaps for registered observation collections) into `omega.analysis-request.v1`.
- `omega.observation-inventory.v1` is materialized from current Evidence-v2 and the latest compatible Discovery snapshot before broker resolution, so already-retained immutable/fresh TTL observations are reused instead of queued again.
- `omega.analysis-request.v1` and the Analysis Broker resolve remaining requests into durable work without executing providers.
- the Analysis Dispatcher uses leased queue claims, global/per-component concurrency and an explicit main-side component allow-list.
- Omega Discovery is generic-broker dispatchable.
- SigmaScope is generic-broker dispatchable through `sigmascope_request_adapter.py`; broker work is merged into the existing canonical SigmaScope scan queue rather than creating a second scanner queue.
- Evidence-v2 remains the retained security-evidence authority; Catalog remains the canonical plugin/source/variant identity authority.

SigmaScope broker concurrency is intentionally `maxConcurrent: 1` today because scan execution and Evidence-v2 candidate merge/publication still share one serialized publication boundary.

## Missing deployable components

### 1. Build Provenance / Rebuilder — `omega.rebuilder`

**Status:** planned; registered but not runnable.

**Owns:** exact source-to-distributed-artifact build proof.

**Must provide:** `sourceArtifactBuildProof`.

Required work:

- define a frozen build-request contract for exact source revision + exact distributed artifact;
- execute source builds in a fresh isolated build environment;
- pin/record SDK/toolchain, dependency restore inputs, build recipe and environment identity;
- hash every relevant output and compare the produced plugin package with the distributed package;
- retain deterministic match/mismatch/indeterminate attestations with provenance;
- add a reusable component workflow and main dispatcher route only after the contract is production-ready;
- ingest the retained observation into Evidence-v2 without allowing the rebuilder itself to assign security severity.

This is what eventually permits `source_to_binary_verified` to be evidence-backed rather than permanently conservative.

### 2. Standalone Threat Intelligence — `omega.threat-intelligence`

**Status:** embedded transition. A bounded daily reputation/DNS snapshot already exists, but it is collected as part of the current catalog/security publication workflow rather than as a separately dispatchable component.

**Owns:** time-dependent external security intelligence.

**Must provide:** at minimum `endpointDns`, `endpointReputation`, `endpointConnectivity`; certificate revocation/status intelligence may later join this component.

Required work:

- extract live DNS/reputation/connectivity collection from the daily builder into an independent reusable workflow/component;
- materialize observations with `observedAt`, expiry/TTL, provider/feed provenance and content digest;
- retain last-known observations without ever equating `unlisted` with `safe`;
- register active collectors and make them broker-dispatchable only after bounded lookup, rate-limit, licensing and failure semantics are defined;
- add a static main dispatcher route.

SigmaScope must remain deterministic/static: it should identify endpoint literals and capabilities, while Threat Intelligence owns live-changing facts about those endpoints.

### 3. Rift runtime-analysis component — `omega.rift`

**Status:** external workstream. It is represented only at the SigmaScope-side component/collector contract boundary in this session.

**Owns:** isolated runtime observations. **Alpha remains a component inside Rift**, not a peer service.

Remaining implementation/launch work is owned by the separate Rift workstream. SigmaScope-side work should only consume validated typed runtime observations through published contracts; this roadmap must not be used to move Rift implementation back into the SigmaScope branch.

## Missing collectors/features inside SigmaScope — not separate components

### 4. Authenticode trust validation

**Status:** implemented first-class collector lane.

**Collector:** `omega.collector.sigmascope.authenticode`.

**Provides:** `binarySignatureTrust`.

Implemented:

- exact variant + artifact-SHA broker binding;
- bounded/safe artifact ZIP inspection without plugin execution;
- Windows-native `Get-AuthenticodeSignature` / WinVerifyTrust status collection;
- signer and timestamp certificate identity/algorithm fields;
- content-addressed generic collector results;
- generic Evidence-v2 retention plus independent collector-only mutation audit;
- exact-subject, seven-day TTL observation-inventory reuse and SRL replay;
- neutral native-PE coverage policy that requests signature observations without making a finding;
- dedicated Windows workflow lane and Windows regression smoke coverage.

Remaining refinement:

- if deterministic frozen-root chain replay is required in addition to Windows platform trust, add it as a separate validation profile rather than overwriting the retained platform observation;
- live CRL/OCSP/revocation intelligence belongs to the standalone Threat Intelligence component.

### 5. ELF and Mach-O analysis parity

**Status:** first specialist parity pass implemented. The shallow artifact classifier still identifies ELF/Mach-O cheaply; brokered `elfBinaryStructure` and `machOBinaryStructure` collectors now retain deeper structure through the generic collector-result/Evidence-v2 path.

**Owner:** SigmaScope native-structure collector.

Implemented:

- ELF `DT_NEEDED`, bounded dynamic symbols, RPATH/RUNPATH, interpreter, program/section counts and PIE/RELRO/bind-now/executable-stack/writable+executable segment state;
- Mach-O dylib/load commands, rpaths, architecture/fat slices, entry/build metadata, encryption flag, code-signature presence and initial segment protections;
- exact artifact binding, bounded ZIP/native-member parsing, generic Evidence-v2 retention and automatic native-format coverage requests.

Remaining refinement:

- ELF relocations/versioned-symbol details where they improve evidence quality;
- Mach-O symbol/export trie, entitlements and hardened-runtime/code-signing metadata beyond signature presence;
- normalized cross-format native dependency/security observations where SRL benefits from one semantic vocabulary rather than format-specific collections.

Do **not** split PE, ELF, Mach-O, YARA or ClamAV into separate platform components merely because they are separate analysis engines; they share SigmaScope's non-executing static-analysis trust boundary.

## Missing control-plane work

### 6. Production Stigma-1/SRL → Analysis Broker request ingestion

**Status:** implemented in the closed-loop broker pass.

Production rule reprojection now persists typed `observationRequests` in a hash-pinned `rule-projections/observation-requests.json` sidecar. `stigma_broker_bridge.py` converts those requests to stable `omega.analysis-request.v1` identities bound to rule revision + exact current variant/artifact subject. It also translates replay gaps (`missingCollections` / bounded historical collections) to generic requests when the missing collection has a registered provider. Reconciliation is idempotent and never grants Stigma component-execution authority or direct finding write-back.

Remaining refinement, not a missing bridge:

- add richer subject derivation for future endpoint-scoped requests where the requested observation must be bound to one endpoint rather than the whole variant;
- surface bridge diagnostics and dependency edges in DeltaScope.

### 7. Parallel SigmaScope execution with serialized Evidence-v2 publication

**Status:** not implemented. Generic SigmaScope broker dispatch exists, but `maxConcurrent` remains 1 deliberately.

To raise it safely:

1. split the current workflow into independent scan-execution workers that emit immutable/content-addressed result bundles;
2. allow several workers to scan exact subjects in parallel without writing candidate Evidence-v2 directly;
3. add one serialized merge/publisher that validates and merges completed result bundles into a fresh candidate Evidence-v2 snapshot;
4. make settlement depend on successful merge/observation verification, not merely worker completion;
5. only then raise SigmaScope `maxConcurrent` in the Component Registry.

The global Analysis Dispatcher already supports this future model; no dispatcher redesign should be needed.

### 8. Broker prerequisite chaining

**Status:** partial.

A brokered source-analysis request currently requires a completed artifact scan prerequisite. If the prerequisite is absent, the SigmaScope request adapter fails closed rather than automatically expanding the dependency graph.

Required work:

- represent prerequisite work as explicit child/parent analysis requests;
- enqueue the artifact prerequisite first;
- keep the original source observation request blocked rather than failed;
- wake/re-resolve the dependent request after prerequisite settlement;
- retain the dependency edge for DeltaScope explanation.

### 9. Production observation-inventory materialization

**Status:** implemented in the closed-loop broker pass.

`observation_inventory.py` now materializes bounded `omega.observation-inventory.v1` state from current retained SigmaScope Evidence-v2 observation contracts, compatible retained collector bundles already present in Evidence-v2, and the latest compatible Omega Discovery collector snapshot. Immutable observations reuse by exact subject; TTL observations carry calculated expiry. The production Analysis Broker loads this inventory before resolving either explicit requests or Stigma-derived requests.

Remaining refinement, not a missing production feed:

- add first-class inventory producers when standalone Threat Intelligence/Rebuilder components become active;
- expose inventory health/age in DeltaScope;
- consider sharding only if real production inventory size approaches the current bounded ceiling.

### 10. Reconciliation of unresolved/planned-provider requests

**Status:** missing automation.

A request retained while its provider is planned/non-dispatchable must not disappear, but it also needs a deterministic way to become runnable after a later Definitions/registry revision activates that provider.

Required work:

- re-resolve durable `requested`/blocked work when Component/Collector Registry revisions change;
- transition only newly satisfiable requests to `queued`;
- retain the previous resolution and new resolution for lineage;
- never silently retarget work to a new provider without recording the registry revision change.

### 11. Generic component result/settlement evidence

**Status:** first generic collector result envelope implemented; dispatcher/component-wide settlement unification remains incomplete.

`omega.collector-result.v1` now provides exact request/work/subject binding, collector + observation contract revisions, bounded typed collection digests, terminal collector outcome/errors, and content-addressed result identity. Authenticode is the first production consumer and Evidence-v2 adapter path.

Remaining component-wide work:

Each component ultimately needs a standard result summary for the broker/dispatcher, such as:

- request/work/claim identity;
- exact subject;
- component + collector revisions;
- produced observation collections/digests;
- terminal outcome/error classification;
- Evidence-v2 or other retained-state reference;
- verification that the hard observation dependency is actually satisfied.

The component remains responsible for its domain-specific evidence; the generic result envelope should not flatten or duplicate full scanner reports.

### 12. Deep Scan migration to generic Analysis Broker semantics

**Status:** separate legacy/specialized queue remains.

The existing SigmaScope Deep Scan queue is a safe static differential-analysis workflow with dynamic resource budgets, but it predates the generic broker/dispatcher model.

Required work:

- express deep static follow-up as normal typed observation requests/profile requirements;
- retain existing safety/budget/profile semantics;
- route through the generic Analysis Broker/Dispatcher rather than a second orchestration island;
- preserve existing queue history/migration compatibility;
- do not conflate deep **static** analysis with runtime execution.

## Evidence and storage work

### 13. Evidence-v2 compaction/content reuse

**Status:** measurement exists; schema rewrite not performed.

The storage audit already measures per-domain bytes, current/history ratios and exact duplicate groups. Remaining work is to design content-addressed reuse/compaction only after production measurements justify it.

Requirements:

- no loss of historical variant/artifact lineage;
- current-vs-history semantics remain explicit;
- exact retained hashes remain verifiable;
- migration must be atomic and reversible/validated;
- never compact merely because two files happen to be byte-identical when their logical identity/retention contract requires distinct references.

## Main/control-plane deployment work

### 14. Install/maintain explicit dispatcher routes

**Status:** Discovery + SigmaScope route templates implemented; actual default-branch deployment is an operator step.

Rules:

- main owns launch authority;
- queue data never supplies executable workflow paths;
- each new component requires an explicit allow-listed main route;
- rollout must add/freeze the component implementation before enabling its main route;
- old dispatchers advertise an explicit allowed-component set so they cannot lease work for a component they do not know how to launch.

For the closed-loop broker specifically, freeze the updated worker into Definitions before enabling the v4 main dispatcher route. The v4 runner performs `reconcile -> reserve -> asynchronous launch`.

## What is *not* missing as a separate component

The following should remain collectors/engines inside SigmaScope unless their trust/execution boundary changes materially:

- PE parsing;
- ELF parsing;
- Mach-O parsing;
- Authenticode offline validation;
- YARA;
- ClamAV;
- dependency/component analysis;
- static endpoint extraction;
- managed metadata/IL/reachability analysis.

A new component is justified by a distinct execution/trust/lifecycle boundary, not simply by having a separate library or scanner engine.

## Recommended implementation order from the SigmaScope workstream

The observation inventory, Stigma→Broker bridge, Authenticode lane, first ELF/Mach-O structural parity pass, and first richer source/build/dependency observation pass are now complete. The remaining recommended order is:

1. **Standalone Threat Intelligence.** Move changing DNS/reputation/connectivity facts out of the daily builder into TTL-backed collector observations so intelligence refresh never forces artifact rescans.
2. **Parallel SigmaScope execution / serialized Evidence-v2 merge.** Unlock useful worker-pool parallelism without concurrent evidence writers.
3. **Prerequisite chaining and unresolved-request reconciliation.** Make compound SRL dependencies self-driving and wake planned-provider work when registries change.
4. **Finish generic component settlement.** Extend the collector-result pattern through dispatcher settlement and non-SigmaScope providers without flattening domain evidence.
5. **Deep Scan migration to the generic broker.** Remove the remaining special orchestration island.
6. **Build Provenance/Rebuilder.** Add exact source-to-distributed-artifact build proof once prerequisite and settlement semantics are mature.
7. **Evidence-v2 compaction**, only after reviewing real storage-audit results.

Rift remains a separate implementation workstream and consumes/publishes only through the shared contracts. DeltaScope is not part of this producer roadmap; it only consumes published data.

# SigmaScope production parallel queue drain

The production queue drain replaces the old Phase-4 shadow/equivalence commissioning loop. It does **not** change Security Evidence v2, queue v2, Definitions, or the Omega customer database contract.

A default production wave selects up to 40 exact persistent queue keys with `release-and-baseline-lanes-v1` worker allocation. Two workers prefer new releases of known plugins; two prefer baseline and other outstanding work. Each lane retains the existing `coverage-first-v1` ordering and retry eligibility. Empty lanes lend their unused capacity. A single-worker configuration alternates lanes within its batch and across one-item waves.

Four immutable scanner workers start in parallel, each processing up to ten exact queue keys sequentially from the same published Evidence head. Each exact key emits an immutable non-authoritative result bundle. One serialized merger synchronizes the current Evidence queue against the immutable queue seed, combines the disjoint bundles, rebuilds global projections, performs SRL reprojection, validates the candidate, and runs independent developer/storage audits. Only one publisher may fast-forward Security Evidence v2.

Deep Scan state and source-follow-up side effects are published only after Evidence becomes authoritative. Another parallel wave is dispatched immediately while eligible artifact/source work remains. Global/non-variant work is deliberately yielded to the existing serialized `sigmascope.yml` worker.

The hard ceiling is 64 exact queue items per wave. The default is 4x10; the architecture can later run 8x8 without changing the authority model.

The customer database is republished every five successful parallel waves by default and always at a terminal/yield boundary. No shadow scan and no serialized equivalence scan are performed.

## Continuous release intake

Manifest enrichment is due hourly through the existing reconciliation heartbeat. After an exact collector result settles successfully against the current catalog revision, the reconciler asynchronously routes `mode=release-intake` through the registered `security-orchestration-dispatch.yml` entrypoint on `sigmascope`. No new default-branch workflow registration is needed.

`catalog-release-intake.yml` validates the result hashes and settlement, normalizes the settled manifests using the canonical seeded catalog importer, checks source inventory and identity-epoch continuity, and atomically publishes catalog identity plus a rebuilt scan-queue seed. Existing plugins' new artifact targets are marked as updates, including plugins whose previously scanned version is now retired. New plugins remain baseline work. Duplicate intake is a no-op; stale, unsettled or tampered results cannot publish.

Frozen Definitions are copied byte-for-byte and validated, not regenerated. A full Definitions freeze remains a scanner/rules release boundary, but is no longer required to admit plugin releases. Metadata-only changes and removals without a new artifact target remain with the ordinary catalog build. Artifact bytes are still acquired and identified by the scanner; manifests alone do not prove their content hash.

Intake and scan waves share the queued authority-writer mutex. Admission happens between waves, never by changing a running worker's inputs. Successful admission wakes the parallel drain. This is periodic, settlement-gated intake, not an immediate release webhook or preemption of a running scan; collector prerequisites, backoff and queued waves can add delay.

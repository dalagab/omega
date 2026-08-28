# SigmaScope production parallel queue drain

The production queue drain replaces the old Phase-4 shadow/equivalence commissioning loop. It does **not** change Security Evidence v2, queue v2, Definitions, or the Omega customer database contract.

A default production wave selects up to 40 exact persistent queue keys through the existing `coverage-first-v1` policy. Four immutable scanner workers start in parallel, each worker processes up to ten exact queue keys sequentially from the same published Evidence head, and each exact key emits an immutable non-authoritative result bundle. One serialized merger then synchronizes the current Evidence queue against the latest immutable queue seed, combines the disjoint bundles, rebuilds global projections, performs SRL reprojection, validates the candidate, and runs independent developer/storage audits. Only one publisher may fast-forward Security Evidence v2.

Deep Scan state and source-follow-up side effects are published only after Evidence becomes authoritative. Another parallel wave is dispatched immediately while eligible artifact/source work remains. Global/non-variant work is deliberately yielded to the existing serialized `sigmascope.yml` worker.

The hard ceiling is 64 exact queue items per wave. The default is 4x10; the architecture can later run 8x8 without changing the authority model.

The customer database is republished every five successful parallel waves by default and always at a terminal/yield boundary. No shadow scan and no serialized equivalence scan are performed.

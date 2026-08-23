# Observation and projection contract

Omega distinguishes **retained observations** from **derived projections** so rules can be replayed without confusing old conclusions with original evidence.

## Observation

An observation is a bounded normalized fact extracted from artifact, source or supplemental engine input. Examples include managed call sites, native imports, endpoints, dependencies, source provenance and developer-profile declarations.

Each registered observation collection defines:

- stable collection identity;
- field schema;
- semantic class;
- completeness/replay semantics;
- whether it is eligible as SRL input;
- provenance and physical Evidence-v2 backing.

## Projection

A projection is derived from observations/facts. Examples include current findings, permission candidates, automation capability summaries, behavior-consistency summaries and relationship views.

A projection must not be fed back into production SRL merely because it is convenient; that creates conclusion-on-conclusion recursion and makes replay harder to reason about.

## Completeness

A collection can be complete, bounded/transport-limited or unavailable for a retained analysis. Rules that depend on absence require sufficient completeness. If an old snapshot retained only a bounded subset of endpoints, a rule must not conclude “no matching endpoint exists”. It should require targeted re-analysis.

## Replay

Rule replay uses the observation contract to determine whether the retained evidence is sufficient. The possible outcomes are conceptually:

- exact evaluation possible;
- evaluation possible with explicitly allowed bounded semantics;
- required collection missing/incomplete → re-analysis required.

## Adding a collection

1. Define a stable logical collection name.
2. Define bounded typed fields.
3. Specify the physical scanner/source input.
4. Specify completeness semantics.
5. Register whether SRL may consume it.
6. Retain it in immutable analysis/Evidence-v2.
7. Expose it through DeltaScope data/reference tooling.
8. Add positive/negative serialization and replay tests.

## Anti-mass-rescan principle

A new rule or Definition should not force every plugin to be rescanned when existing immutable observations are sufficient. Conversely, the platform must not pretend old evidence contains a primitive that was never retained. The contract decides whether reprojection or targeted re-analysis is appropriate.

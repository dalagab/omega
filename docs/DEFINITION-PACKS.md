# Definition Packs

A Definition Pack is a reviewed group of Stigma-1 rules, fixtures and provenance metadata that can be compiled and frozen into Security Definitions.

Definition Packs separate **rule source** from **production activation**. A source-controlled rule is not authoritative until it is accepted through the review/freeze boundary used by the platform.

## Why packs exist

Packs provide:

- stable grouping by security purpose;
- deterministic compilation;
- positive/negative fixtures;
- review/provenance metadata;
- content-addressed identity;
- an auditable boundary between experimental rules and production rules.

## Recommended pack scope

Keep a pack focused, for example:

- network endpoint classifications;
- managed API capabilities;
- provenance/source relationships;
- compound execution/network correlations;
- deep-analysis request logic.

Do not group unrelated rules merely to reduce file count.

## Pack lifecycle

```text
rule source + fixtures
        ↓
local validation/replay
        ↓
GitHub candidate/review
        ↓
merged Definition Pack source
        ↓
Definitions compiler/freezer
        ↓
frozen pack + exact provenance
        ↓
production-capable rule set when authority gates permit
```

## Fixtures

Each security rule should have enough fixture coverage to demonstrate both intended matches and important near-misses. Compound rules need fixtures for combinations that should and should not match.

## Trust tiers and activation

The repository can contain experimental/research rules that are useful in DeltaScope but not active in production. Pack metadata and frozen Definitions determine what is authoritative; repository presence alone does not.

## Changing a pack

1. Update rule source/fixtures.
2. Validate with the same compiler/evaluator used by DeltaScope.
3. Replay representative retained evidence.
4. Review false-positive implications.
5. Submit through normal GitHub review.
6. Let the Definitions freezer compile and content-address the accepted pack.

A pack-only rule change should not require an artifact rescan when the retained observation contract already contains everything required for exact replay.

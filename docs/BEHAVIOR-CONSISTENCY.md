# Behavior consistency projection

Status: **implemented in the unreleased 2.15 development line** as `omega.sigmascope.behavior-consistency.v1`.

## Purpose

Behavior consistency places independent SigmaScope observations next to developer-provided `.omega/plugin.yaml` declarations. It is a deterministic presentation/research projection, not a verdict engine.

The invariant is:

> Developer claims can explain an observation, but they cannot create, suppress, downgrade, or prove an observation.

The projection never changes native SigmaScope findings/severity, capability observations, YARA, ClamAV, OSV, artifact identity, source attribution, review coverage, or source-to-artifact verification.

## Capability states

For a plugin with a valid developer profile, each canonical capability can be projected into one of these states:

| State | Meaning |
| --- | --- |
| `expected-observed` | Developer declares the capability as expected and SigmaScope independently observes it. |
| `observed-undeclared` | SigmaScope observes the capability, but the valid profile has no declaration for it. |
| `expected-not-observed` | Developer declares it expected, but the current compatible static observations do not contain it. This is not proof that the plugin never uses it. |
| `not-expected-observed` | Developer explicitly says the capability is not expected, but SigmaScope independently observes it. This is a strong consistency-review signal, not a malware verdict. |
| `not-expected-not-observed` | Developer explicitly says the capability is not expected and SigmaScope does not currently observe it. |

If no valid developer profile exists, observed capabilities are reported as `observed-no-profile`, **not** as `observed-undeclared`. Absence of a profile is not a developer claim.

## Destination/service comparison

The projection also compares developer-declared destination patterns and service URL hosts with SigmaScope endpoint observations.

Only endpoint rows marked as concrete destination evidence are used. Supported developer patterns are exact hosts and bounded wildcard subdomains such as `*.example.com`.

The projection distinguishes:

- observed destination explained by a declaration;
- observed destination not covered by the valid profile;
- declared destination not currently observed;
- observed destination when no valid profile exists.

An `.omega/plugin.yaml` URL cannot prove itself. Profile files are not fed through normal source-code scanning as independent endpoint evidence, and historical endpoint evidence originating from `.omega/plugin.yaml` is filtered out during comparison.

## Evidence-v2 and marketplace transport

The compact projection is retained as `behaviorConsistency` in current Evidence-v2 detail and projected to marketplace security state. Marketplace rows expose bounded summary counters for:

- observed-but-undeclared capabilities;
- observed capabilities explicitly declared not expected;
- expected declarations not currently observed;
- unexplained concrete destinations.

These fields are presentation/research data. They are intentionally excluded from artifact-intrinsic canonicalization because developer/source context can differ between variants even when artifact bytes are shared.

## DeltaScope

DeltaScope shows a dedicated **Behavior consistency · observed ↔ developer-declared** panel. Developer reasons are explicitly labelled **Developer explanation** and are visually separated from SigmaScope evidence.

DeltaScope may use mismatches to raise deterministic research priority, but that developer-only prioritization does not alter production SigmaScope severity.

## Rule-author boundary

Rule authors should understand this projection, but future production SRL rules **must not consume `behaviorConsistency` as an input collection**. It is already a conclusion/projection and consuming it would create conclusion-on-conclusion recursion.

A production consistency rule should consume the underlying independent observation collection(s) plus `developerProfile` directly. For example, a future rule comparing declared network destinations to observed `networkEndpoints` should use those two source collections, not `behaviorConsistency.unexplained`.

DeltaScope exposes `behaviorConsistency` in `rule-schema` only as a presentation/research collection so authors can inspect what the current deterministic comparison produced.

## Replay and migration

The projection can be rebuilt from retained scan/Evidence-v2 data without downloading plugin bytes when the required capability, endpoint and developer-profile data already exists. Historical 2.14 evidence has no `.omega` profile, so migration must preserve it as independent observation evidence and report `observed-no-profile` rather than manufacturing an undeclared-capability mismatch.

If a future comparison requires an observation primitive that historical evidence did not retain, only those variants need targeted re-analysis after the observation/projection compatibility layer identifies the missing collection.

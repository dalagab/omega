# SigmaScope Definition Packs

This directory is the source-controlled authority for SigmaScope Rule Language (SRL / Stigma-1) packs on the unreleased 2.15 development line.

Each pack lives at `packs/<pack-id>/pack.yaml` and uses schema `omega.sigmascope.definition-pack.v1`. Daily Definitions compilation treats pack YAML, SRL rule files, and fixtures as inert bounded data. The compiler validates compatibility and metadata, compiles rules with the exact Stigma-1 engine, runs every declared fixture, prevents duplicate rule/fact identities, hashes all content, and freezes a compiled ruleset under `definitions/srl/`.

Trust tiers:

- `core`: first-party production-eligible after review; every rule must be `reviewed` and fixtures are mandatory, with at least one positive `expected.matchedRules` fixture covering every production rule.
- `reviewed`: externally sourced/curated production-eligible after review; the same reviewed-rule and fixture requirements apply.
- `experimental`: compiled, fixture-tested, and frozen for research/provenance, but not included in the active production ruleset.
- `local`: developer-only. Daily compilation excludes these packs. DeltaScope/local tooling may opt in explicitly.

Production workers must never read this source tree directly. The only production-facing loader is the verified frozen Definition Pack payload in the Daily Definitions snapshot. YARA, ClamAV, OSV and other secondary evidence engines remain independent of SRL packs.

## Current library

DeltaScope 4.5 ships **6 packs, 54 rules and 14 fixtures**:

- `omega-core-static-primitives` — **14 reviewed** literal-backed legacy static observation-to-fact migrations;
- `omega-core-compound` — **2 reviewed** legacy compound correlations;
- `omega-experimental-managed-capabilities` — **13 experimental** managed-call/game-input capability facts;
- `omega-experimental-network-endpoints` — **9 experimental** endpoint-classification facts;
- `omega-experimental-provenance` — **8 experimental** source-provenance/attribution facts;
- `omega-experimental-correlations` — **8 experimental** higher-order research correlations, including a typed Deep Scan request example.

The reviewed production-tier migration set is therefore **16 rules**. It is parity-tested against the current hard-coded legacy behavior over **147 primitive cases** and **32 compound combinations**. Production SRL finding writeback remains separately gated by the cutover process; being reviewed/frozen does not itself switch production evaluation on.

The 38 experimental rules exist so DeltaScope has a useful corpus for inspection, learning, forking, fixture replay, and future review. Experimental rules are never production-active merely because they compile or freeze.

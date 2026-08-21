# SigmaScope Definition Packs

This directory is the source-controlled authority for reviewed SigmaScope Rule Language (SRL) packs on the unreleased 2.15 development line.

Each pack lives at `packs/<pack-id>/pack.yaml` and uses schema `omega.sigmascope.definition-pack.v1`. Daily Definitions compilation treats pack YAML, SRL rule files, and fixtures as inert bounded data. The compiler validates compatibility and metadata, compiles rules with the exact SRL v1 engine, runs every declared fixture, prevents duplicate rule/fact identities, hashes all content, and freezes a compiled ruleset under `definitions/srl/`.

Trust tiers:

- `core`: first-party production-eligible after review; every rule must be `reviewed` and fixtures are mandatory, with at least one positive `expected.matchedRules` fixture covering every production rule.
- `reviewed`: externally sourced/curated production-eligible after review; the same reviewed-rule and fixture requirements apply.
- `experimental`: compiled, fixture-tested, and frozen for research/provenance, but not included in the active production ruleset.
- `local`: developer-only. Daily compilation excludes these packs. DeltaScope/local tooling may opt in explicitly.

Production workers must never read this source tree directly. The only production-facing loader is the verified frozen Definition Pack payload in the Daily Definitions snapshot. YARA, ClamAV, OSV and other secondary evidence engines remain independent of SRL packs.

The first Phase-7 reviewed pack is `omega-core-compound`. It migrates only the two legacy compound correlations; its primitive facts are migration-parity inputs for now, not production observation projections. `python tools/security/deltascope.py rule-parity` must remain green before Daily Definitions can freeze that pack.

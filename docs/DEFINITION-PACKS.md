# SigmaScope Definition Pack v1

Status: **Phase 6 complete; the first end-to-end Phase 7 migration path is implemented locally on the unreleased 2.15 development line.** Production 2.14 remains untouched. Definition Packs are compiled, fixture-tested, content-addressed and frozen into Daily Definitions. Reviewed packs now cover 14 literal-backed primitive observation-to-fact rules and two legacy compound correlations, with fail-closed parity and retained-Evidence replay tooling. The source library also carries 39 experimental rules across managed-call capabilities, endpoint classifications, source provenance and research correlations. Production SRL projection remains gated.

## Pack manifest

A pack is stored at `security-definitions/packs/<pack-id>/pack.yaml`:

```yaml
schema: omega.sigmascope.definition-pack.v1
id: example-core
title: Example reviewed rules
trustTier: core
license: MIT
provenance:
  kind: first-party
  source: https://github.com/dalagab/omega
review:
  reviewer: maintainer-id
  reviewedAtUtc: 2026-08-21T00:00:00Z
compatibility:
  minimumSrlEngineVersion: 1
  minimumObservationContractVersion: 1
  ruleSchema: omega.sigmascope.rule.v1
  fixtureSchema: omega.sigmascope.rule-fixture.v1
  observationContractSchema: omega.sigmascope.observation-contract.v1
rules:
  - path: rules/example.yaml
    ids: [example.rule]
    license: MIT
    provenance:
      kind: first-party
      source: security-definitions/packs/example-core/rules/example.yaml
    review:
      reviewer: maintainer-id
      reviewedAtUtc: 2026-08-21T00:00:00Z
fixtures:
  - path: fixtures/example-positive.yaml
```

The directory name and `id` must match. Rule and fixture paths are pack-relative, regular files only; absolute paths, `..`, symlinks, YAML aliases/anchors/tags and oversized documents are rejected.

## Daily freezing

`tools/security/definition_packs.py` is called by `tools/catalog/definitions_snapshot.py`. A successful Daily Definitions build writes:

- `srl/index.json`: exact pack inventory, provenance, trust tiers, content hashes and Definition Pack revision;
- `srl/compiled-ruleset.json`: the active compiled SRL ruleset containing only `core`/`reviewed` packs;
- `srl/packs/<pack-id>/...`: exact reviewed source rules, fixtures and manifest used for the freeze.

The parent Definitions `index.json` carries `srlDefinitionPacks` with its own `definitionPackRevision` and SRL `ruleSetRevision`. The top-level `ruleSetRevision` remains the separate hard-coded scanner-analysis/queue identity; it is never repurposed as SRL identity. A **pack-only** change leaves that scanner identity alone, while a scanner implementation change (such as Phase 7b retaining a new observation primitive) legitimately advances it.

Every production-tier pack must contain only rules with SRL status `reviewed`, must include review/provenance/license metadata, and must declare passing fixtures and every production rule must be positively covered by at least one fixture `expected.matchedRules` assertion. Duplicate rule IDs and emitted facts fail closed across the complete pack set.

## Production boundary

The frozen loader verifies the parent descriptor, `srl/index.json`, compiled ruleset, and every frozen rule/fixture hash before returning the ruleset. It never reads `security-definitions/packs` at worker runtime.

`productionRuleEvaluationEnabled` remains `false`. The first Phase-7 migration path now has reviewed primitive observation rules and compound correlations, but production activation still requires a real retained corpus produced with the new complete observation contract and a clean replay/cutover review. Historical 2.14 evidence that lacks `staticPatternMatches` is intentionally classified as requiring targeted re-analysis rather than being treated as a negative result.

DeltaScope can inspect a frozen Definitions snapshot with:

```text
python tools/security/deltascope.py definition-packs --definitions-root <path-to-definitions>
```

## Phase 7 migration parity and replay

Two source-controlled production-tier packs form the first migration chain:

- `security-definitions/packs/omega-core-static-primitives/` — 14 reviewed literal-backed observation rules producing the current migratable legacy static primitive facts from `staticPatternMatches`; the five facts used by the existing compound rules are `network.http`, `network.socket`, `process.launch`, `shell.powershell`, and `credential.api`;
- `security-definitions/packs/omega-core-compound/` — reviewed `compound.network-execute` and `compound.credential-network` correlations preserving the legacy user-visible finding payloads.

`tools/security/srl_migration_parity.py` validates the real scanner-observation path. It checks 147 primitive literal cases (canonical/case-perturbed migrated legacy patterns plus near misses) and all 32 combinations of the five primitive facts. Current findings, permission candidates and automation projections are never supplied as SRL raw inputs.

Daily Definitions runs the same migration checker whenever the migrated rules are active. A partial migration or payload/condition drift fails the build. `srl/migration-parity.json` is hash-pinned through `srlDefinitionPacks.migrationParity` and verified with the rest of the snapshot. DeltaScope exposes the check with:

```text
python tools/security/deltascope.py rule-parity
```

Retained-corpus replay is exposed with:

```text
python tools/security/deltascope.py rule-replay --evidence-v2 <path-to-security-evidence-v2>
```

Replay loads only the logical observation collections declared by the reviewed SRL rules. Historical `findings` are used solely as the baseline to compare outputs; they are never converted into facts or otherwise fed into SRL. A new scan with `staticPatternMatchContractVersion=1` freezes an explicit empty collection when there are zero matches, so negative evidence is replayable. A historical report without that completeness marker is `rescanRequired`, not implicitly empty.

Hard-coded primitive and compound logic remains in `sigmascope.py` for now as the migration/production baseline. It must not be removed until a compatible 2.15 corpus has been collected and replayed cleanly and cutover is explicitly reviewed.

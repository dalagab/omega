# SigmaScope observation / projection contract

Status: **Phase 4 implemented locally on the unreleased 2.15 development line.** Production 2.14 continues collecting evidence unchanged. This contract is a migration and replay boundary; it is not a request to rewrite the live Evidence-v2 branch or rescan every plugin.

## Why this split exists

SigmaScope historically stored both low-level normalized evidence and conclusions produced by the scanner in the same analysis/evidence surfaces. That is useful for transport, but it makes a definition-only change look too much like a scanner-analysis change.

Phase 4 gives those two concepts separate identities:

```text
plugin artifact/source
        |
        v
parsers / bounded static analysis
        |
        v
retained observations + provenance + developer claims
        |                         ^
        |                         |
        +---- frozen rules -------+
        |
        v
projection: facts, capabilities, findings, behavior consistency
```

An **observation** says what SigmaScope retained from the artifact/source/catalog context. A **projection** says what a particular deterministic evaluator/rule set concludes from compatible observations.

A rule-only change should therefore not imply an artifact download, PE/.NET parse, source scrape, ClamAV scan, or YARA scan when all observations required by the new rule are already retained exactly.

## Contract identities

Phase 4 adds these transport contracts:

- `omega.sigmascope.observation-contract.v1`
- `omega.sigmascope.observation-collection.v1`
- `omega.sigmascope.projection-contract.v1`
- `omega.sigmascope.projection-replay-audit.v1`

The deterministic root identities are exposed as:

- `observationContractRevision`
- `projectionContractRevision`

Each active variant may carry:

- `observations.observationDigest` — digest of the retained logical collection descriptors;
- `observations.collections` — logical collection availability/completeness;
- `observations.providerRevisions` — artifact/source analysis revisions that produced the retained inputs;
- `projection.projectionRevision` — evaluator/rule-set identity, not a hash of the resulting findings;
- `projection.outputs` — output record counts/digests for auditability.

Do not confuse `observationContractRevision` with the older Definitions field `sourceObservationRevision`. `sourceObservationRevision` identifies the catalog's source-repository ref observations. It is a different subsystem and deliberately keeps its existing name and semantics.

## Logical collections

The machine-readable authority is:

```bash
python tools/security/deltascope.py observation-schema
```

It emits `omega.deltascope.observation-reference.v1` with every registered logical collection, its schema, current physical backing dataset, semantic class, SRL eligibility and any special matching rules.

Phase 4 currently registers logical collections for:

- dependencies;
- IPC integrations;
- namespace imports;
- managed assemblies and symbols;
- managed call sites and reachability;
- native imports;
- rule-neutral static literal-pattern matches (`staticPatternMatches`);
- concrete/sanitized network endpoint observations;
- source-file observations;
- binary classifications;
- artifact identity and manifest observation;
- source attribution and source provenance;
- developer profile claims;
- supplemental secondary-security evidence.

The contract distinguishes four input classes:

- `observation` — independently extracted static evidence;
- `provenance` — identity/attribution context;
- `developer-claim` — explicitly untrusted context from `.omega/plugin.yaml`;
- `hygiene-evidence` — specialist-engine evidence such as YARA/ClamAV, still supplemental-only.

`developerProfile` being SRL-readable does **not** make it trusted. Rules may compare a developer claim with independent evidence, but the claim can never suppress or rewrite the evidence.

## Derived data is not an observation input

The physical Evidence-v2 analysis layout remains backward-compatible during migration. Historical/new analyses may still contain datasets such as:

- `findings`;
- `permissions`;
- `automation`.

Phase 4 marks those datasets as `semanticClass: projection` and `srlEligible: false`.

Likewise, current presentation/research outputs such as `behaviorConsistency`, capability projections and summaries must not become recursive production rule inputs. A future SRL consistency rule must read the original endpoint/call/etc. observations and `developerProfile` directly.

This is a **semantic split first**, not a destructive physical rewrite of every historical Evidence-v2 analysis. Physical transport can be simplified later after migration parity is proven.

## New 2.15 analyses retain report-only observations

Several useful observations historically existed only inside the complete scan report and could be reduced when the report was compacted for public transport. Phase 4 promotes already-present report data into first-class immutable analysis datasets where available, including:

- `nativeImports`;
- `staticPatternMatches`;
- `networkEndpoints`;
- `sourceFiles`;
- `binaryClassifications`;
- `developerProfile`;
- `sourceAttribution`;
- `sourceProvenance`;
- `secondarySecurity`;
- `artifactIdentity`;
- `manifestObservation`.

This export does not reopen or execute plugin bytes. It persists data already present in the completed scan report before transport compaction.

## Historical 2.14 compatibility

Retained 2.14 Evidence-v2 is migration input, not disposable legacy data.

When a future 2.15 candidate synchronizes an older variant, it can infer a variant-level observation contract from:

1. immutable analysis datasets that already exist; and
2. the bounded compact scan report retained on the variant.

Such a contract is marked `legacyCompatibility: true` when the immutable analysis manifest predates the explicit Phase-4 observation contract.

The adapter does **not** download the artifact, scrape source, run a secondary engine, or mutate the retained analysis bytes merely to add the compatibility view.

## Completeness matters

Collection presence is not enough. The contract carries a `completeness` value.

Current meanings include:

- `retained` — first-class normalized dataset retained for exact replay;
- `retained-summary` — exact bounded singleton/context material that can be reused as declared;
- `bounded-transport` — historical compact transport that may omit rows and therefore cannot support exact rules that depend on full collection membership.

The most important historical example is `networkEndpoints`. A 2.14 compact report can preserve useful endpoint rows for research/UI, but because transport compaction was bounded, Phase 4 will not pretend it is a complete endpoint universe.

The first Phase-7 migration also makes **empty-collection completeness** explicit. New scanners publish `dependencyIntelligence.staticPatternMatchContractVersion=1`. When that marker is present, Evidence-v2 freezes `staticPatternMatches` even when it contains zero rows, proving that the plugin was scanned under the producer contract and no configured literals matched. Historical reports without the marker are not interpreted as empty: the collection is missing and any rule that requires it must request targeted re-analysis.

`staticPatternMatches` rows intentionally contain only the matched canonical literal plus origin/evidence location. They contain no legacy rule ID, severity, capability or finding conclusion. Changing the producer's literal vocabulary is therefore an analysis-semantic change requiring a new provider revision and, where needed, targeted re-analysis.

## Replay audit

Before a future SRL rule is evaluated over retained evidence, the rule declares the logical collections it requires. DeltaScope/production can then run `omega.sigmascope.projection-replay-audit.v1`.

The audit returns:

- required collections;
- missing collections;
- bounded compatibility collections;
- forbidden derived inputs;
- `reusableWithoutRescan`;
- `rescanRequired` and an explicit reason.

Examples:

```text
required: managedCallSites + managedReachability
both retained exactly
=> reusableWithoutRescan = true
```

```text
required: networkEndpoints
only historical bounded compact transport exists
=> reusableWithoutRescan = false
=> targeted re-analysis required for an exact endpoint-universe rule
```

```text
required: behaviorConsistency
=> forbidden derived input
=> rule must be rewritten against underlying observations + developerProfile
```

A Definitions/rule change by itself is never a rescan reason. The reason is the specific missing/incompatible observation primitive.

The first concrete implementation of this rule is DeltaScope `rule-replay`. It can replay the reviewed primitive/compound migration chain only where `staticPatternMatches` is retained completely. It reads historical `findings` only to compare the replayed output with the old baseline; findings are never passed into SRL as observations or facts.

## Projection identity

`projectionRevision` identifies the deterministic evaluator contract plus rule-set/capability-registry identity. It intentionally does **not** hash the output findings as its identity.

That distinction allows two plugins with different outputs to be evaluated by the same projection revision, and allows a rule-set change to advance the projection identity even when a particular plugin happens to produce the same output.

Output counts/digests are retained separately for reproducibility.

## Migration rule from live 2.14

When the user intentionally ends the current 2.14 collection period and the full 2.15 architecture is ready:

1. freeze/retain the last-known-good 2.14 Evidence-v2 snapshot;
2. build the final 2.15 Daily Catalog/Definitions once;
3. adapt every retained active variant to the observation contract without rescanning;
4. run replay audits for the final production rule set;
5. re-project variants whose required collections are complete;
6. enqueue **only** variants whose required collections are missing, bounded or semantically incompatible;
7. preserve historical/terminal evidence and artifact identities throughout.

This is the core anti-mass-rescan invariant for the 2.14 -> 2.15 migration.

## DeltaScope author workflow today

Rule authors can inspect the exact boundary now even though SRL execution is not implemented yet:

```bash
python tools/security/deltascope.py observation-schema
python tools/security/deltascope.py rule-schema
python tools/security/deltascope.py capabilities
```

`observation-schema` is the authority for what is a legal future production input. `rule-schema` describes concrete author-facing fields currently available in DeltaScope. When they disagree about whether a derived surface is suitable for production SRL, the observation boundary wins.

The future Rule Lab must perform a replay audit before executing candidate YAML and show the author whether the selected plugin can be evaluated exactly from retained evidence or requires a targeted re-analysis.

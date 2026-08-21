# SigmaScope data reference for rule authors

Two machine-readable contracts govern this document:

```bash
python tools/security/deltascope.py observation-schema
python tools/security/deltascope.py rule-schema
```

`omega.deltascope.observation-reference.v1` is the **production-input authority**: it names the logical collections that future SRL may consume and their replay/completeness semantics. `omega.deltascope.rule-author-reference.v1` documents concrete current DeltaScope/Evidence fields that authors can inspect. It remains `author-reference-pre-srl` until the compiler/evaluator is implemented.

Rules should address logical collection names, not Evidence-v2 file paths. Physical backings are documented only to help researchers trace evidence. See `../OBSERVATION-PROJECTION-CONTRACT.md`.

## Data classes

Not every collection has the same authority. Keep these classes separate when designing rules:

- **Immutable normalized observations**: concrete static facts extracted from artifact/source material, such as call sites, reachability rows, imports, dependencies and IPC endpoints.
- **Derived capability candidates**: current SigmaScope interpretations such as permission candidates and automation capabilities. These are useful during migration but should not become a recursive "finding matches finding" rule graph.
- **Provenance evidence**: source attribution and source-to-artifact confidence/verification state.
- **Developer declarations**: `.omega/plugin.yaml` context. Untrusted, separately labelled, consistency-only.
- **Secondary security evidence**: YARA/ClamAV results. Supplemental hygiene evidence, not a replacement for native observations.

## `managedCallSites`

Persisted dataset/table: `calls` / `plugin_security_managed_calls`.

Fields include:

- `origin`
- `path`
- `sourceMethodToken`
- `sourceDeclaringType`
- `sourceMethodName`
- `ilOffset` (integer)
- `opcode`
- `targetToken`
- `targetKind`
- `targetDeclaringType`
- `targetName`
- `targetAssemblyName`
- `targetNativeLibrary`
- `targetNativeEntryPoint`
- `targetMethodToken`
- `evidence[]`

This is one of the strongest inputs for managed-code behavior rules. **Same-record semantics are mandatory**: a selector requiring `targetDeclaringType = System.Diagnostics.Process` and `targetName = Start` must match those fields on one call-site row, not one field from each of two unrelated rows.

## `managedReachability`

Persisted dataset/table: `reachability` / `plugin_security_managed_reachability`.

Fields:

- `origin`
- `path`
- `methodToken`
- `depth` (integer)
- `rootMethodToken`
- `evidence[]`

Reachability means SigmaScope found a bounded static call path from a known lifecycle/callback root. It raises evidence confidence but does not prove that a runtime branch was taken.

## `nativeImports`

Logical Phase-4 collection: `nativeImports`. New 2.15 evidence retains `dependencyIntelligence.nativeImports` as a first-class immutable `nativeImports` analysis dataset; managed P/Invoke call targets remain a second concrete source visible through managed call evidence. Historical 2.14 evidence can only replay this collection exactly when equivalent retained data is present.

Fields:

- `origin`
- `path`
- `library`
- `entryPoint`
- `evidence[]`

Use concrete library/entry-point pairs when possible. Import presence is static capability evidence only.

## `permissionCandidates`

Persisted compatibility projection: `permissions` / `plugin_security_permission_candidates`. **Not a legal future raw SRL observation input.**

Fields:

- `origin`
- `permissionId`
- `risk`
- `confidence`
- `reason`
- `evidence[]`

This is already derived data. It is useful for comparing today's hard-coded scanner behavior while migrating rules, but Phase 4 marks the backing dataset `semanticClass: projection` and `srlEligible: false`. Production SRL must use the lower-level observation collection(s) that justify the capability.

## `automationCapabilities`

Persisted compatibility projection: `automation` / `plugin_security_automation_capabilities`. **Not a legal future raw SRL observation input.**

Fields:

- `capabilityId`
- `label`
- `automationLevel`
- `confidence`
- `reachable` (boolean)
- `indirect` (boolean)
- `reason`
- `evidence[]`

Again, this is derived capability data. Phase 4 classifies it as projection-only. Use it to prove migration parity, not as a production selector source; future automation rules must query the underlying call/IPC/other registered observations.

## `dependencies`

Persisted dataset/table: `dependencies` / `plugin_security_dependencies`.

Fields include:

- `origin`
- `kind`
- `name`
- `version`
- `versionRequirement`
- `resolvedVersion`
- `path`
- `status`
- `requirement`
- `relationship`
- `relationshipConfidence`
- `evidence[]`

OSV vulnerability matching remains a separate frozen advisory system. SRL may reason about dependency/component relationships but should not duplicate OSV's job.

## `ipcIntegrations`

Persisted dataset/table: `ipc` / `plugin_security_ipc_endpoints`.

Fields:

- `origin`
- `role`
- `channel`
- `signature`
- `path`
- `status`
- `relationship`
- `relationshipConfidence`
- `evidence[]`

Use this for explicit producer/consumer relationships and, later, deterministic automation-via-IPC correlation.

## `networkEndpoints`

Logical Phase-4 collection: `networkEndpoints`. New 2.15 analyses retain the full normalized `dependencyIntelligence.networkEndpoints` rows as a first-class `networkEndpoints` dataset before public report compaction.

Historical 2.14 compact Evidence may expose endpoint rows only through a bounded transport summary. Phase 4 marks that compatibility view `completeness: bounded-transport`; it is useful for research/UI but cannot support an exact rule that depends on the full endpoint universe. Such a rule receives a targeted re-analysis requirement instead of treating omitted rows as absent.

Fields:

- `url`
- `host`
- `origin`
- `originType`
- `classification`
- `purpose`
- `confidence`
- `concreteDestinationEvidence` (boolean)
- `evidence[]`

Concrete destination evidence is stronger than a generic network capability. URLs persisted by SigmaScope are sanitized; credentials/query/fragment and secret-like webhook path material are not intended to become rule-author secrets.

## `sourceAttribution`

Compact source evidence: `source.attribution`.

Fields:

- `confidence` (integer, based on the 0/40/70/95/100 model)
- `coverageLabel`
- `basis[]`

Do not use a developer-provided source link as proof of source↔artifact identity. Attribution is computed independently.

## `sourceProvenance`

Compact source evidence: `source.provenance`.

Fields include:

- `selectedRef`
- `selectedRefKind`
- `identityMatched`
- `versionMatched`
- `manifestRepositoryMatched`
- `artifactOriginMatched`
- `sourceToBinaryVerified`
- `reproducibleSourceToArtifact`

A source repository being found is not the same thing as reproducible source-to-artifact verification.

## `developerProfile`

Logical Phase-4 collection: `developerProfile`. Source: `source.developerProfile.profile`, contract `omega.plugin-profile.v1` inside an `omega.plugin-profile-observation.v1` wrapper. New 2.15 analyses retain the bounded profile observation as its own dataset; historical compact transport may provide an exact retained summary when available.

Relevant fields include:

- `profile.tagline`
- `profile.description`
- `capabilities[].id`
- `capabilities[].expected`
- `capabilities[].required`
- `capabilities[].reason`
- `capabilities[].destinations[]`
- `services[].url`
- `services[].purpose`
- `nativeComponents[].name`
- `ipc[].plugin`
- `ipc[].channel`

This is **untrusted developer declaration data**. It may support rules such as "observed capability was explicitly marked not expected" or "observed concrete host is unexplained by declared service/destination context." It must never suppress, lower or erase scanner evidence.

## `secondarySecurity`

Logical Phase-4 collection: `secondarySecurity`, with `semanticClass: hygiene-evidence` and `authority: supplemental-only`. New 2.15 analyses retain the bounded secondary-engine result object as an observation dataset. It contains fields such as:

- `engines[].engine`
- `engines[].status`
- `engines[].matches[]`
- `matchCount`

YARA and ClamAV stay their own engines. Do not port byte signatures into SRL merely because SRL can see their bounded outcomes.

## `behaviorConsistency`

**Class:** derived presentation/research projection.

**Schema:** `omega.sigmascope.behavior-consistency.v1`.

This collection compares `developerProfile` claims with independent canonical capability and concrete endpoint observations. It exposes capability comparison states and explained/unexplained destination summaries so rule authors can inspect current behavior-transparency output in DeltaScope.

Important: **do not design production SRL rules that consume this collection.** It is already a derived conclusion. Production consistency rules should consume the underlying observation collection(s) plus `developerProfile` directly to prevent conclusion-on-conclusion recursion.

Useful fields for inspection include `profileAvailable`, `summary.*`, `capabilities[].id`, `capabilities[].state`, `capabilities[].observed`, `capabilities[].declared`, `capabilities[].expected`, `destinations.explained[]`, `destinations.unexplained[]`, and `destinations.declaredNotObserved[]`. The machine-readable `deltascope.py rule-schema` output is authoritative for the current field/type contract.

## Registered observation collections without a dedicated author-facing field section yet

`deltascope.py observation-schema` already reserves stable logical Phase-4 identities for several retained inputs that do not yet have a polished SRL field schema in `rule-schema`, including:

- `namespaceImports`;
- `managedAssemblies`;
- `managedSymbols`;
- `sourceFiles`;
- `binaryClassifications`;
- `artifactIdentity`;
- `manifestObservation`.

Do not guess field syntax from the raw JSON files. Until the Phase-5 compiler publishes a typed field registry for a collection, use the raw rows for research/fixture design only and propose the required typed fields as part of the SRL/observation-contract work.

Additional future observations such as package-member facts, raw bounded indicators, Dalamud service observations, filesystem path observations and richer component relationships must first be added as bounded registered collections. A rule must never gain arbitrary filesystem/network/code access just because its desired input is missing.

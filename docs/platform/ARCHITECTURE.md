# Security architecture

Omega separates collection, observation, interpretation and publication so that a failure or assumption in one layer does not silently become authoritative everywhere else.

## Main components

### Component Registry

The Component Registry (`omega.component-registry.v1`) defines deployable/trust-boundary services separately from collectors. It records component ownership, branch, execution class, authority, launchability and whether a component can currently accept an implementation-neutral Analysis Broker request. The daily Definitions snapshot freezes the exact component and collector registry revisions used by Stigma-1 and orchestration.

### Analysis Broker

The Analysis Broker accepts `omega.analysis-request.v1` requests for logical observation types, resolves collector/component providers, applies freshness/reuse policy and retains bounded durable state. It does not invoke scanner workflows. The `omega.analysis-dispatcher` queue runner on `main` atomically reserves a bounded set of eligible items with leases, persists those leases before launch, then asynchronously starts explicit allow-listed worker workflows. Other dispatcher runs see the same in-flight leases and can fill only remaining global/per-component capacity; queue data never selects an arbitrary workflow path.

### Omega client

The in-game client is the user-facing discovery and installation experience. It consumes catalog and security information. It is not the security scanner and does not independently re-interpret scanner evidence.

### Omega Discovery

Omega Discovery (`omega.discovery`) is the ecosystem-intelligence component. Its bounded collectors search public indexes, PluginMaster feeds, project/README links, repository trees and source issues, then publish provenance-backed candidate observations. It runs independently of security analysis and has no catalog identity or security authority.

### Catalog services

Catalog services reconcile discovery observations, configured sources and the prior canonical snapshot into plugin identities, variants, manifests, project metadata, tags, source references and installable artifact URLs. The catalog defines **what plugin variant exists and what artifact should be inspected**.

### SigmaScope

SigmaScope performs bounded static inspection of the selected installable artifact and attributable source evidence. It retains observations such as managed calls, native imports, endpoints, dependencies, IPC relationships, capability candidates and secondary-engine results.

SigmaScope is intentionally non-executing for ordinary artifact analysis. Static analysis should not be described as proof that a code path executed at runtime.

### Security Definitions

Definitions are frozen, reviewable inputs used by scanners and rule evaluation. They can contain capability vocabulary, reviewed Definition Packs, YARA policy/rules, advisory data and other code-owned security inputs.

### Stigma-1 / SRL Core

Stigma-1 evaluates deterministic SRL rules over registered observation collections and typed facts. Rules cannot execute shell commands, make arbitrary network requests or reach into the filesystem. The evaluator only exposes the bounded data model registered by the platform.

### Deep Scan

Deep Scan is a separate evidence-acquisition workflow. A rule may request more analysis by emitting a typed `analysisRequest`, but the allowed analysis profile, runner behavior, time budget and network/execution policy are owned by platform code.

### Security Evidence v2

Security Evidence v2 is the publication boundary. It keeps current plugin state, immutable analyses, historical snapshots, indexes, queue state and provenance identities distinct.

### DeltaScope

DeltaScope is the human workbench over published evidence and local rule authoring. Its perspectives change the workflow and presentation, not the underlying evidence.

### Rift and Alpha

Rift is a separate branch-level experimental execution environment. Alpha is a component inside Rift. Rift is not part of the normal SigmaScope production scan path.

## Data flow

```text
Public ecosystem / search indexes / project pages / issues
        ↓
Omega Discovery collectors
        ↓
Typed candidate observations + provenance
        ↓
Catalog normalization / canonical identity
        ↓
Active plugin variant + installable artifact
        ↓
Component Registry + Collector Registry
        ↓
Stigma-1 may request additional logical observations
        ↓
Analysis Broker ── freshness/reuse ── durable request state
    │
    └── Analysis Dispatcher ── lease/claim ── static main route
        │
        └── main control plane launches only compatible component workflows

SigmaScope artifact/source analysis ────────┐
        ↓                                    │
Secondary security evidence                 │
        ↓                                    │
Registered observations                     │
        ↓                                    │
Stigma-1 rules                               │
        ↓                                    │
Optional bounded extra analysis ────────────┘
        ↓
Security Evidence v2
        ↓
DeltaScope / Omega
```

## Authority boundaries

| Data | Who can produce it | What it means |
| --- | --- | --- |
| Component definition | Component Registry | Deployment/trust-boundary metadata; never a security verdict |
| Analysis request/work item | Analysis Broker | Request/queue state only; does not execute providers |
| Discovery observation | Omega Discovery collectors | Candidate public fact with collector provenance; not canonical identity |
| Catalog metadata | Canonical catalog builder | Identity, source, manifest and presentation data |
| Artifact observations | SigmaScope | Static observations from the selected installable artifact |
| Source observations | Source-analysis pipeline | Evidence from attributed public source |
| Developer profile | Plugin developer | Explanatory declaration only |
| Secondary-engine result | YARA/ClamAV/OSV pipeline | Supplemental security evidence |
| SRL fact/finding | Stigma-1 | Deterministic interpretation of registered observations |
| Deep-scan result | Deep Scan worker | Additional bounded evidence |
| Published current state | Evidence publication | Current active plugin security projection |
| Historical snapshot | Evidence publication | Archive evidence, excluded from current headline totals |

## Fail-closed behavior

Where evidence integrity or authority is uncertain, the platform should stop or mark the data incomplete instead of silently weakening a check. Examples include:

- Evidence-v2 hash mismatch;
- invalid or incompatible Definitions;
- missing required observation collections for exact rule replay;
- incomplete secondary-engine coverage;
- unreviewed local rule candidates;
- source attribution that cannot be verified;
- analysis requests that do not match a code-owned profile.

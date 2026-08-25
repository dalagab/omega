# Omega Discovery

Omega Discovery is the ecosystem-intelligence component that continuously looks for public Dalamud plugin and source facts. It is deliberately separate from catalog identity, security scanning, rule evaluation and client publication.

Its component identity is `omega.discovery`. Collector implementations under that component publish typed observations through `omega.collector-registry.v1`.

## Responsibility

Omega Discovery answers **what public facts might exist?** It does not answer **what is the canonical plugin identity?** and it does not answer **is this plugin safe?**

The normal scheduled run is every six hours. The replaceable `catalog-discovery` snapshot is an inbox of provenance-backed candidates for the next canonical catalog reconciliation.

## Collector graph

Discovery can obtain candidates from several bounded sources:

- curated and validated community source registries;
- Puni repository-directory discovery;
- GitHub code search for Dalamud JSON signatures;
- canonical plugin project/README links already retained by catalog enrichment;
- bounded GitHub repository-tree inspection for likely manifests;
- bounded Omega source-submission/follow-up issue hints;
- an optional configured public web-search API using a deterministic query set;
- the production PluginMaster parser, which validates only novel source candidates and classifies new plugin/source facts.

Known canonical source URLs are checked before network validation so discovery does not repeatedly fetch them merely to prove they still exist. Newly validated feeds are retained as short-lived normalized shards so the next catalog build can reuse the parse instead of downloading the same feed again.

## First-class collector contract

A collector has a stable implementation identity, for example:

```text
omega.collector.discovery.project-page
omega.collector.discovery.github-code-search
omega.collector.discovery.repository-tree
omega.collector.discovery.pluginmaster-validator
```

Collectors advertise logical observation types rather than giving rules callable implementation hooks. Current discovery observation types include:

- `catalogSourceCandidates`
- `catalogPluginFacts`
- `catalogProjectLinks`
- `catalogRepositoryCandidates`
- `catalogManifestCandidates`
- `catalogIssueHints`

Each retained row carries `_collector` metadata and bounded `_provenance`. The registry declares which collector versions may provide which observation types.

## Stigma-1 binding

Stigma-1 rules bind to the **logical observation type**, not the collector implementation ID. This keeps rules stable when a new provider is added or an existing implementation changes.

A rule can also emit a typed `observationRequest` when another observation class would be useful:

```yaml
observationRequest:
  collection: catalogRepositoryCandidates
  reason: Resolve a repository candidate for the newly observed plugin.
  priority: 700
```

Stigma-1 only resolves the request to registered provider candidates. Rule evaluation performs no network request and executes no collector. `collectorId` is intentionally forbidden in an observation request; execution authority belongs to orchestration.

## Authority boundary

Omega Discovery has no authority to:

- assign or change plugin/source IDs;
- retire canonical catalog records;
- freeze Definitions;
- create or modify security findings;
- change severity or trust policy;
- enqueue or execute SigmaScope work;
- publish Security Evidence v2;
- publish the Omega client database;
- execute Stigma-1 observation requests.

The daily catalog process reconciles discovery observations with the existing canonical `catalog-data` snapshot. Network failure or absence in a discovery run does not delete previously known canonical data.

## Downstream flow

```text
public ecosystem
      ↓
Omega Discovery collectors
      ↓
typed candidate observations + provenance
      ↓
replaceable catalog-discovery snapshot
      ↓
daily canonical catalog reconciliation
      ↓
catalog-data
   ├── fresh Omega client projection
   └── immutable SigmaScope queue seed
             ↓
          SigmaScope
             ↓
      Security Evidence v2
```

Security remains event-driven. A discovery observation only becomes security work after the canonical catalog accepts a relevant change and the queue logic determines that an artifact/source/analysis input actually changed.

## Future Rift relationship

The same collector contract is intended to cover runtime observations from Rift. `omega.collector.rift.runtime` is reserved as a planned provider identity, but it is not currently an active observation provider. Alpha remains a component inside Rift. Runtime collector activation requires a separate production design and safety boundary.

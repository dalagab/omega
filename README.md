# SigmaScope security services

**SigmaScope 2.15.0** is the producer/authority side of Omega's security platform.

This source tree is intentionally independent from DeltaScope. It owns artifact/source analysis, retained observations, frozen Definitions, Stigma-1/SRL production integration, Analysis Broker/dispatcher state, Deep Scan, Security Evidence v2 validation/publication, Discovery contracts, threat-intelligence collection, and the platform registries/contracts consumed by external tools.

DeltaScope is now a separate Python source tree. SigmaScope may publish descriptive/versioned data for it, but SigmaScope must never import DeltaScope application code, local Investigator state, My Rules state, or the DeltaScope consumer SDK.

## Authority boundary

SigmaScope owns or participates in production security authority:

- scan and source-analysis execution;
- Security Evidence v2 candidate validation and publication;
- frozen Definitions and SRL Definition Pack publication;
- Stigma-1 production rule evaluation/reprojection;
- Analysis Broker and dispatcher contracts;
- Deep Scan queue/state;
- component, collector/provider, capability and execution-topology registries;
- Discovery and threat-intelligence producer contracts.

DeltaScope consumes these outputs read-only. Production security decisions must never depend on DeltaScope state.

## Published consumer contracts

The supported cross-tree boundary is data, not Python imports. Frozen Definitions may publish, among other resources:

- `platform/component-registry.json`
- `platform/collector-registry.json`
- `platform/execution-topology.json`
- `capabilities/registry.json`
- `srl/index.json` and its hash-pinned rule/fixture resources
- the compiled SRL ruleset
- Security Evidence v2 indexes and relationship/provenance contracts

New components, providers, observation types, capabilities or execution nodes should extend those contracts. They should not require a DeltaScope code change merely to become discoverable.

## Development

Security-service dependencies remain pinned in:

```text
tools/requirements-security.txt
```

The repository regression workflows install external scanner dependencies such as YARA/ClamAV where required. Local tests that compile-check enabled YARA policy require a `yara` executable on `PATH` and intentionally fail closed if it is absent.

The physical split rules are summarized in `DEVELOPMENT-BOUNDARY.md`. The remaining platform roadmap is in `docs/platform/MISSING-COMPONENTS.md`.

## DeltaScope

DeltaScope 4.21.8 is delivered as the sibling `deltascope/` source root in the split handoff package. It can be moved to a dedicated `deltascope` branch and developed independently from this tree.

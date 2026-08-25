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

## First-class collectors

SigmaScope collectors are observation producers, not security verdict engines. The collector registry describes what each provider can observe, and retained results are bound to exact subjects and collector/observation contract revisions.

The first specialist lane is `omega.collector.sigmascope.authenticode`: exact artifacts containing retained native PE classifications can be queued for Windows-native Authenticode validation. The lane never executes plugin binaries; it validates the artifact SHA-256, safely extracts bounded PE members, asks Windows for Authenticode status/certificate information, and retains `binarySignatureTrust` observations through the generic collector-result/Evidence-v2 path. Windows platform-trust results are reusable for seven days; they are not treated as permanently immutable because hosted trust policy can change.

The native-structure lane provides `elfBinaryStructure` and `machOBinaryStructure` for exact artifacts containing retained ELF/Mach-O classifications. It is a pure bounded parser: ELF observations retain loader dependencies, interpreter, RPATH/RUNPATH, PIE/RELRO/bind-now/executable-stack state and bounded dynamic symbols; Mach-O observations retain dylib/rpath/load-command metadata, architecture slices, code-signature presence and segment protections. These are structural observations only and do not assign trust or malware verdicts.

## Source build and dependency observations

The existing `omega.collector.sigmascope.source-analysis` provider also retains bounded build context from the selected plugin source graph without executing source code or build commands. The source-only `omega.sigmascope.source-build-intelligence.v1` contract publishes six logical observation collections: project/build nodes, project-reference edges, hashed build inputs, SDK/package-policy context, managed dependency declarations/lock identities, and relevant CI/release construction metadata.

These observations are source context, not build provenance. Seeing a project, dependency declaration, or release workflow does **not** prove that it produced the distributed artifact; exact source-to-artifact reproducibility remains the separate future Rebuilder boundary. Arbitrary CI command bodies and NuGet credential fields are not retained, and package-source URLs are sanitized before entering evidence. Changes to this collector are source-analysis-only and must not invalidate artifact-analysis coverage.

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

# Omega

[![Latest Omega release](https://img.shields.io/github/v/release/dalagab/omega?display_name=tag&sort=semver&label=Omega%20release)](https://github.com/dalagab/omega/releases/latest)
[![Omega client regression tests](https://github.com/dalagab/omega/actions/workflows/regression-tests.yml/badge.svg?branch=omega)](https://github.com/dalagab/omega/actions/workflows/regression-tests.yml?query=branch%3Aomega)
[![SigmaScope production drain](https://github.com/dalagab/omega/actions/workflows/sigmascope-drain-wake.yml/badge.svg?branch=sigmascope)](https://github.com/dalagab/omega/actions/workflows/sigmascope-drain-wake.yml?query=branch%3Asigmascope)
[![Omega website deployment](https://github.com/dalagab/omega/actions/workflows/pages.yml/badge.svg?branch=website)](https://github.com/dalagab/omega/actions/workflows/pages.yml?query=branch%3Awebsite)

**Omega is a discovery and security-information layer for public Dalamud plugins.** It brings plugin sources into one marketplace, shows provenance and published security findings, and hands installation back to Dalamud.

[Install Omega](https://dalagab.github.io/omega/#install) | [Open the website](https://dalagab.github.io/omega/) | [View releases](https://github.com/dalagab/omega/releases) | [Get support on Discord](https://discord.gg/rMBHbJTjp)

> A plugin appearing in Omega is not an approval or safety guarantee. Omega publishes evidence and context so users can make better-informed decisions.

## Omega and the Omega Protocol

**Omega** is the user-facing Dalamud client and marketplace. The **Omega Protocol** is the wider collection of tools, evidence formats, and authority boundaries that discover plugins, analyze them, explain findings, and preserve reproducible security records.

| Component | What it does | Where it lives |
| --- | --- | --- |
| **Omega** | Browses plugins, presents sources and security context, and coordinates installation through Dalamud. | [`omega`](https://github.com/dalagab/omega/tree/omega) |
| **SigmaScope** | Performs deterministic static analysis of plugin artifacts and attributable source material. | [`sigmascope`](https://github.com/dalagab/omega/tree/sigmascope) |
| **Stigma-1 / SRL** | Evaluates reviewed, deterministic rules over normalized observations. | [Rule documentation](https://github.com/dalagab/omega/tree/sigmascope/docs/rule-authors) |
| **DeltaScope** | Provides read-only developer, investigator, researcher, and operator views over published evidence. | [Security documentation](https://github.com/dalagab/omega/tree/sigmascope/docs) |
| **Interdimensional Rift** | Runs approved deep investigations in an isolated runtime-observation environment. | [`rift`](https://github.com/dalagab/omega/tree/rift) |
| **Alpha** | Supplies controlled fixtures for integration, calibration, and containment testing. | [`alpha`](https://github.com/dalagab/omega/tree/alpha) |
| **Roboscope** | Provides the remote operations interface used around SigmaScope services. | [`dalagab/Roboscope`](https://github.com/dalagab/Roboscope) |

```text
public plugin sources and artifacts
             |
      catalog and discovery
             |
        SigmaScope
    static observations
             |
      Stigma-1 rules
             |
   Security Evidence v2
       /           \
      v             v
Omega client     DeltaScope
+
Approved deeper investigation may additionally use the Rift.
```

The platform separates observations from conclusions, current state from historical evidence, and developer explanations from scanner authority. Start with the [platform overview](https://github.com/dalagab/omega/blob/sigmascope/docs/platform/README.md), [security architecture](https://github.com/dalagab/omega/blob/sigmascope/docs/platform/ARCHITECTURE.md), and [evidence lifecycle](https://github.com/dalagab/omega/blob/sigmascope/docs/platform/EVIDENCE-LIFECYCLE.md).

## I am a plugin developer

Omega can show you what users and reviewers see about your plugin: active source variants, artifact identity, scan coverage, capabilities, endpoints, dependencies, findings, source attribution, and changes between versions.

### Add or describe your plugin

- [Submit a public PluginMaster feed](https://github.com/dalagab/omega/issues/new?template=plugin-source.yml). Accepted sources enter the normal catalog and security pipeline; submission is not an endorsement.
- Use the [PluginMaster manifest template](https://github.com/dalagab/omega/blob/main/repository/pluginmaster.template.json) when you need a concrete feed example.
- Add an optional [`.omega/plugin.yaml` profile](https://github.com/dalagab/omega/blob/sigmascope/docs/plugin-developers/examples/plugin.yaml) to explain expected capabilities, network destinations, native components, IPC use, documentation, support, and vulnerability-reporting links.
- Read the [Plugin Developer guide](https://github.com/dalagab/omega/blob/sigmascope/docs/plugin-developers/README.md) and [Omega plugin profile reference](https://github.com/dalagab/omega/blob/sigmascope/docs/OMEGA-PLUGIN-PROFILE.md).

A developer profile adds context; it cannot mark a plugin safe, suppress a finding, reduce severity, override independent evidence, or prove that public source produced a shipped artifact.

### Understand or correct a finding

Use DeltaScope to inspect what was observed, which rule produced a finding, what the evidence does and does not establish, and whether the result belongs to the current artifact or retained history. Stable tags, public build instructions, checksums, and source-to-artifact traceability make the record more useful.

If the evidence or classification is wrong, [report an incorrect scanner result](https://github.com/dalagab/omega/issues/new?template=scanner-result.yml). Include the plugin version, artifact or variant identity, finding or rule ID, expected result, and public evidence. Detector repairs should apply consistently to every plugin rather than create one-off exceptions.

## I am a security researcher

The platform retains artifact identities, observations, findings, dependencies, endpoints, provenance, rule projections, source coverage, and historical snapshots. DeltaScope presents that material without authority to rewrite production evidence.

- [Security Researcher guide](https://github.com/dalagab/omega/blob/sigmascope/docs/security-researchers/README.md) - ecosystem-wide analysis and research discipline.
- [Investigator guide](https://github.com/dalagab/omega/blob/sigmascope/docs/investigators/README.md) - investigation of one plugin or signal.
- [Finding lineage](https://github.com/dalagab/omega/blob/sigmascope/docs/platform/FINDING-LINEAGE.md) - tracing conclusions through observations and rule evaluation.
- [Detection coverage](https://github.com/dalagab/omega/blob/sigmascope/docs/platform/DETECTION-COVERAGE.md) - collection gaps and stale producers.
- [Rule authoring](https://github.com/dalagab/omega/blob/sigmascope/docs/rule-authors/README.md) and [SRL reference](https://github.com/dalagab/omega/blob/sigmascope/docs/SIGMASCOPE-RULE-LANGUAGE.md) - local rule development and replay.
- [Extending Omega security logic](https://github.com/dalagab/omega/blob/sigmascope/docs/platform/EXTENDING-OMEGA.md) - collectors, observations, capabilities, rules, Definition Packs, YARA, and classification.

Static capability evidence is not automatically proof of runtime behavior. Absence is meaningful only when the relevant observation coverage is complete, and source claims remain separate from artifact claims unless correspondence is verified.

Report sensitive vulnerabilities through [GitHub private vulnerability reporting](https://github.com/dalagab/omega/security/advisories/new). Do not disclose an issue publicly if doing so could place users at risk before a repair is available.

## I want to help build the platform

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Choose the branch that owns the component:

| Branch | Owned source or state |
| --- | --- |
| [`main`](https://github.com/dalagab/omega/tree/main) | Default-branch workflow registrations, release-facing files, issue forms, and this landing page. |
| [`omega`](https://github.com/dalagab/omega/tree/omega) | Omega Dalamud client and regression tests. |
| [`sigmascope`](https://github.com/dalagab/omega/tree/sigmascope) | SigmaScope, DeltaScope, Stigma-1/SRL, catalog tooling, Definitions, orchestration, and platform documentation. |
| [`rift`](https://github.com/dalagab/omega/tree/rift) | Runtime observation, sandboxing, containment fixtures, and Rift documentation. |
| [`website`](https://github.com/dalagab/omega/tree/website) | Public website source and build tooling. |
| [`catalog-data`](https://github.com/dalagab/omega/tree/catalog-data) | Generated catalog, Definitions projection, and queue state. Do not edit as ordinary source. |
| [`security-evidence-v2`](https://github.com/dalagab/omega/tree/security-evidence-v2) | Generated evidence and indexes. Do not edit as ordinary source. |
| [`deep-scan-state`](https://github.com/dalagab/omega/tree/deep-scan-state) | Generated deep-scan state. Do not edit as ordinary source. |

Scheduled and manually dispatched workflows must be registered on the default branch, but several `main` workflows delegate to the branch that owns the implementation. The [Actions page](https://github.com/dalagab/omega/actions) is the authoritative view of individual runs. The badges at the top intentionally follow the owning branches: client regression on `omega`, the production drain on `sigmascope`, and website deployment on `website`. They report those specific contracts, not a single platform-wide health verdict.

## Project links

| Need | Destination |
| --- | --- |
| Install or use Omega | [Omega website](https://dalagab.github.io/omega/) |
| Submit a plugin source | [Plugin source form](https://github.com/dalagab/omega/issues/new?template=plugin-source.yml) |
| Correct a scanner result | [Scanner result form](https://github.com/dalagab/omega/issues/new?template=scanner-result.yml) |
| Report a vulnerability privately | [Security advisory](https://github.com/dalagab/omega/security/advisories/new) |
| Review workflow runs | [GitHub Actions](https://github.com/dalagab/omega/actions) |
| Ask for help | [Omega Discord](https://discord.gg/rMBHbJTjp) |

Omega is an independent community project. It is not affiliated with Square Enix, Dalamud, XIVLauncher, or FINAL FANTASY XIV.

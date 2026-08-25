# Omega security platform

Omega is a plugin-discovery and security-evidence platform for the Dalamud ecosystem. The user-facing Omega client, catalog services, SigmaScope scanner, Stigma-1 rule system, DeltaScope workbench, Definitions, and supporting collectors all contribute to one evidence model.

This documentation describes the platform by **purpose and responsibility**. It intentionally avoids development-history language. If a component exists in this manual, the important question is what it owns, what it consumes, what it produces, and where its authority stops.

## The platform at a glance

1. **The Component Registry describes deployable/trust-boundary services.** It records ownership, branch, execution class, authority, launchability and whether a component can currently accept a generic broker request.
2. **The Analysis Broker resolves logical observation requests.** It uses the component/collector registries, freshness policy and durable state; it never executes components itself.
3. **The Analysis Dispatcher is a leased worker-pool runner on `main`.** It atomically reserves bounded parallel capacity, persists every lease before launch, asynchronously starts only explicit static component workers, and settles/retries each exact claim; it never chooses providers or accepts a workflow path from queue data.
3. **Omega Discovery continuously maps the public plugin ecosystem.** First-class collectors find PluginMaster feeds, project/README links, repository manifests, issue hints and optional web-search candidates, publishing typed observations without catalog/security authority.
4. **Other collectors acquire security and supporting intelligence.** They obtain source revisions, dependency intelligence and external advisory data.
5. **The catalog identifies plugins and active variants.** It preserves source attribution, metadata, tags, artifact URLs and lifecycle state.
6. **SigmaScope acquires and inspects the installable artifact.** It performs bounded static analysis and retains typed observations.
7. **Source analysis adds attributable source evidence when available.** Source and artifact are kept as separate evidence domains unless correspondence can actually be proven.
8. **Secondary security engines add supplemental evidence.** YARA, ClamAV and OSV-derived intelligence supplement the scanner; they do not erase other observations.
9. **Stigma-1 evaluates deterministic rules over registered observations and facts.** Rules are data, not arbitrary executable code.
10. **Deep Scan can acquire more evidence when an approved rule requests it.** Deep-analysis profiles and budgets are code-owned and bounded.
11. **Security Evidence v2 publishes the retained result.** Current plugin state, immutable analyses, history, provenance and indexes are separated so consumers can distinguish current risk from archive evidence.
12. **DeltaScope provides human access to the evidence.** Different perspectives show the same evidence for plugin developers, investigators, security researchers and operators.
13. **Omega consumes the resulting security context in the plugin-discovery experience.**

## Core principles

### Artifact first

The installable plugin artifact is the primary object of security inspection. Public source code is valuable evidence, but source availability alone does not prove what users downloaded.

### Observations before conclusions

The platform distinguishes low-level observations from derived findings. A retained URL literal, managed call, native import or dependency is evidence. A finding is a deterministic interpretation of one or more observations.

### Current state and archive history are different

Dashboard severity, current findings and plugin status are calculated from the **current active variant and current scan**. Older versions remain available for comparison and research, but historical risky behavior does not keep a current plugin marked HIGH or CRITICAL.

### Coverage and severity are separate

A plugin can have low severity but incomplete source coverage. A plugin can have high severity while being thoroughly reviewed. DeltaScope presents both dimensions separately.

### Developer context is explanatory, not authoritative

A developer can provide `.omega/plugin.yaml` to explain expected capabilities, destinations and project metadata. That declaration cannot suppress scanner findings, lower severity or prove that source produced an artifact.

### Production authority is explicit

DeltaScope is primarily read-only. Local rule authoring is intentionally separate from production activation. Production rules, Definitions, queue state and published evidence move through reviewed repository/workflow boundaries.

## Where to start

- Plugin author: **Plugin Developer guide**
- Security analyst investigating one plugin: **Investigator guide**
- Ecosystem-wide research or rule work: **Security Researcher guide**
- Pipeline health, collectors, queues and gates: **Operations guide**
- Adding detection logic: **Detection systems** and **Extending Omega security logic**
- Adding or changing tags/classification: **Tagging and classification**
- Adding Stigma-1 logic: **Rule authoring** and **Definition Packs**
- Understanding retained evidence: **Evidence lifecycle and authority**

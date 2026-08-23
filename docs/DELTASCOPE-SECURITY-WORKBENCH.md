# DeltaScope security workbench

DeltaScope is the read-only investigation and research interface for Omega’s published security evidence, plus a deliberately local Stigma-1 rule-authoring workspace.

## Perspectives

### Plugin Developer

One-plugin workflow focused on findings, Journey, version changes, source/build provenance and `.omega/plugin.yaml` explanations.

### Investigator

Case/subject workflow focused on following evidence for one plugin through findings, endpoints, relationships, events and raw provenance.

### Security Researcher

Corpus-wide workflow for intelligence, relationships, rules, comparisons, reports and raw evidence.

### Operations

Pipeline/collector workflow for current evidence health, GitHub Actions history, collectors, queue state, Definitions and authority gates.

## Read-only boundary

Published Evidence-v2, queue state, Definitions, system rules and GitHub workflow state are inspection-only in DeltaScope. My Rules are local files; production rule activation remains a reviewed repository/Definitions action.

## Object-centric navigation

Selecting a plugin establishes a subject. Journey, Findings, Network, Compare, Source/Build and Relationships all refer to that subject. Historical versions are grouped under the same plugin identity and clearly marked archive/current.

## Documentation

The Documentation workspace is an allow-listed manual shipped with the source tree. It is organized by purpose rather than development history and covers platform architecture, developers, investigators, researchers, operations, collectors, detection extension, tags and rules.

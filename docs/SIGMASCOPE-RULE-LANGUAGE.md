# SigmaScope Rule Language (SRL)

SRL is the bounded declarative language evaluated by Stigma-1.

The language is intentionally small. Security rules should be easy to inspect, fixture-test and replay without embedding a second general-purpose programming environment inside Definitions.

## Safety model

SRL does not expose arbitrary code execution, imports, shell commands, filesystem access, templates or unrestricted network access. YAML anchors, aliases and explicit tags are rejected so review/resource behavior remains straightforward.

## Inputs

Rules can consume:

- registered Evidence-v2 observation collections;
- registered external collector observation types carried in an explicit collector bundle;
- typed facts emitted by earlier rules;
- bounded scalar fields exposed by the SRL data contract.

See **Rule data reference** for the available collections and completeness semantics.

## Selectors

Selectors choose rows/facts from a registered collection. A selector should be specific enough that a reviewer can understand exactly which observation qualifies.

Common selector operations include equality, membership, string matching and bounded field comparisons supported by the compiler.

## Conditions

Conditions compose selectors/facts using bounded logic such as:

- all / AND;
- any / OR;
- not;
- count/threshold;
- fact presence.

Avoid building giant opaque condition trees. Prefer small fact-producing rules plus a clear correlation rule when that improves reuse and reviewability.

## Outputs

### Fact

Facts normalize observations into reusable security vocabulary.

### Finding

A finding includes stable identity, severity/category, human explanation and evidence references.

### Analysis request

An analysis request asks for a registered Deep Scan profile. It is not executable code.

### Observation request

An observation request asks orchestration for another **logical collector observation type**. It is not network/execution authority and cannot name a collector implementation. The evaluator only resolves the request to registered provider candidates.

```yaml
observationRequest:
  collection: catalogRepositoryCandidates
  reason: Resolve a repository candidate for the newly observed plugin.
  priority: 700
```

Allowed fields are `schema`, `collection`, `reason` and `priority`. A `collectorId` or any other implementation-binding field is rejected.

## Completeness and replay

A rule may only treat the absence of observations as meaningful when the observation contract says the required collection is complete enough for that query. If required data is missing/bounded, replay should report a re-analysis requirement rather than a false negative.

## Example shape

```yaml
schema: omega.srl.ruleset.v1
rules:
  - id: example.network-capability
    kind: observation
    when:
      collection: managedCalls
      where:
        member:
          contains: HttpClient
    emit:
      fact: network.http

  - id: example.network-process
    kind: correlation
    when:
      all:
        - fact: network.http
        - fact: process.launch
    emit:
      finding:
        severity: high
        category: execution
        title: Network plus process execution capability
        description: The retained static observations contain both network and process-launch capabilities.
```

Use the shipped example rules/fixtures for exact compileable syntax.

## Authoring workflow

Use DeltaScope Rules to validate, format, inspect symbols, edit visually, dry-run a selected plugin, replay a corpus, create fixtures and export a candidate. Production activation remains a reviewed Definitions operation.

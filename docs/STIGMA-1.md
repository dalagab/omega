# Stigma-1

Stigma-1 is Omega’s deterministic security-rule system. Its technical core is the SigmaScope Rule Language (SRL).

Stigma-1 exists so security logic that can be expressed over retained observations does not need to be hidden inside scanner implementation code.

## Responsibilities

Stigma-1:

- reads registered observation collections and typed facts;
- evaluates bounded deterministic conditions;
- emits facts, findings, typed analysis requests or typed observation requests;
- preserves rule and Definition Pack provenance;
- supports replay against retained Evidence-v2 when required observations are complete;
- powers DeltaScope’s local rule-authoring/dry-run experience.

Stigma-1 does **not**:

- execute arbitrary code;
- run shell commands;
- fetch arbitrary URLs;
- read arbitrary filesystem paths;
- mutate production Evidence-v2 from DeltaScope;
- make a local rule authoritative merely because it compiles.

## Rule kinds

A rule can broadly perform one of these jobs:

1. **Observation → fact** — normalize a low-level observation into a reusable typed fact.
2. **Fact/observation correlation → finding** — combine evidence into a security conclusion.
3. **Evidence condition → analysis request** — request a code-owned Deep Scan profile when more evidence is justified.
4. **Observation condition → observation request** — request a logical registered observation type when another collector could provide useful context. Stigma-1 resolves provider candidates but never executes the collector.

## Fastest way to create a rule

1. Open DeltaScope → Security Researcher → Rules.
2. Choose **New Rule** or fork a System Rule into My Rules.
3. Use YAML or the visual editor.
4. Validate the rule.
5. Dry-run it against a selected plugin.
6. Create positive and negative fixtures.
7. Replay a bounded set/corpus to inspect false positives and coverage requirements.
8. Export or propose the candidate through the reviewed GitHub workflow.

## Collector observations and requests

Collectors are first-class observation providers. A rule references a registered logical collection such as `catalogPluginFacts` or `networkEndpoints`; it normally does not reference `omega.collector.*` implementation IDs. Retained row provenance records the provider that actually supplied the observation.

`observationRequest` is deliberately non-executable. It names only a rule-eligible logical collection, a reason and a bounded priority. Stigma-1 may expose provider candidates for explanation, but the generic `omega.analysis-request.v1` handed to the Analysis Broker deliberately strips provider resolution and is resolved again against the frozen registries. This keeps provider choice and freshness policy outside rule semantics. An implementation-specific `collectorId` or `componentId` is rejected as an execution binding.

## Production boundary

System Rules are repository/frozen-definition data. My Rules are local authoring files. Production use requires normal source review and frozen Definitions publication; DeltaScope does not provide a hidden activation button.

## Related documentation

- SRL language reference
- Rule design guidance
- Rule data reference
- Definition Packs
- DeltaScope rule workflow
- Deep Scan workflow

# SigmaScope Rule Language (SRL) v1

Status: **Phases 5–6 and the first end-to-end Phase 7 migration path are implemented locally on the unreleased 2.15 development line.** SRL v1 and Definition Pack freezing are implemented; 14 reviewed literal-backed primitive fact producers plus two reviewed compound correlations pass exhaustive old-vs-SRL parity, and retained Evidence-v2 replay is available. Production SRL projection remains deliberately disabled until a compatible 2.15 corpus has replayed cleanly and cutover is reviewed. Production 2.14 remains untouched while scans continue.

SRL is a deterministic, non-executable, Sigma-inspired YAML language for expressing static capability and behavior rules over SigmaScope's registered observation collections. It does not replace YARA, ClamAV, OSV, endpoint protection, signature verification, or other specialist security systems.

`tools/security/srl.py` is now explicitly the shared **Stigma-1 (SRL Core)** used by both SigmaScope and DeltaScope. DeltaScope 4.2 may project one SRL rule into `omega.sigmascope.srl-authoring-graph.v1` for visual editing, but that graph is not another executable language: graph edits must reconstruct canonical SRL YAML and pass the same compiler before evaluation or local save.

## Inspect the live authoring contracts

Do not guess collection names or fields. Use the branch-shipped machine-readable references:

```bash
python tools/security/deltascope.py capabilities
python tools/security/deltascope.py observation-schema
python tools/security/deltascope.py rule-schema
```

`rule-schema` now reports an `omega.sigmascope.srl-engine.v1` block with the exact operators, typed collections and deterministic limits implemented by the compiler.

## Compile and test a rule locally

A complete example is shipped under `docs/rule-authors/examples/`.

Compile it:

```bash
python tools/security/deltascope.py rule-compile \
  --rule docs/rule-authors/examples/process-network-rules.yaml
```

Run a positive fixture:

```bash
python tools/security/deltascope.py rule-test \
  --rule docs/rule-authors/examples/process-network-rules.yaml \
  --fixture docs/rule-authors/examples/process-network-positive.fixture.yaml
```

Run a near-miss negative fixture:

```bash
python tools/security/deltascope.py rule-test \
  --rule docs/rule-authors/examples/process-network-rules.yaml \
  --fixture docs/rule-authors/examples/process-network-negative.fixture.yaml
```

`rule-test` exits non-zero when fixture expectations do not match.

For a raw logical-observation JSON mapping, use:

```bash
python tools/security/deltascope.py rule-eval \
  --rule candidate.yaml \
  --observations observations.json
```

Phase 8 DeltaScope Rule Lab now provides real Evidence-v2 plugin selection, visual selector tracing, baseline diff, bounded replay, fixture generation/testing, and candidate export. It uses this same compiler/evaluator module; there is no browser-only rule engine.

## Rule schemas

Single rule:

```yaml
schema: omega.sigmascope.rule.v1
id: capability.process.execute
kind: observation
status: experimental
requires: [managedCallSites]

selectors:
  process_start:
    collection: managedCallSites
    where:
      targetDeclaringType:
        equals-ci: System.Diagnostics.Process
      targetName:
        in-ci: [Start]

condition: process_start

emit:
  fact: process.execute
  confidence: high
  title: Process execution capability
```

Ruleset:

```yaml
schema: omega.sigmascope.ruleset.v1
rules:
  - ...
  - ...
```

Fixtures use:

```yaml
schema: omega.sigmascope.rule-fixture.v1
name: process-start positive
observations:
  managedCallSites:
    - targetDeclaringType: System.Diagnostics.Process
      targetName: Start
expected:
  facts: [process.execute]
  matchedRules: [capability.process.execute]
  findingIds: []
```

## Rule kinds

### `observation`

Consumes registered observations and emits one typed fact when its condition matches.

### `classification`

Uses the same safe observation-to-fact semantics for bounded classification/mapping knowledge. It cannot execute code or recursively consume findings.

### `correlation`

May consume registered observations and/or typed facts and emits a review finding. Correlation rules **cannot emit facts**, which makes fact cycles and recursive finding chains structurally impossible in v1.

A fact-only correlation declares:

```yaml
requires: []
```

because it does not require an observation collection directly.

## Required collections and replay safety

Every rule must explicitly declare `requires` as the exact set of logical observation collections used by collection selectors. The compiler rejects missing or unused entries.

Before evaluating real retained Evidence-v2, SRL uses `omega.sigmascope.projection-replay-audit.v1` from Phase 4. A rule evaluates only when all required collections are present with sufficient completeness.

A historical `bounded-transport` endpoint view is therefore useful for UI/research but cannot silently satisfy an exact full-endpoint rule. The result is **targeted re-analysis required**, not a negative match.

Production selectors may only read collections marked `srlEligible: true` by:

```bash
python tools/security/deltascope.py observation-schema
```

Derived inputs such as current `findings`, `permissions`, `automationCapabilities`, and `behaviorConsistency` are forbidden raw production inputs.

## Selector semantics

A collection selector has one `collection` and a `where` mapping. All field predicates must match the **same observation row**.

This prevents accidental joins such as:

- row A: `System.Diagnostics.Process.Kill`
- row B: `Example.Unrelated.Start`

from satisfying a selector asking for `System.Diagnostics.Process.Start`.

Repeated developer-profile arrays also use same-element semantics. For example:

```yaml
where:
  capabilities[].id:
    equals: process.execute
  capabilities[].expected:
    equals: false
```

matches only when **one capability declaration element** has both values. It cannot combine `id` from one declaration with `expected` from another.

SRL v1 allows only one repeated-array path group in a selector to keep these semantics deterministic and reviewable.

## Fact selectors

Correlation rules may inspect typed facts:

```yaml
selectors:
  network:
    facts:
      any: [network.http, network.socket]

  execution:
    facts:
      any: [process.execute, shell.powershell]
```

Supported modes are `any` and `all`.

Observation/classification rules cannot consume facts. This keeps the pipeline one-directional:

```text
observations -> facts -> correlations/findings
```

## Conditions

A condition can reference a selector directly:

```yaml
condition: process_start
```

or compose selectors with:

```yaml
condition:
  all: [network, execution]
```

```yaml
condition:
  any: [managed_start, native_start]
```

```yaml
condition:
  not: forbidden_case
```

Counts are bounded and operate on a selector's same-record match count:

```yaml
condition:
  count:
    selector: concrete_endpoint
    gte: 2
```

Count thresholds support `gt`, `gte`, `lt`, `lte`, and `equals`.

## Field operators

The implemented SRL v1 operator set is machine-readable in `rule-schema`. It currently includes:

- `equals`
- `equals-ci`
- `in`
- `in-ci`
- `contains`
- `contains-ci`
- `starts-with`
- `starts-with-ci`
- `ends-with`
- `ends-with-ci`
- `exists`
- `missing`
- `gt`
- `gte`
- `lt`
- `lte`

The compiler type-checks operators against each registered field. Numeric comparison cannot be applied to a string field, and string containment cannot be applied to an integer/boolean field.

There is deliberately **no regex, template, Python, JavaScript, SQL, shell, import, network request, filesystem lookup, process execution, environment access, or plugin callback syntax** in SRL v1.

## Typed field registry

SRL compilation fails when a rule references a collection that has not yet received a frozen typed SRL field registry, even if the Phase-4 transport knows that collection exists. This is intentional: adding a legal logical collection is not enough to guess its field types.

Use `rule-schema` for the current compileable field set and `observation-schema` for the wider observation transport boundary.

If needed evidence is absent, request a new bounded SigmaScope observation primitive or typed field registration. Do not work around the boundary with derived findings or raw data access.

## Determinism

Compilation canonicalizes semantic rule content and emits:

- `omega.sigmascope.compiled-rule.v1`
- `ruleRevision: srl-rule-v1-...`
- `omega.sigmascope.compiled-ruleset.v1`
- `ruleSetRevision: srl-ruleset-v1-...`

Whitespace and YAML formatting do not affect these identities. Semantic changes do.

Evaluation produces stable selector/rule ordering, typed facts sorted by ID, and findings sorted by rule/finding identity.

## Bounds

The exact values are exposed in `rule-schema`. SRL v1 currently bounds at least:

- YAML/document bytes and token/node counts;
- rules per ruleset;
- selectors per rule;
- values per membership operator;
- condition nesting depth;
- rows accepted per collection;
- retained matched evidence rows per selector/rule;
- emitted facts and findings.

YAML anchors, aliases and explicit tags are rejected, as are duplicate mapping keys.

Limit violations are compile/evaluation failures. They never enable unbounded fallback behavior.

## Status and production boundary

A rule status is one of:

- `experimental`
- `reviewed`
- `deprecated`
- `disabled`

`disabled` and `deprecated` rules may still be evaluated for diagnostics/parity but do not emit a fact/finding.

**Production rule evaluation is still disabled after Phase 6 freezing.** `rule-schema` explicitly reports:

```json
"productionRuleEvaluationEnabled": false
```

Definition Pack v1 and the Daily Catalog compiler/freezer are implemented. The first Phase-7 migration chain now starts from retained `staticPatternMatches`, emits 14 reviewed literal-backed primitive facts, and evaluates `compound.network-execute` / `compound.credential-network`. Migration checks cover 147 primitive literal cases plus all 32 compound input combinations and are enforced by Daily Definitions. `rule-replay` can compare compatible retained Evidence-v2 against the hard-coded baseline without feeding old findings into SRL. Reviewed frozen SRL output still cannot affect production projections until a real compatible 2.15 corpus has replayed cleanly and cutover is reviewed.

## Why not Snort syntax

Snort's useful lesson is declarative security rules, but its language is packet/flow-specific. SigmaScope works over static evidence: managed calls, native imports, endpoints, dependencies, provenance, developer declarations and other normalized records. Sigma-inspired YAML maps naturally onto that model while remaining readable in GitHub issues and code review.

## Specialist systems stay specialist

- malware/file signatures -> YARA / ClamAV;
- known vulnerable dependency versions -> frozen OSV matching;
- endpoint protection/runtime detection -> endpoint/security tooling;
- signature/trust-chain verification -> integrity subsystem;
- static plugin capability/behavior transparency -> SigmaScope/SRL.

SRL may correlate bounded outputs from other systems where appropriate, but it does not attempt to reimplement them.

## Deep-analysis outcome

Rules may optionally add `analysisRequest` with `profile`, bounded `depth`, `compareWith`, and `reason`. `depth` is `standard`, `extended`, or `exhaustive`; it is an evidence-acquisition escalation hint, not a raw runtime setting. Commands, timeouts and runner controls are invalid SRL. Production queue mutation is available only to matched frozen rules; DeltaScope local rules preview the request only.

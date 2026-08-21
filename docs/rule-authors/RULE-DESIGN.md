# Designing a good SigmaScope rule

SigmaScope is a static behavior-transparency scanner. A good rule describes evidence and capability precisely without turning static possibility into an accusation of runtime intent.

## Decide which problem you are solving

Use the appropriate subsystem:

- **Known malware/file signatures** -> YARA or ClamAV.
- **Known vulnerable dependency versions** -> frozen OSV advisory matching.
- **Binary signature/trust-chain verification** -> the future integrity/AuthentiCode subsystem.
- **Static capability/behavior evidence** -> SigmaScope/SRL.
- **Developer-declaration consistency** -> SigmaScope/SRL correlation against `.omega` declarations.

Do not recreate mature specialist engines as YAML rules.

## Prefer observation -> fact -> correlation

The long-term SRL model has two logical layers:

1. Observation rules consume normalized rows and emit stable facts/capabilities.
2. Correlation rules combine facts/observations into a review signal.

Do not create a chain where one arbitrary finding consumes another arbitrary finding. That creates recursive semantics, order dependence and difficult auditability.

Example conceptual rule:

```yaml
schema: omega.sigmascope.rule.v1
id: capability.process.execute
kind: observation
selectors:
  process_start:
    collection: managedCallSites
    where:
      targetDeclaringType:
        equals-ci: System.Diagnostics.Process
      targetName:
        equals-ci: Start
condition:
  any: [process_start]
emit:
  fact: process.execute
```

This is design syntax until SRL v1 is implemented; use `deltascope.py rule-schema` for current field names.

## Declare required observation collections

Every future production SRL rule must declare the logical Phase-4 collections it requires. The compiler/evaluator must resolve these names through the observation registry and run the shared replay audit before matching any rows.

A rule is exactly replayable only when each required collection is retained with sufficient completeness. If historical Evidence contains only a `bounded-transport` compatibility view, the correct result is **targeted re-analysis required**, not a negative match.

Do not request derived collections such as `findings`, `permissionCandidates`, `automationCapabilities`, or `behaviorConsistency`. If the desired condition can only be expressed by consuming one of those, identify the underlying observation primitive that should be registered instead.

Use:

```bash
python tools/security/deltascope.py observation-schema
```

to inspect the current legal input boundary.

## Same-record matching

A multi-field selector must match one observation row. Otherwise a rule can manufacture evidence by combining unrelated records. This is especially important for call sites, imports, endpoints and dependencies.

## Confidence and reachability

Treat evidence strength separately from severity:

- loose strings/references are weak evidence;
- concrete metadata/imports/call sites are stronger;
- static reachability from a known callback/lifecycle root is stronger still;
- none of these prove runtime branch execution.

Severity answers "how much review should this combination receive?" Confidence answers "how directly does the static evidence establish the capability?" Do not collapse them.

## Negative evidence is difficult

Absence of an observation is not automatically proof that a capability does not exist. Analysis may be bounded, code may be native/dynamic, a path may be reflection-driven, or historical evidence may predate a new observation contract. Rules using `missing`/negative logic should require compatible coverage metadata when the SRL implementation makes that available.

## Developer declarations

`.omega/plugin.yaml` is useful for consistency, not permission:

- observed + declared expected -> explained behavior;
- observed + undeclared -> unexplained behavior;
- observed + explicitly not expected -> strong consistency mismatch;
- declared + not observed -> not necessarily a problem.

Never write a rule that says "developer declared this, therefore suppress the observed capability."

Do not consume the derived `behaviorConsistency` projection in production SRL. A consistency rule should query the independent observation collection and `developerProfile` directly. `behaviorConsistency` exists for presentation/research inspection and consuming it would create recursive conclusion semantics.

## Endpoint rules

Prefer sanitized concrete `host`/classification/origin data over raw URL substring matching. Avoid rules that classify common infrastructure (certificate revocation, generic source/project links, etc.) as active plugin destinations unless `concreteDestinationEvidence` supports it.

## Native/API rules

Use concrete library and entry-point evidence. Broad primitives can be normal in plugins. Compound behavior generally belongs in a correlation rule rather than assigning a high verdict to one common API.

## Required fixtures

A future production rule contribution should include at minimum:

- one positive fixture that must match;
- one near-miss negative fixture;
- one common-benign fixture when the primitive is broad;
- expected emitted fact/finding identity;
- expected evidence row(s);
- author explanation of false-positive expectations;
- provenance/license when adapted from an external rule source.

Rules intended to correlate multiple evidence families should include a split-row/same-record negative fixture where applicable.

## Safety requirements for rule syntax

SRL is intentionally non-executable. Rules must never request:

- arbitrary filesystem reads;
- network access;
- process spawning;
- imports/plugins/modules;
- environment/secrets access;
- raw SQL;
- templates or code evaluation;
- scanner-authority overrides.

If a rule needs information that is not in a registered collection, that is a request for a new bounded SigmaScope observation primitive—not justification for embedding code into the rule.

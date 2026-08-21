# Writing rules for SigmaScope

SigmaScope Rule Language (SRL) v1 and Definition Pack v1 are implemented locally on the unreleased 2.15 development line. Daily Definitions can compile, fixture-test and freeze reviewed packs deterministically. Production SRL projection is **not enabled yet**. The first Phase-7 migration chain now has five reviewed `staticPatternMatches` observation-to-fact rules, two reviewed compound correlations, exhaustive primitive/compound parity and retained Evidence-v2 replay tooling. Phase 8 DeltaScope Rule Lab is also implemented locally for visual candidate authoring/dry-run/replay/fixture/export. Activation still requires a clean compatible 2.15 corpus replay and explicit cutover review.

Start with the machine-readable contracts:

```bash
python tools/security/deltascope.py capabilities
python tools/security/deltascope.py observation-schema
python tools/security/deltascope.py rule-schema
```

Then read:

- `DATA-REFERENCE.md` — what the current collections/fields actually mean;
- `RULE-DESIGN.md` — how to avoid weak or misleading static-security rules;
- `DELTASCOPE-WORKFLOW.md` — compile/test/evaluate plus the implemented visual Rule Lab workflow;
- `../SIGMASCOPE-RULE-LANGUAGE.md` — exact SRL v1 syntax, operators, conditions, limits and safety boundaries;
- `../DEFINITION-PACKS.md` — pack manifest, trust tiers, review metadata and Daily freezing contract;
- `examples/` — a compileable ruleset with positive and negative fixtures.

Quick test:

```bash
python tools/security/deltascope.py rule-test \
  --rule docs/rule-authors/examples/process-network-rules.yaml \
  --fixture docs/rule-authors/examples/process-network-positive.fixture.yaml
```

Rules must only consume registered `srlEligible` observations and typed facts. Never use current findings/permission/automation/behavior-consistency conclusions as recursive production inputs.

SRL is non-executable. If a rule needs information that is not represented by a legal observation field, request a new bounded observation primitive rather than embedding code, SQL, filesystem or network behavior in a rule.

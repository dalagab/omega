# DeltaScope workflow for SigmaScope rule authors

Status: SRL v1 compiler/evaluator and **Phase 8 DeltaScope Rule Lab are implemented locally**. The Rule Lab provides direct retained Evidence-v2 plugin dry runs, selector exploration, baseline diff, bounded replay, fixture editing/testing, and deterministic candidate export. GitHub promotion remains a later authorization-gated phase. Production SRL loading is still disabled.

## 1. Inspect the legal data boundary

```bash
python tools/security/deltascope.py observation-schema
python tools/security/deltascope.py rule-schema
```

`observation-schema` answers which logical Phase-4 collections can ever be valid SRL inputs and whether they are observation, provenance, developer-claim, or hygiene evidence.

`rule-schema` answers which of those collections currently have a typed SRL field registry, exact field types/operators/limits, and whether production rule evaluation is enabled.

A collection may be `srlEligible` at the Phase-4 transport level but not yet compileable until its exact field registry is frozen. That is intentional.

## 2. Write a candidate YAML rule

Use `omega.sigmascope.rule.v1`. Every rule declares:

- stable `id`;
- `kind` (`observation`, `classification`, or `correlation`);
- status;
- exact `requires` observation collections;
- named selectors;
- one deterministic condition tree;
- one fact or finding output.

See `examples/process-network-rules.yaml`.

## 3. Compile it before touching plugin evidence

```bash
python tools/security/deltascope.py rule-compile --rule candidate.yaml
```

Compilation is where unknown collections, unknown fields, operator/type errors, condition errors, duplicate rule/fact IDs, illegal recursive inputs, and deterministic bounds fail.

The output contains content-derived `ruleRevision` and `ruleSetRevision` identities.

## 4. Start with fixtures

A positive fixture should prove the intended match. A near-miss negative should prove an important boundary such as same-record matching.

```bash
python tools/security/deltascope.py rule-test \
  --rule candidate.yaml \
  --fixture positive.fixture.yaml
```

The fixture schema is `omega.sigmascope.rule-fixture.v1`.

Useful fixture categories:

- positive;
- near-miss negative;
- common-benign primitive;
- split-row same-record negative;
- developer-profile repeated-array same-element negative;
- count threshold edge;
- historical replay incompatibility fixture where applicable.

## 5. Evaluate against exported logical observations

The CLI can still evaluate a JSON mapping of logical collections directly:

```bash
python tools/security/deltascope.py rule-eval \
  --rule candidate.yaml \
  --observations observations.json
```

Example input:

```json
{
  "managedCallSites": [
    {
      "targetDeclaringType": "System.Diagnostics.Process",
      "targetName": "Start"
    }
  ]
}
```

Optional pre-existing facts can be supplied with repeated `--initial-fact` arguments for local correlation testing.

For retained Evidence-v2 replay, pass the actual Phase-4 contract as well:

```bash
python tools/security/deltascope.py rule-eval \
  --rule candidate.yaml \
  --observations observations.json \
  --observation-contract observation-contract.json
```

If the contract says a required collection is absent or only historical `bounded-transport`, SRL returns `evaluated: false` and explains the targeted re-analysis requirement. It never treats truncated historical transport as a valid negative result.

## 6. Read selector traces

The evaluator result and Rule Lab selector explorer expose per selector:

- selector name/type;
- collection/fact family;
- match boolean;
- total match count;
- bounded exact matched evidence rows with row indexes;
- whether retained trace rows were truncated.

This is the deterministic basis for the later UI selector explorer.

## 7. Compare with current production behavior

During migration, current hard-coded findings/permission/automation projections are useful as a **baseline only**. They are not legal SRL raw inputs.

A migration rule should be tested against the underlying observations and then compared with current projection output. Parity should be proven before hard-coded Python logic is removed.

## 8. Phase-8 visual Rule Lab

Run DeltaScope against local or published Evidence-v2 and open **Rule Lab**. The browser wraps the same `srl.py` compiler/evaluator used by CLI/tests and provides:

```text
selected Evidence-v2 plugin
       +
candidate YAML
       ↓
compile/type diagnostics
       ↓
Phase-4 replay audit
       ↓
selector trace + exact rows
       ↓
facts/findings
       ↓
production baseline diff scoped to candidate finding IDs
       ↓
bounded selected-set/corpus replay
       ↓
exact retained-observation fixture generation/edit/test
       ↓
deterministic hash-pinned candidate ZIP export
```

Candidate YAML remains inert data. Missing required retained observations produce an explicit replay/rescan requirement; they are never interpreted as negative evidence. Observation-only candidates do not compare against unrelated production findings.

Rule Lab export contains candidate YAML, optional passing fixture, a candidate descriptor, README, and hash-pinned manifest with fixed ZIP metadata for deterministic bytes. The exported bundle carries `productionWriteBack=false` and no promotion authority.

There is intentionally no `/api/rule-lab/promote` or equivalent production mutation path. No Rule Lab action may write production Evidence-v2, Definitions, queue state, or catalog state.

## 9. Candidate issue/promotion — implemented Phase 9

A candidate export should contain at minimum:

- canonical rule YAML;
- positive and negative fixtures;
- rule/revision identity;
- required observation collections;
- author rationale;
- false-positive expectations;
- external provenance/license where applicable;
- corpus summary.

The GitHub issue validator treats YAML as inert data. A self-declared YAML `author:` or candidate `status: reviewed` is never authorization.

Use the `SigmaScope rule candidate` issue form. The canonical `sigmascope` reusable workflow validates with `contents: read`, while promotion first checks the triggering GitHub actor's repository permission, then re-fetches and revalidates from scratch. Authorized materialization creates a new source-controlled `reviewed` Definition Pack and opens a normal PR; it never overwrites an existing pack or auto-merges. The default-branch caller example is `docs/workflow-callers/rule-candidates-main.yml`.

Daily Catalog freezing remains a separate step and production SRL projection is still disabled. Do not use contribution-controlled executable code or `pull_request_target` in a privileged workflow.


## Phase 7 migration parity and retained replay

For reviewed rules being migrated from current hard-coded SigmaScope semantics, run:

```text
python tools/security/deltascope.py rule-parity
```

The current checker covers the reviewed migration chain: 14 literal-backed primitive fact producers in `omega-core-static-primitives` and the two reviewed compound correlations in `omega-core-compound`. It checks 147 primitive literal cases and all 32 combinations of the five primitive facts consumed by those compounds. Inputs are scanner-retained `staticPatternMatches`; current findings or other projections are not converted into SRL facts.

To replay the chain over retained Evidence-v2, run:

```text
python tools/security/deltascope.py rule-replay --evidence-v2 <path-to-security-evidence-v2>
```

Replay loads only SRL-eligible retained observations and uses historical findings strictly as the baseline diff. A new complete zero-hit `staticPatternMatches` dataset is a valid negative; a historical variant without the completeness marker is reported as requiring targeted re-analysis. `--strict-warnings` can be used when a cutover-readiness result is required rather than a diagnostic audit.

Production SRL projection remains disabled. Do not remove the hard-coded baseline until a real compatible 2.15 corpus replays with no mismatches or required rescans and cutover is explicitly reviewed.

# DeltaScope rule-development workbench architecture

Status: **Phase 8 Rule Lab execution/export is implemented locally** on the unreleased 2.15 line. `deltascope.py capabilities`, `observation-schema`, and `rule-schema` expose the typed vocabulary; the browser adds inert candidate editing/import, retained-evidence dry-run/replay, fixture tooling, and deterministic export. Production write-back remains impossible from Rule Lab.

## Goal

DeltaScope should be the safe developer environment for creating and testing SigmaScope Rule Language definitions against real, already-generated evidence without putting experimental rules into the production scanner path.

DeltaScope remains developer-only and read-only with respect to catalog/Definitions/Security Evidence publication.

## Phase-4 evidence compatibility gate

DeltaScope now exposes the exact reusable-evidence boundary even before the Rule Lab compiler exists:

```bash
python tools/security/deltascope.py observation-schema
python tools/security/deltascope.py rule-schema
```

The implemented Rule Lab compiles a candidate rule to a list of required logical collections, run the shared projection replay audit for the selected Evidence-v2 variant, and show one of:

- **Exact replay available** — all required observations are retained;
- **Targeted re-analysis required** — one or more required collections are absent or only historically bounded;
- **Invalid rule input** — candidate requested a derived/conclusion collection rather than a legal observation input.

Rule Lab must never hide this distinction or treat a bounded historical summary as complete evidence. See `docs/OBSERVATION-PROJECTION-CONTRACT.md`.

## Local rule lifecycle

The intended workflow is:

```text
select plugin/evidence case
 -> create or import SRL YAML
 -> schema/type/limit validation
 -> compile in local/experimental trust mode
 -> dry-run against selected immutable observations
 -> inspect selector matches and emitted facts/findings
 -> compare with production baseline
 -> expand to a bounded plugin set/corpus
 -> add expected-result fixtures
 -> export candidate rule bundle
```

No DeltaScope dry-run result is production evidence.

## Workbench UI

The Rule Lab area provides:

- YAML editor or file import;
- schema diagnostics with line/field context;
- compiled rule metadata and trust mode;
- selected plugin/artifact/source identity;
- exact observation collections available to the rule;
- selector-by-selector match counts;
- matched rows/evidence snippets under existing bounds;
- emitted typed facts;
- emitted findings/correlations;
- before/after production baseline diff;
- false-positive review notes;
- rule performance/evaluation counters under deterministic limits;
- fixture editor/generator;
- export action.

## Test scopes

Support three explicit scopes:

1. **Selected case** - fastest feedback for one plugin variant.
2. **Selected set** - developer chooses a bounded group of variants.
3. **Corpus/replay set** - deterministic regression set maintained with Definitions/tests.

A rule that looks correct on one plugin should not be considered production-ready until it has passed fixtures and a representative corpus comparison.

## Explainability

For every emitted result DeltaScope should be able to show:

- rule ID/hash;
- selector(s) that matched;
- exact observation rows/facts used;
- condition branch that evaluated true;
- emitted fact/finding;
- developer declaration involved, if any;
- whether the rule is local/experimental/reviewed/core.

This explanation is generated from evaluator state, not an LLM.

## Export format

DeltaScope should export a self-contained candidate directory or YAML bundle containing at minimum:

```text
candidate/
  rule.yaml
  tests/
    positive.yaml
    negative.yaml
  candidate.json
```

`candidate.json` can contain non-semantic review metadata such as:

- generated-at timestamp;
- source Evidence revision used for development;
- plugins tested;
- baseline/new finding counts;
- known false-positive notes;
- author/reviewer notes.

The authoritative rule remains YAML. The export must not contain raw plugin binaries or sensitive/unbounded evidence.

## GitHub issue integration

Implemented in DeltaScope 3.7 as a **URL-only handoff**. Rule Lab has separate positive and negative fixture editors plus candidate pack/title, rationale, false-positive expectation, provenance and license fields. `Propose on GitHub` first validates the candidate and both fixture polarities with the same authorization-independent Phase-9 candidate validator, then constructs a normal GitHub new-issue URL using `template=sigmascope-rule-candidate.yml` and the Issue Form element IDs as query parameters.

DeltaScope does not call the GitHub issue API, does not submit the issue, and does not need repository credentials for this proposal path. The operator reviews the pre-filled form and presses GitHub's own submit button. GitHub CI re-fetches/revalidates the resulting issue from scratch; local validation is convenience, never authority.

The full prefill is conservatively bounded to 7,500 URL bytes. If candidate/fixture data would make the URL too large, DeltaScope progressively falls back to metadata/identity prefills and presents explicit copy buttons for the omitted candidate/positive/negative YAML. Nothing is truncated silently. A deterministic GitHub-ready candidate ZIP containing both fixture polarities remains available as the offline/fallback artifact.

The canonical Issue Form IDs are owned by `tools/security/rule_candidate.py` and regression-checked against `.github/ISSUE_TEMPLATE/sigmascope-rule-candidate.yml`. Because GitHub Issue Forms are sourced from the default branch, `docs/workflow-callers/sigmascope-rule-candidate-main.yml` is an exact reference copy for the companion `main` overlay alongside `rule-candidates-main.yml`.

## Security boundary

Experimental rule evaluation must use the same parser/compiler/evaluator library as production but run under a `local`/`experimental` trust context. The evaluator receives only already-normalized evidence records and bounded developer-profile metadata.

The Rule Lab must not:

- execute plugin code;
- execute rule-provided code;
- download arbitrary rule-selected URLs;
- query host files from rule expressions;
- mutate Evidence-v2;
- publish Definitions;
- write source overrides;
- change queue state.

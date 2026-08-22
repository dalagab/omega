# Stigma-1 — SRL Core

Stigma-1 is Omega's shared deterministic security-rule component. **SRL Core** remains its technical description. It is not a network service and it is not another scanner: SigmaScope and DeltaScope import the same parser, validator, compiler and evaluator so that a rule tested in DeltaScope cannot acquire different semantics when it reaches SigmaScope.

```text
security definitions / local rule YAML
              |
              v
          Stigma-1
   parser · schema · AST
 validator · compiler · evaluator
      /                 \
     v                   v
SigmaScope            DeltaScope
production evidence   author / inspect / replay
```

## What Stigma-1 owns

Stigma-1 owns:

- hardened SRL YAML parsing;
- the registered rule schema and legal operators;
- typed selector validation against retained observation collections;
- canonical rule/ruleset compilation and revision identity;
- deterministic fact and finding evaluation;
- fixture execution;
- explanation data used by DeltaScope;
- conversion between canonical SRL and DeltaScope's non-executable visual authoring graph.

Stigma-1 does **not** download plugins, collect raw evidence, publish Definitions, mutate Security Evidence v2, decide queue state, or activate local rules.

## Fastest way to create a rule

1. Open **DeltaScope → Rules**.
2. Select a System Rule to learn from it, or choose **+ New Rule**.
3. Use **Fork to My Rules** if you want to modify an existing rule safely.
4. Work in **YAML** or **Visual**. Both are representations of the same SRL rule.
5. Use **Validate now** while editing.
6. Select a plugin and use **Dry-run selected plugin** to see selectors, facts, findings and replay requirements.
7. Add positive and negative fixtures before treating the rule as a serious candidate.
8. Export/propose the candidate through the GitHub review workflow. Saving a My Rule never activates it.

Local rules are versioned under `~/.omega/deltascope/rules/v1` by default. On Windows this is normally `%USERPROFILE%\.omega\deltascope\rules\v1`. `OMEGA_DELTASCOPE_RULE_HOME` or `--rule-home` can redirect it.

## Start with the shipped examples

The example ruleset is:

`docs/rule-authors/examples/process-network-rules.yaml`

with positive and negative fixtures next to it. In DeltaScope 4.5 these documents are also available directly from the **Documentation** page.

For the exact language, read `docs/SIGMASCOPE-RULE-LANGUAGE.md`. For rule-writing guidance, start with `docs/rule-authors/README.md` and `docs/rule-authors/RULE-DESIGN.md`.

## Shipped rule library

The current source library contains **55 rules across 6 Definition Packs**. Sixteen are reviewed production-tier migration rules; 39 are experimental examples/research rules. Experimental rules are useful for learning Stigma-1, forking in DeltaScope, fixture replay and exploring future detection logic, but they are not production-active. The experimental groups cover managed-call/game capabilities, network endpoints, source provenance and higher-order correlations including a typed Deep Scan request example.

## Deep-analysis requests

A matched Stigma-1 rule may request additional evidence with `analysisRequest`. This is a typed evidence-acquisition outcome; it is **not** a shell command and it does not grant a rule control over runner configuration.

```yaml
analysisRequest:
  profile: artifact-differential-v1
  compareWith: stable-artifact-baseline
  reason: Compare divergent package bytes with the stable publisher baseline.
```

Rules may only select a profile implemented by Omega. They cannot provide commands, executables, arbitrary paths, network policy, timeouts, or runner resource settings. The request is bound to the matched rule ID/revision and exact artifact identity, then materialized into the durable SigmaScope Deep Scan queue.

`artifact-differential-v1` is executable today. It downloads the exact candidate and comparison baseline, verifies their SHA-256 identities, performs the normal non-executing SigmaScope static analysis on both, and records a side-by-side package/static-behavior difference. Plugin code is never executed.

`sandbox-differential-v1` is reserved by contract but deliberately unavailable until Omega has a genuine isolated plugin-execution sandbox. A normal GitHub Actions runner must never execute an untrusted plugin merely because a rule requested deeper analysis.

Local DeltaScope rules can compile and preview `analysisRequest`, but local rules have no production queue authority. Operational queue creation occurs only while SigmaScope evaluates the exact frozen Definition rule set.

### Requesting deeper evidence

A rule may emit a bounded Deep Scan request alongside a fact/finding:

```yaml
analysisRequest:
  profile: artifact-differential-v1
  depth: extended
  compareWith: stable-artifact-baseline
  reason: Divergent package warrants a longer equal-profile static comparison.
```

`depth` is one of `standard`, `extended`, or `exhaustive`. Stigma-1 deliberately rejects fields such as `timeoutMinutes`, `command`, runner configuration or arbitrary paths. SigmaScope/Deep Scan map the semantic depth to approved code-owned budgets. If multiple rules request the same work, the deepest request wins.

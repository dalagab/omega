# Extending Omega security logic

> Platform implementation status and missing components are tracked in [MISSING-COMPONENTS.md](MISSING-COMPONENTS.md). Use that roadmap before creating a new component: many missing capabilities belong as collectors inside an existing trust boundary.

This guide helps contributors choose the correct extension point for new security or catalog behavior.

## Decision table

| You want to add… | Primary extension point |
| --- | --- |
| A new external data source | Collector + normalized contract |
| A new plugin browsing/category tag | Catalog tag model |
| A new security behavior primitive | SigmaScope observation + observation contract |
| A new reusable capability name | Capability registry |
| A deterministic correlation over existing observations | Stigma-1 rule |
| A file signature/string detector | YARA Definition |
| Dependency vulnerability knowledge | Advisory collector / Definitions |
| More expensive follow-up analysis | Deep Scan profile + approved `analysisRequest` logic |
| A developer explanation field | Plugin profile schema |

## Adding a collector

See **Collectors and data acquisition**. The core requirement is that collection output be normalized and reviewable before it becomes input to security interpretation.

## Adding a scanner observation

1. Define the primitive evidence and its source.
2. Keep the output bounded and serializable.
3. Add it to the observation contract with completeness semantics.
4. Retain it in Evidence-v2.
5. Expose it through DeltaScope raw/typed evidence.
6. Add tests proving both presence and absence behavior.
7. Only then build findings/rules on top of it.

## Adding a capability

Edit the capability registry and validation tests. Capabilities should be stable vocabulary shared by scanner observations, developer declarations and rules. Avoid synonyms that fragment the model.

## Adding a Stigma-1 rule

1. Start in DeltaScope Rules → New Rule.
2. Select registered collections/facts; do not invent fields that are not in the data reference.
3. Create positive and negative fixtures.
4. Dry-run against a selected plugin.
5. Replay a bounded set/corpus to understand false positives.
6. Export/propose the candidate through the reviewed GitHub workflow.
7. Production activation occurs only after source review and a frozen Definitions publication.

## Adding a Definition Pack

A pack groups related rules and fixtures with provenance/review metadata. Keep packs narrow enough to understand and review. A pack should not mix unrelated security domains merely for convenience.

## Adding a YARA rule

Keep YARA rules first-party/reviewed, deterministic and bounded. Include a test sample/fixture that proves the rule compiles and matches only the intended pattern. Treat a YARA match as evidence requiring interpretation, not an automatic malware verdict unless the rule semantics justify that claim.

## Changing tagging or classification

See **Tagging and classification**. Decide whether the requested tag is marketplace metadata, developer context, capability vocabulary, source permission taxonomy or security conclusion before changing code.

## Review checklist

Every extension should answer:

- What exact input is trusted?
- What is untrusted/external?
- What output contract is produced?
- Is the output an observation, context or conclusion?
- How is completeness represented?
- How is provenance retained?
- What prevents unbounded input or execution?
- What tests prevent obvious false positives/regressions?
- Does the change require re-analysis, or can retained evidence be reprojected?
- Which dashboard/collector/documentation surface lets another person verify that it works?

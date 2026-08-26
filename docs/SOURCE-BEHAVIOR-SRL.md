# Source behavior observations and SRL

This pass keeps behavioral meaning in Stigma-1/SRL and makes SigmaScope emit bounded lower-level source observations. The scanner does not label a plugin as a bot, buyer, seller, or malicious application merely because it can identify primitive operations.

## Definitions-backed knowledge

`security-definitions/services/registry.json` maps known public hosts to stable service IDs, categories and service capabilities. Recognition is descriptive, not a safety verdict: unknown hosts receive stable `host:<hostname>` identities and threat/reputation remains a separate evidence system. Endpoint observations retain the service-registry revision used for enrichment.

`security-definitions/semantic-apis/registry.json` maps SDK/library source or compiled symbols to primitive operation IDs. Source operation rows retain the raw receiver/member symbol and the semantic-API registry revision that produced the primitive mapping. Adding or changing a matcher can therefore be treated explicitly as analysis-semantic change; previously unrecognized source calls may require targeted re-analysis rather than silently changing old evidence.

## Source collections

The bounded source collector emits:

- `sourceOperations`: primitive calls such as `network.http.request`, `data.select`, `game.character.move` and `game.marketboard.purchase`;
- `sourceFlowEdges`: lexical/control ordering, explicit minimum delays and trigger-to-handler relationships;
- `sourceTriggers`: named event subscriptions, command handlers and bounded periodic-timer observations;
- `sourceConditions`: string-redacted conditional expressions plus stable hashes;
- `sourceDataFlow`: conservative local value-use edges between retained primitive operations, including inherited service provenance.

Collection rows are scoped to the source surface selected for the plugin. Unrelated projects elsewhere in a monorepo do not become behavior evidence for that plugin merely because they share a repository. These observations are static possibilities and do not prove that a runtime branch executed.

The first implementation is intentionally lexical and bounded. It does not claim complete C# semantics, interprocedural alias tracking, reflection resolution, dynamic dispatch resolution, or arbitrary control-flow reconstruction. Unsupported/unrecognized code remains unclassified rather than guessed.

## SRL owns interpretation

`omega-experimental-source-behavior` is an experimental Definition Pack. Its rules consume the raw collections and currently expose facts for registered market-data retrieval, market data flowing into a purchase primitive, navigation immediately preceding purchase, explicit delay before purchase, generic registered-trigger purchase paths and periodic-trigger purchase paths. Because the pack is `experimental`, Daily Definitions compiles/freezes and fixture-tests it but does not add it to the active production ruleset.

Example primitive graph:

```text
network.http.request [service capability: ffxiv.market-data]
        │
        │ local value provenance
        ▼
      data.select
        │
        │ value-used-by
        ▼
game.marketboard.purchase
```

SRL may interpret that graph as `behavior.marketboard.external-data-driven-purchase`; SigmaScope itself does not.

Rift can later add runtime timestamps/observations for comparison with the static possible-order graph. The static and runtime layers should remain separate evidence providers so runtime absence is not used to erase a statically possible behavior and static possibility is not misreported as observed runtime execution.

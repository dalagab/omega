# DeltaScope separation boundary

DeltaScope is a **local, read-only consumer** of the Omega security platform. It is not a SigmaScope worker, a Stigma-1 production authority, a queue publisher, or an Evidence-v2 writer.

## Direction

Security services own execution and publication:

- SigmaScope produces static artifact/source observations;
- Stigma-1/SRL evaluates approved frozen rules and emits findings/typed evidence requests;
- Discovery, Rift, Threat Intelligence, Rebuilder and future components publish observations through their contracts;
- Security Evidence v2 and frozen Definitions publish coherent read-only state.

DeltaScope consumes those contracts. Adding a component/provider/rule should not require DeltaScope application code merely to make the new object visible.

## 4.21.7 boundary

The second separation pass extracts a bundled **DeltaScope consumer SDK** under `deltascope_sdk/`. The primary workbench, local rule store, finding-lineage projection, detection-coverage projection and Definition provenance reader now consume the SDK's SRL/observation/Definition-Pack compatibility layer instead of importing the production SigmaScope/Stigma modules directly.

The SDK remains local code shipped with DeltaScope. It may bind hash-verified published component, collector/provider and capability registries at runtime, allowing newly registered components and rule-eligible observation types to become visible/authorable without downloading Python or changing DeltaScope ID-specific code. Consumer validation is intentionally forward-compatible with new published component kinds; production registry validation remains strict in the security service.

Security Definitions now publish `platform/execution-topology.json` (`omega.execution-topology.v1`). This read-only contract describes workflow/job/step correlation, component ownership, cadence and diagnostic parser hints. DeltaScope Operations consumes that contract instead of owning the workflow map. Unknown future execution nodes get a generic Operations row even when DeltaScope has no specialized log metric parser.

Rollout is compatible with the currently published Definitions revision: until the next Definitions freeze includes the new descriptor, DeltaScope uses `deltascope/execution-topology-fallback.json`. Once the descriptor exists, the verified published copy wins automatically. The fallback has no launch or policy authority.

No scanner code, Evidence-v2 writer, dispatcher, credentials or repository mutation code moved into the SDK.

## 4.21.6 boundary

The first separation pass adds a verified published-resource cache (`tools/security/deltascope_resources.py`). In online mode DeltaScope reads the current `catalog-data/definitions/index.json` and materializes only the small consumer resources needed by the workbench:

- frozen SRL Definition Pack index;
- frozen SRL pack source rules and fixtures;
- frozen compiled SRL ruleset;
- component registry;
- collector/provider registry;
- capability registry.

The root Definitions index is the HTTPS trust anchor. Every downloaded child file is checked against its published SHA-256. SRL pack files are additionally pinned by the hash-verified SRL index. Completed revisions are cached immutably and DeltaScope can fall back to the last verified revision when the network is unavailable.

**The frozen SigmaScope worker bundle is deliberately excluded.** DeltaScope does not need scanner implementation code to browse rules/components/providers, and remote resource synchronization must never turn into remote code loading.

Run an explicit synchronization/diagnostic pass with:

```text
python deltascope.py sync-resources
```

Normal `serve-online` startup performs the same synchronization automatically. `--offline-resources` uses only the last verified resource snapshot.

## Dependency ownership

DeltaScope now owns `deltascope/requirements.txt`. The launcher no longer installs `tools/requirements-security.txt`. This prevents a future SigmaScope scanner dependency from becoming a DeltaScope runtime dependency by accident.

The current Python SRL Core/evaluator remains bundled with DeltaScope. Rules are downloaded as **data**, not executable Python. Moving the reusable SRL compatibility layer out of the SigmaScope implementation tree is a later pass.

## Registry-driven discovery

The Components dashboard now overlays the published `omega.component-registry.v1`. A newly registered component therefore appears generically even if DeltaScope has never heard of its ID. If its declared workflow is observed in recent Actions data, DeltaScope correlates that diagnostic run state; otherwise it reports the component as unobserved/unknown rather than guessing.

The Collectors page separately exposes every provider in the published `omega.collector-registry.v1`, including planned providers and their declared observation types. New providers therefore appear without adding a DeltaScope-specific provider case.

Specialized visualizations remain optional. Unknown components/providers/observations must always retain a useful generic representation first.

## Still coupled after this pass

This is still an incremental separation rather than a repository split. The main remaining coupling is physical/source-layout coupling: the HTTP workbench and Evidence-v2 inspector still live under `tools/security`, and several advanced developer-only replay/reprojection commands still call repository security utilities. Those are compatibility/tooling dependencies, not scanner execution dependencies, but they would still need to move or be narrowed before the DeltaScope branch can be packaged entirely on its own.

The next clean separation work is therefore:

1. move the DeltaScope application/workbench modules and Evidence-v2 consumer inspector under a DeltaScope-owned source root;
2. narrow or relocate the advanced SRL corpus-replay/reprojection CLI helpers so the application no longer imports repository security utilities;
3. publish generic result/settlement schemas and richer observation presentation metadata so future providers need even less bespoke UI;
4. keep generic JSON rendering as the fallback for observation types added after a DeltaScope release;
5. once the source boundary is proven, create the dedicated `deltascope` branch/package without carrying SigmaScope scanner sources.

None of these steps changes production security authority.

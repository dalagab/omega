# Collectors and data acquisition

Collectors are named observation providers **owned by first-class Omega components**. They obtain or refresh external facts before those facts are normalized into catalog or security evidence. A collector is not itself a deployable service boundary: the Component Registry defines that boundary, while the Collector Registry defines which typed observations each component can provide.

DeltaScope exposes collector health in the **Operations → Collectors** workspace. The collector view combines bounded recent GitHub Actions history with current published evidence metrics so an operator can answer:

- Did this collector run recently?
- Did the collector-specific workflow step succeed?
- Is its success rate getting worse?
- Is it taking materially longer than its recent baseline?
- Is its parsed output/throughput unexpectedly shrinking or falling to zero?
- Is it late relative to its own recent cadence?
- Where the runner emits both sides of a ratio, are source failures or batch non-completions increasing?
- What input does it consume and what output/artifact does it create?
- What current published-evidence metric demonstrates the resulting coverage?
- Which GitHub Actions runs produced the recent results?


## Component and collector identities

Every collector has a stable `omega.collector.*` identity and a `componentId`. The component owns execution/trust boundaries; the collector owns an observation-provider contract. Stigma-1 rules bind to logical observation types rather than either implementation identity. The Analysis Broker resolves observation → collector → component and may queue work only when the owning component is explicitly marked broker-dispatchable.

Operational views may aggregate collectors by component, but collector health and component launchability are different signals. A healthy collector does not grant its component new authority, and merely registering a planned collector never makes it runnable.

## Health versus trend

DeltaScope deliberately shows two independent states for each collector:

- **Latest state** is the outcome of the newest matching collector step/job: healthy, running, warning, failed, skipped or unknown.
- **Trend state** asks whether recent operational quality is degrading even when the newest run technically succeeded.

A successful green workflow can therefore still receive a trend warning. Examples include a collector that normally discovers about 45 sources suddenly returning 10, a source observer whose failure ratio rises, or a step whose runtime becomes several times slower than its recent successful baseline.

Trend state is diagnostic only. It has `mutationAuthority = none` and is not a Stigma-1 policy input. A collector anomaly cannot create or change a plugin security finding.

## Trend window and API budget

The workbench reads at most eight recent runs per registered workflow. Job/step outcomes and timestamps are retained for that bounded window. To derive throughput history without turning DeltaScope into a GitHub log scraper, job logs are downloaded only for the newest four runs and only for jobs registered as collector producers. Results are cached in memory.

This provides enough recent history for a baseline while keeping GitHub Actions traffic bounded. A manual **Refresh runner history** bypasses the cache once; ordinary navigation reuses the cached projection.

## Signals DeltaScope can derive

### Outcome reliability

DeltaScope calculates recent observed runs, successes, failures and success rate. Multiple recent failures can raise a trend warning even if the latest retry succeeded.

### Duration

Collector-step start/completion timestamps produce a runtime series. The latest runtime is compared with the median of recent successful runs. Material regressions are highlighted; small changes are not treated as faults.

### Throughput and output volume

Only machine-readable values actually emitted by the runner are trended. Examples include:

- deduplicated discovered sources;
- normalized plugin count;
- website records considered;
- source revisions observed;
- OSV package/version pairs queried;
- completed SigmaScope analyses.

For relatively stable universe collectors, a sharp drop or a successful zero result is suspicious. Workload-driven collectors such as SigmaScope are treated differently: a smaller batch is not itself degradation because there may simply be less work due. For SigmaScope, DeltaScope instead checks whether selected work actually completes.

### Freshness

Rather than hard-coding one schedule for every workflow, DeltaScope learns the recent interval between observed runs. A scheduled/continuous collector that drifts materially beyond that recent cadence can become late or stale. Event-driven collectors such as Deep Scan do not receive a stale warning merely because no request was queued.

### Failure/drop ratios where measurable

DeltaScope derives ratios only where the runner exposes both numerator and denominator. Current examples include successful versus attempted manifest sources, failed source-revision observations, and completed versus selected SigmaScope analyses. If a collector does not emit enough information to calculate a duplicate/drop ratio, DeltaScope reports it as unavailable rather than guessing.

## Collector inventory

### Omega Discovery / source intelligence

**Purpose:** continuously map public PluginMaster/source/plugin facts outside the heavy canonical/security pipeline.

**Component:** `omega.discovery`.

**Inputs:** canonical source identities, curated/community registries, Puni.sh, GitHub code search, retained project/README links, source issues, bounded repository trees and an optional configured public web-search API.

**Output:** lease-bound durable result on `catalog-discovery-work-state`, plus a backward-compatible replaceable `catalog-discovery` snapshot containing typed collector observations and reusable normalized shards for Analysis Broker/consumer reuse.

**Implementation:** `tools/catalog/catalog_discovery.py`, `tools/catalog/discovery_collectors.py` and `tools/security/collector_contracts.py`.

**Review signals:** recent `catalog-discovery-worker.yml` lease/result runs for scheduled collection, or `catalog-discovery.yml` for an explicit Analysis Broker full refresh. DeltaScope preserves legacy source-discovery history across the workflow cutover so the Operations trend does not reset merely because the producer moved.

**Authority:** observation-only. Discovery cannot assign catalog identity, freeze Definitions, queue scans, execute rules or publish client/security state.

See **Omega Discovery** for the collector graph, observation schemas and six-hour boundary.

### Manifest normalization

**Purpose:** retrieve PluginMaster feeds and normalize plugin manifests into a consistent source dataset.

**Inputs:** `raw-sources.json`, optional previous-catalog cache hints.

**Output:** `catalog/enriched-sources.json`.

**Implementation:** `tools/catalog/enrich_metadata.py`.

**Useful metrics:** source count, source success/failure, HTTP-not-modified reuse, total plugins and metadata-complete plugins.

### Website/project enrichment

**Purpose:** collect bounded public project-page metadata without re-scraping fresh pages on every catalog run.

**Inputs:** enriched manifests and previous website cache hints.

**Output:** `catalog/website-enrichment.json`.

**Implementation:** `tools/catalog/scrape_websites_incremental.py`.

**Useful metrics:** cached repositories, network-scraped repositories and configured freshness window.

### Source revision observer

**Purpose:** observe public source HEAD revisions without downloading source bodies, allowing source-change events to be queued deterministically.

**Input:** canonical catalog source inventory.

**Output:** `catalog/source-revision-observations.json`.

**Implementation:** `tools/catalog/source_revision_observer.py`.

### Public advisory collector

**Purpose:** query OSV for exact NuGet package/version pairs observed in current plugin evidence.

**Input:** Evidence-v2 NuGet index.

**Output:** frozen advisory data inside Definitions.

**Implementation:** `tools/catalog/collect_public_advisories.py` through the Definitions freezer.

**Useful metrics:** observed package/version pairs, queried pairs, matched pairs, advisory records and packages not covered by the frozen query universe.

### Artifact/security analysis collector

**Purpose:** acquire due plugin artifacts and source evidence, run SigmaScope analysis and produce an Evidence-v2 candidate.

**Inputs:** frozen catalog, Definitions, queue seed and previous last-known-good evidence.

**Output:** new immutable analyses, current variant projections and scanner queue state.

**Implementation:** `tools/security/production_sigmascope_v2_pipeline.py` and the frozen scanner worker.

**Useful metrics:** selected batch size, completed analyses, failures, queue pending/retry counts and current coverage.

### Source follow-up collector

**Purpose:** resolve or refresh source attribution after artifact analysis or source-observation changes.

**Inputs:** current plugin identity, source candidates, source revision observations and artifact evidence.

**Output:** source attribution/provenance observations and follow-up queue state.

### Deep Scan worker

**Purpose:** execute approved, bounded deep-analysis requests that need more evidence than the normal scan budget.

**Inputs:** durable deep-scan queue and exact frozen worker/Definitions state.

**Output:** durable deep-scan results and updated request state.

**Implementation:** `tools/security/deep_scan_worker.py` and `deep-scan.yml`.

## Reading collector health

Collector health should distinguish these conditions:

- **healthy** — the relevant step succeeded in the latest observed run;
- **running** — the collector step or workflow is currently in progress;
- **warning** — recent cancellation/neutral outcome or incomplete coverage metric;
- **failed** — the collector-specific step failed;
- **unknown** — no recent run/step was observed in the bounded history.

A successful workflow is not enough if the collector-specific step was skipped or failed. DeltaScope therefore prefers step-level status when GitHub exposes job steps.

## Adding a collector

1. Give the collector a single clear responsibility and bounded external input.
2. Normalize output into a documented JSON/SQLite contract before other components consume it.
3. Emit machine-readable metadata such as timestamps, counts, success/failure totals and coverage bounds.
4. Retain the output as a named workflow artifact when it is useful for debugging or reproducibility.
5. Add unit tests that mock external transport and validate normalization.
6. Add the collector to the workflow with a stable job/step name.
7. Register the collector in DeltaScope’s collector inventory so Operations can review its recent history.
8. Document which downstream component consumes the output and whether that data has security authority or is contextual only.
9. Register a stable implementation ID in `tools/security/collector_contracts.py` and declare the logical observation types it provides.
10. Put implementation identity/provenance on retained rows, but make Stigma-1 rules bind the logical observation type rather than the implementation ID.
11. If a rule may request additional data, expose it through a typed `observationRequest`; collectors are resolved/executed only by orchestration.

## What collectors must not do

Collectors should not silently turn fetched text into security verdicts. Collection and normalization happen first; security interpretation belongs in scanner logic, Definitions or Stigma-1 rules where it can be reviewed and reproduced.

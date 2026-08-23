# Collectors and data acquisition

Collectors are the parts of Omega that obtain or refresh external facts before those facts are normalized into catalog or security evidence. They are reviewable operational components, not invisible background plumbing.

DeltaScope exposes collector health in the **Operations → Collectors** workspace. The collector view combines recent GitHub Actions history with current published evidence metrics so an operator can answer:

- Did this collector run recently?
- Did the collector-specific workflow step succeed?
- How often has it failed in the recent window?
- What input does it consume?
- What output/artifact does it create?
- What current evidence metric demonstrates coverage?
- Which GitHub Actions run produced the most recent result?

## Collector inventory

### Source discovery

**Purpose:** find public PluginMaster/source feeds.

**Inputs:** curated source registry, validated community source registry, Puni.sh publisher discovery and GitHub search where enabled.

**Output:** `catalog/raw-sources.json`.

**Implementation:** `tools/catalog/collect_sources.py`.

**Review signals:** recent `catalog-builder.yml` / `Discover source feeds` job and its `Discover curated, Puni.sh and GitHub PluginMaster sources` step.

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

## What collectors must not do

Collectors should not silently turn fetched text into security verdicts. Collection and normalization happen first; security interpretation belongs in scanner logic, Definitions or Stigma-1 rules where it can be reviewed and reproduced.

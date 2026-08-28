# DeltaScope Operations: Alpha lane integration

Target: current `deltascope` branch `tools/security/deltascope_operations.py` + `developer_view.py`.

## API

Extend `/api/operations` with `show_alpha=0|1` (default `0`). `GitHubOperationsClient.status()` should accept the same boolean and keep separate cache keys for Alpha-hidden and Alpha-visible projections.

`normalize_run()` should add:

```json
{"lane":"alpha|production","isAlpha":true|false}
```

A run is Alpha only when its trusted workflow/corpus context identifies the lane (for example the Alpha suite workflow and protected `alpha` branch). Do not classify a run as Alpha because a plugin title merely contains the word `ALPHA`.

When `show_alpha=0`, omit Alpha runs from normal component/event rows. When `show_alpha=1`, retain them but keep `lane=alpha` so the UI can render them separately.

When enabled, fail-soft fetch `security-alpha-evidence/index.json` and return it under an `alphaEvidence` member. Never merge those runs/findings into production incident/finding projections.

## UI

In the Operations perspective add a browser-local checkbox:

`[ ] Show ALPHA calibration`

Default OFF. Store only as a local display preference. Toggling it reloads `/api/operations?show_alpha=1`.

When enabled render a separate **Alpha calibration** panel with:

* test id;
* `ALPHA:` finding IDs;
* expected / observed / missing status;
* Alpha corpus commit and registry revision;
* engine revisions;
* GitHub run link.

Use a distinct `ALPHA` badge. Do not add these rows to `Latest security findings`, Incidents, notification severity, marketplace/public summaries, or production counts.

## Current-code fit

The existing Operations module is already a read-only GitHub Actions projection, and the UI already routes `/api/operations` separately from evidence. This change preserves that separation and adds an opt-in Alpha projection instead of creating an Alpha control plane inside DeltaScope.

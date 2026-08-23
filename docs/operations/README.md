# Operations guide

The Operations perspective answers whether the Omega security platform is collecting, analyzing and publishing data as expected.

## Navigation

- **Overview** — current platform/evidence state and important notifications.
- **Pipelines** — recent GitHub Actions workflow history.
- **Collectors** — collector-specific health, recent step outcomes and data/coverage metrics.
- **Scan Queue** — pending, retry and completed analysis work.
- **Evidence** — current publication and raw retained state.
- **Definitions & Gates** — frozen security inputs and authority boundaries.
- **Reports** — derived coverage/readiness summaries.
- **Documentation** — operational and architecture reference.

## Collector review

Collector cards show what each collector consumes and produces, the most recent matching workflow step, recent success/failure history, and current metrics from published evidence where the platform has an exact count.

The GitHub Actions history is a diagnostic source. It does not become security policy. A collector failure can coexist with a valid last-known-good Evidence-v2 snapshot.

## Queue review

Use queue reasons to understand why work exists. A large queue is not automatically a failure; the important questions are whether work is advancing, retry work is bounded, and current coverage metrics match expectations.

## Gates

A gated state means a production authority is intentionally disabled or waiting for a prerequisite. A gate should be visible on the dashboard because it changes what the platform is allowed to publish, even when all underlying services are healthy.

## Incident response for platform failures

1. Identify the collector/pipeline stage.
2. Open its recent Actions run.
3. Verify whether publication was attempted or blocked.
4. Check the current evidence revision and last-known-good status.
5. Inspect queue/retry state.
6. Fix the source of the failure; do not weaken hash, provenance or validation checks just to make publication continue.

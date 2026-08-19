# Omega security services · SigmaScope + DeltaScope

This package is the source intended for the **`sigmascope` branch** of `dalagab/omega`. It contains repository discovery/catalog generation, frozen Definitions, SigmaScope, DeltaScope, Security Evidence v2 publication, source submissions, and their Python regression tests.

It deliberately contains **no Omega C# client source**.

## Services

### SigmaScope 2.9.0
Deterministic static scanner. Plugin artifacts and source are treated as untrusted data and are never executed. The continuous worker consumes the frozen worker bundle from `catalog-data` and publishes validated evidence to `security-evidence-v2`.

### DeltaScope
Developer/operator-only, read-only inspection and audit tooling over published or local SigmaScope evidence. Run it with:

```bash
python tools/security/deltascope.py serve-online
python tools/security/deltascope.py audit --evidence-v2 path/to/security-evidence-v2 --json
```

DeltaScope is not part of the production scanner decision path and has no publication step.

## Branch model

- `sigmascope` — this source.
- `catalog-data` — generated canonical catalog + frozen Definitions + immutable worker bundle.
- `security-evidence-v2` — generated validated detailed evidence.
- `main` — Omega client plus small default-branch launcher workflows.

GitHub schedules run from the default branch, so `main` keeps thin callers that invoke these reusable workflows using `@sigmascope`. The full implementation remains here.

## Workflows owned here

- `catalog-builder.yml` — daily/manual catalog + Definitions snapshot and client marketplace DB compiler.
- `sigmascope.yml` — bounded continuous SigmaScope worker.
- `source-submissions.yml` — validates and persists public source metadata onto `sigmascope`.
- `catalog-compaction.yml` — manual legacy compatibility self-test.
- `regression-tests.yml` — Python/service regression suite for the `sigmascope` branch.
- `deltascope.yml` — manual read-only developer audit.

The scheduled/event launchers with matching names live on `main`; do not move scanner implementation back there.

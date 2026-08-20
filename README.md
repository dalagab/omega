# Omega security services · SigmaScope + DeltaScope

This package is the source intended for the **`sigmascope` branch** of `dalagab/omega`. It contains repository discovery/catalog generation, frozen Definitions, SigmaScope, DeltaScope, Security Evidence v2 publication, source submissions, and their Python regression tests.

It deliberately contains **no Omega C# client source**.

## Services

### Security services 2.13.0 · SigmaScope scanner engine 2.13.0

2.13.0 deepens the native artifact model and implements endpoint intelligence as an explicit evidence contract. Native PE classification now records bounded loader/security characteristics, certificate-table *presence* (never treated as Authenticode verification), section permissions and entropy, and writable+executable sections. A writable+executable native section becomes a bounded caution finding, while entropy and certificate metadata remain contextual structural evidence rather than malware verdicts.

Endpoint evidence now separates **network capability** from **destination literals**. Every retained HTTP(S) literal records its origin type and evidence confidence. Source/config literals therefore remain distinguishable from low-confidence strings embedded in compiled binaries. Source/repository references, community navigation and certificate/revocation metadata stay in the forensic inventory but do not masquerade as concrete destinations. Webhook paths and secret-like path segments remain redacted before persistence. A bounded endpoint summary exposes host/classification/origin counts and an explicit `destinationsUndetermined` state when network capability exists without attributable concrete endpoints.

The existing dependency graph already provides exact-version, advisory, IPC, source/artifact comparison and drift analysis. 2.13 adds a concise **component summary** on top of those authoritative rows: dependency families, exact-version coverage, plugin/IPC relationship summaries, and managed/native relationships that distinguish bundled native components, Windows platform libraries and unresolved/runtime-resolved libraries. Direct compiled IL calls to P/Invoke targets strengthen those native relationship records without claiming runtime execution.

The 2.12 lifecycle/event-driven queue contracts remain unchanged, as do the 2.11 immutable ClamAV/reviewed-YARA contracts and the 2.10 artifact/source-attribution model. Plugin artifacts and source remain untrusted data and are never executed or dynamically loaded.

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

## Discord publication notifications

Public publication notices are built from already-sanitised catalog/SigmaScope outputs. The notice builder has no webhook credential; delivery happens in a separate `discord-public` environment job.

- `tools/notifications/discord_notice.py` — deterministic, sanitised notice builder.
- `tools/notifications/post_discord_notice.py` — isolated webhook sender with a Discord-compliant API User-Agent.
- `tools/tests/test_discord_notifications.py` — notification routing, sanitisation, and voice regression tests.

Message wording is selected deterministically from fixed line pools. No AI or generated copy is used at runtime. Security notices sound mildly irritated, catalog growth sounds wealthy/data-hungry, Definitions updates sound pleased, and ordinary evidence reviews are deliberately a little smug.

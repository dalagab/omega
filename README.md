# Omega security services · SigmaScope + DeltaScope

This package is the source intended for the **`sigmascope` branch** of `dalagab/omega`. It contains repository discovery/catalog generation, frozen Definitions, SigmaScope, DeltaScope, Security Evidence v2 publication, source submissions, and their Python regression tests.

It deliberately contains **no Omega C# client source**.

## Services

### Security services 2.14.0 · SigmaScope scanner engine 2.14.0

2.14.0 turns the reviewed-YARA infrastructure into a real production evidence layer. The initial **Omega Core** seed contains 14 first-party compound rules across credential/token theft + exfiltration, process injection, encoded download/execute, security tampering, embedded PE loading, persistence, and contextual anti-analysis clusters. Rules remain supplemental evidence: a YARA match does not silently modify SigmaScope's native severity or source-review coverage.

YARA now scans both the exact downloaded plugin package container and a **bounded generated view of ZIP members**. Code/config/payload-like members are read through strict byte/count/compression limits and written only under generated temporary filenames; original archive paths are never used for extraction. Evidence-v2 records the original member path, member SHA-256/byte count, scan scope, truncation/skip counts, rule provenance, review hash, reviewer, rule class, confidence, license and false-positive expectation.

The YARA review contract advances to v2. Enabled rules must pin the SHA-256 of the exact reviewed rule bytes, declare every rule name exactly, carry reviewer/class/confidence metadata, and pass a real YARA compile check at the Definitions boundary. Regression CI now triggers on `security-definitions/**` and installs YARA before running tests so rule-only changes cannot bypass validation. Third-party packs are not enabled wholesale; candidate upstreams are kept in a review queue for rule-by-rule provenance/license/false-positive assessment.

ClamAV remains operational through the 2.11 immutable database/executable identity path. The 2.13 native/endpoint/component contracts, 2.12 lifecycle/event-driven queue contracts, and 2.10 artifact/source-attribution model remain compatible. Plugin artifacts and source remain untrusted data and are never executed or dynamically loaded.

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

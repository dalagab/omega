# Omega Security Developer View

This is a read-only developer tool for auditing the conclusions in Omega's published security databases.

## Quick start

```bash
python tools/security/developer_view.py
```

By default it:

1. reads the `security-evidence-latest` and `catalog-latest` GitHub releases;
2. downloads the detailed evidence bundle and the small marketplace database into a user cache;
3. verifies the published SHA-256 sidecars;
4. safely extracts the SQLite databases;
5. opens both databases read-only; and
6. starts a localhost-only browser UI at `127.0.0.1:8765`.

The detailed evidence database is intentionally large. Downloads use a resumable `.part` file, verify the published SHA-256, and invalidate the local cache when the release asset changes. Use `fetch` once if you prefer to download it before opening the UI:

```bash
python tools/security/developer_view.py fetch
python tools/security/developer_view.py serve --no-download --database /path/to/omega-security-evidence.sqlite --marketplace-database /path/to/omega-marketplace.sqlite
```

To preview a local, un-published Security Evidence v2 JSON snapshot directly, without downloading or publishing anything:

```bash
python tools/security/developer_view.py serve --evidence-v2 /path/to/security-evidence-v2
```

The v2 browser reads `index.json` and individual JSON evidence files on demand. It keeps the plugin/detail and evidence-browser views, but deliberately disables the SQL console and marketplace-projection comparison because v2 is a JSON evidence snapshot rather than a SQLite runtime database.

A `GITHUB_TOKEN` or `GH_TOKEN` environment variable is optional and only used to authenticate GitHub API/download requests.

## What can be inspected

The UI exposes current scans per plugin/source variant, static findings and evidence, exact-version OSV matches, dependency resolutions/issues, IPC providers and consumers, required/feature/optional IPC semantics, permission candidates, automation evidence, source build scope, source-to-package comparisons, scan lineage and dependency drift. It also shows how many current rows were produced by the latest scanner generation versus older scanner generations, so zero-count feature cards can be interpreted in the context of incremental rescan coverage. Managed IL/native calls are loaded lazily because they can be large.

The **Evidence browser** is the normal way to traverse the database: choose a grouped table, page through rows, inspect a row, and follow database relationship links into related tables. Summary cards jump directly to the relevant evidence table, and rows containing a plugin variant ID can jump back into the higher-level plugin conclusion view.

When the small marketplace database is loaded too, the inspector independently recomputes the hidden risk score and advisory summary from the detailed evidence and compares those values with the client projection. This makes it possible to catch conclusion/projection drift instead of merely displaying what the marketplace already says.

## Regression/audit mode

The same audit engine is usable in CI:

```bash
python tools/security/developer_view.py audit \
  --database catalog/omega-security-evidence.sqlite \
  --marketplace-database catalog/omega-marketplace.sqlite
```

`audit` returns a non-zero exit code for consistency failures. `--strict-warnings` also treats warnings as a failing exit code. `--json` produces machine-readable results.

Checks include SQLite integrity and foreign keys, current-scan pointers, finding counters and highest-severity reproduction, identical-artifact conclusion consistency, IPC provider-registry consistency, source/package comparison counters, and evidence-to-marketplace security projection consistency.

## Advanced SQL console

SQL is optional. The browser keeps a collapsed raw SQL console under **Advanced** for investigations that are awkward to express through the click-through table browser. The database connection has `PRAGMA query_only=ON`, and the console rejects anything except a single `SELECT`, `PRAGMA`, `WITH`, or `EXPLAIN` statement. Results are bounded to 1,000 rows.

## Security evidence v2 local migration

Omega's detailed security evidence has outgrown a single SQLite file as a transport format. The **client Definitions database remains SQLite**; only the large server-side forensic evidence is being prepared for migration to a sharded v2 format.

Security Evidence v2 is the production scanner state as of Omega 0.8.80. The migration commands below remain useful for reconstructing/bootstraping a v2 snapshot from the archived v1 SQLite evidence, but routine GitHub Actions scanning now updates `security-evidence-v2` incrementally through a staged, fail-closed pipeline.

### 1. Download the current v1 evidence, migrate it locally, and validate it

The recommended operator path is now one command:

```bash
python tools/security/migrate_security_evidence_v2.py \
  --download-current \
  --output /path/to/security-evidence-v2 \
  --resume \
  --validate
```

`--download-current` resolves the live `security-evidence-latest` release, resumes an interrupted `.part` download where possible, verifies the published size and SHA-256 sidecar, invalidates stale cached copies, and safely extracts the SQLite database before migration starts. The default cache is under the user's Omega cache area; use `--cache-dir /path/to/cache` to override it. `GITHUB_TOKEN` or `GH_TOKEN` is optional and is used only for GitHub API/download authentication.

`--validate` runs the **full** v1 ↔ v2 parity validator after migration and writes `<output>/validation-report.json`. Any parity mismatch returns a failing exit code, so the resulting tree cannot be mistaken for publication-ready evidence.

For an already-downloaded or archived database, the offline form remains available:

```bash
python tools/security/migrate_security_evidence_v2.py \
  --database /path/to/omega-security-evidence.sqlite \
  --output /path/to/security-evidence-v2 \
  --resume \
  --validate
```

The source SQLite database is opened read-only and is never modified or deleted. The exporter writes the root `index.json` last, so its presence marks a completed current-state snapshot. If the migration is interrupted, rerun the same command with `--resume`; completed variants are reused when the source database revision is unchanged.

Phase 1 migrates the **current security state**. Historical scans remain preserved in the archived v1 SQLite database while future v2 publications can accumulate immutable content-addressed analyses.

The v2 tree uses:

- `variants/` for per-repository/current-scan identity and derived graph state;
- `artifacts/<sha256>/analyses/<analysis-id>/` for content-addressed scan evidence;
- readable JSON for ordinary findings/dependencies/permissions/automation where bounded;
- deterministic gzip JSONL shards for large symbols/calls/reachability/import collections;
- `indexes/nuget.json` for exact NuGet package/version observations;
- `indexes/ipc.json` for the IPC provider registry;
- `indexes/plugins.json` and `indexes/artifacts.json` for traversal; and
- `index.json` as the atomic root revision pointer.

Identical evidence from mirrors deduplicates to the same analysis ID. The artifact SHA-256 remains the primary grouping key, while the analysis ID is derived from the semantic evidence digests so rescanning the same artifact with materially different evidence does not overwrite a previous analysis.

### 2. Prove parity before publication

```bash
python tools/security/validate_security_evidence_v2.py \
  --evidence /path/to/security-evidence-v2 \
  --report /path/to/security-evidence-v2/validation-report.json
```

When the v2 tree was created by the migration CLI, the validator reads the original local database path from the excluded migration state file. `--database` can still be supplied explicitly if the source database was moved.

Full validation recomputes semantic digests from the v1 database for every current plugin variant, including managed symbols, calls and reachability, and compares them with the v2 analysis manifests. It also checks current/scan/source identity, derived dependency state, NuGet and IPC indexes, advisory/component indexes, every referenced SHA-256 and the 32 MiB per-file publication ceiling.

`--quick` skips the three largest forensic digest comparisons and is intended only for iterative development. Do not use quick mode as the final publication gate.

### 3. Preflight and publish the snapshot branch

```bash
python tools/security/publish_security_evidence_v2.py \
  --input /path/to/security-evidence-v2 \
  --repo /path/to/omega
```

That command is **preflight-only**. If validation has passed and the preflight looks correct:

```bash
python tools/security/publish_security_evidence_v2.py \
  --input /path/to/security-evidence-v2 \
  --repo /path/to/omega \
  --branch security-evidence-v2 \
  --validation-report /path/to/security-evidence-v2/validation-report.json \
  --push
```

Publishing happens from a temporary Git repository and never checks out or rewrites the Omega source tree. The default evidence branch is maintained as a **single snapshot commit** with `--force-with-lease`, so the evidence branch does not build an ever-growing reachable Git history. A push requires a successful **full** parity validation report whose `index.json` SHA-256 matches the snapshot being published. The migration state file and temporary staging data are never published.

The existing `omega-security-evidence.sqlite.zip` remains the archived v1 historical/rollback reference. Production scanning no longer rewrites it. Incremental production updates use `production_security_v2_pipeline.py`, intrinsic snapshot validation, the independent developer audit, and `publish_security_evidence_v2.py` before replacing the `security-evidence-v2` branch snapshot.

### Production v2 update path

The GitHub security workflow performs the production sequence automatically: last-known-good v2 snapshot → disposable working projection → bounded scans → failed-scan rollback to prior current pointers → OSV/dependency/IPC refresh → successful-analysis merge → v2 index rebuild → intrinsic snapshot validation → small marketplace projection → independent audit → atomic v2 snapshot push → client marketplace publication. A failure before the final push leaves the previous published snapshot intact.

`*.deps.json` files inside distributed plugin packages are scanned for exact resolved NuGet package versions (`nuget-resolved`), so OSV coverage no longer depends on project lock/assets files being shipped with the plugin. Publication fails if queryable current NuGet versions exist but the bounded OSV collector does not query the expected package set.

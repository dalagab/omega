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

A `GITHUB_TOKEN` or `GH_TOKEN` environment variable is optional and only used to authenticate GitHub API/download requests.

## What can be inspected

The UI exposes current scans per plugin/source variant, static findings and evidence, exact-version OSV matches, dependency resolutions/issues, IPC providers and consumers, required/feature/optional IPC semantics, permission candidates, automation evidence, source build scope, source-to-package comparisons, scan lineage and dependency drift. It also shows how many current rows were produced by the latest scanner generation versus older scanner generations, so zero-count feature cards can be interpreted in the context of incremental rescan coverage. Managed IL/native calls are loaded lazily because they can be large.

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

## SQL console

The browser view includes a raw SQL console for investigation. The database connection has `PRAGMA query_only=ON`, and the console rejects anything except a single `SELECT`, `PRAGMA`, `WITH`, or `EXPLAIN` statement. Results are bounded to 1,000 rows.

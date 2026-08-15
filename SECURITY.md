# Security policy

## Supported version

Security fixes are made against the current Omega release line. Users should update to the newest published `Omega.zip` through Dalamud when a security-related release is available.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability that could put users at risk. Use GitHub's private vulnerability reporting for the `dalagab/omega` repository when available, or contact the project maintainers privately through the contact route published on the repository.

Include the affected Omega version, the component involved, reproduction details, expected impact, and any logs or proof-of-concept material that can be shared safely.

## Repository security controls

The repository ships workflows for CodeQL code scanning, dependency review, OpenSSF Scorecard analysis, Dependabot updates, signed build provenance attestations for release artifacts, and repository regression tests for workflow permissions/handoffs and the Python catalog tooling. These controls reduce risk but do not constitute a guarantee that Omega or third-party plugins are free of vulnerabilities.

Workflow-critical SQLite/hash validation is implemented in importable Python modules and unit-tested separately from GitHub Actions orchestration. Static workflow-contract tests verify that the scanner remains read-only, the compactor is the security-catalog publisher, upstream workflow names and success gates remain aligned, and release publication stays behind both Python and .NET regression gates.

Omega's runtime SQLite catalog is separately hash-checked and integrity-checked before replacement. A failed online catalog update leaves the last-known-good local database active.

## Third-party plugin scanning

Omega's repository-side plugin security scanner is intentionally static-only. It runs after successful catalog builds, when scanner/schema code changes on the default branch, and on a daily recovery schedule. Third-party plugin packages are downloaded as untrusted data, hashed, inspected without execution, and discarded with the ephemeral GitHub-hosted runner. The scan workflow has read-only repository permissions and produces a security-enriched Actions artifact.

A separate catalog-compaction workflow consumes successful security artifacts, converts redundant large JSON snapshots into bounded summaries, vacuums the SQLite file, verifies preserved historical/normalized row counts and the complete runtime projection, and only then receives write permission to replace the production catalog assets. The uncompacted security database is therefore not promoted to `catalog-latest`.

## Catalog and security revision identity

Published catalogs expose a **Catalog Revision** and **Security Revision** in both SQLite metadata and the release descriptor. The Catalog Revision identifies the logical marketplace plus security state; the Security Revision identifies the normalized static-analysis state and includes the scanner version in its identity. Exact file integrity continues to use the separate SQLite and ZIP SHA-256 values.

Operational timestamps alone do not advance either semantic revision. Meaningful catalog/security changes do. `catalog_changelog` records each published semantic Catalog Revision and the previous revision IDs with bounded change counters. The compaction workflow compares the candidate against the previous production database and skips release replacement when neither semantic state nor a required representation migration changed.

The separate `security-scan-ledger.json` asset records operational revalidation freshness. It is not part of Security Revision calculation. A successful timestamp-only revalidation can update that small ledger without replacing the production SQLite database, preventing repeated stale rescans while keeping semantic identities stable.

The scanner reports observable capabilities such as network access, filesystem writes, process launching, registry/native API use, dynamic code loading, process-memory APIs, game hooking/signature scanning, local listeners, clipboard access, and credential/protected-data APIs. It also records declared and compiled dependency evidence, preserves required/soft/optional dependency semantics, inventories managed assembly references and P/Invoke metadata, records bounded IL call sites and local reachability evidence, resolves current dependencies against the Omega catalog, evaluates conservative version compatibility, and records dependency/permission drift between completed scans.

A static reference, call site, or reachable local path is evidence, not proof that a runtime branch executes. Source inspection is kept separate from published-artifact evidence unless source-to-binary correspondence has actually been verified. Compound rules highlight combinations with higher potential impact, such as network access together with process execution. These findings are security-relevant context, not allegations of malicious behavior.

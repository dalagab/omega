# Security policy

## Supported version

Security fixes are made against the current Omega release line. Users should update to the newest published `Omega.zip` through Dalamud when a security-related release is available.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability that could put users at risk. Use GitHub's private vulnerability reporting for the `dalagab/omega` repository when available, or contact the project maintainers privately through the contact route published on the repository.

Include the affected Omega version, the component involved, reproduction details, expected impact, and any logs or proof-of-concept material that can be shared safely.

## Repository security controls

The repository ships workflows for CodeQL code scanning, dependency review, OpenSSF Scorecard analysis, Dependabot updates, signed build provenance attestations for release artifacts, and repository regression tests for workflow permissions/handoffs and the Python catalog tooling. These controls reduce risk but do not constitute a guarantee that Omega or third-party plugins are free of vulnerabilities.

Workflow-critical SQLite/hash validation is implemented in importable Python modules and unit-tested separately from GitHub Actions orchestration. Static workflow-contract tests verify that the scanner remains read-only, the compaction workflow controls both database publications, upstream workflow names and success gates remain aligned, the client release cannot advance ahead of a required evidence release, and release publication stays behind both Python and .NET regression gates.

Omega's runtime SQLite catalog is separately hash-checked and integrity-checked before replacement. A failed online catalog update leaves the last-known-good local database active.

## Third-party plugin scanning

Omega's repository-side plugin security scanner is intentionally static-only. It runs after successful catalog builds, when scanner/schema code changes on the default branch, and on a daily recovery schedule. Third-party plugin packages are downloaded as untrusted data, hashed, inspected without execution, and discarded with the ephemeral GitHub-hosted runner. The scan workflow has read-only repository permissions and produces a security-enriched Actions artifact.

A separate catalog-compaction workflow consumes successful security artifacts, converts redundant large JSON snapshots into bounded summaries, vacuums the full evidence SQLite database, and verifies preserved historical/normalized row counts and the complete runtime projection. It then projects a physically separate small marketplace database, including only a bounded dependency summary suitable for the client while retaining full dependency evidence server-side. Write permission exists only in the final publication jobs: detailed evidence is published to `security-evidence-latest`, while the client marketplace database is published to `catalog-latest`. The Omega plugin never needs the detailed evidence release.

## Catalog, security, and evidence revision identity

Published marketplace catalogs expose a **Catalog Revision**, **Security Revision**, and **Evidence Revision** in SQLite metadata and release descriptors. The Catalog Revision identifies the logical marketplace plus user-facing security state. The Security Revision identifies the normalized static-analysis conclusions and includes the scanner version in its identity. The Evidence Revision identifies the detailed server-side evidence state, including managed symbols, IL call sites, and reachability material. Exact file integrity continues to use separate SQLite and ZIP SHA-256 values.

Operational timestamps alone do not advance the semantic revisions. Meaningful catalog or security conclusions advance Catalog/Security Revision; detailed forensic evidence changes can independently advance Evidence Revision. The small marketplace database is refreshed when Evidence Revision changes so its troubleshooting identity continues to identify the published evidence state. `catalog_changelog` records each published semantic Catalog Revision and the previous revision IDs with bounded change counters. Publication is skipped when the relevant semantic state and database representation are unchanged.

The separate `security-scan-ledger.json` asset records operational revalidation freshness on the evidence release. It is not part of Security Revision or Evidence Revision calculation. A successful timestamp-only revalidation can update that small ledger without replacing either SQLite database, preventing repeated stale rescans while keeping semantic identities stable.

The scanner reports observable capabilities such as network access, filesystem writes, process launching, registry/native API use, dynamic code loading, process-memory APIs, game hooking/signature scanning, local listeners, clipboard access, and credential/protected-data APIs. It also records declared and compiled dependency evidence, preserves required/soft/optional dependency semantics, inventories managed assembly references and P/Invoke metadata, records bounded IL call sites and local reachability evidence, resolves current dependencies against the Omega catalog, evaluates conservative version compatibility, and records dependency/permission drift between completed scans.

Additional static enrichment records redacted literal HTTP(S) endpoints, hard-coded filesystem paths outside known FFXIV/Dalamud locations when filesystem API evidence is present, and cross-source artifact-hash consensus for matching plugin/version identities. The security workflow also queries OSV for publicly known vulnerabilities affecting resolved NuGet dependency versions already observed in the evidence database. These records are evidence for review: a literal endpoint is not proof of a connection, a path literal is not proof of an access, and a hash mismatch is not by itself proof of tampering.

A static reference, call site, or reachable local path is evidence, not proof that a runtime branch executes. Source inspection is kept separate from published-artifact evidence unless source-to-binary correspondence has actually been verified. Compound rules highlight combinations with higher potential impact, such as network access together with process execution. These findings are security-relevant context, not allegations of malicious behavior.


## Security intelligence storage

Omega separates client-facing marketplace state from detailed static-analysis evidence. `catalog-latest` publishes the small marketplace SQLite projection used by the plugin. `security-evidence-latest` publishes the detailed evidence SQLite database used by repository automation and auditing. The Omega runtime has no evidence database endpoint and does not download that database.

Static automation findings distinguish observational access, game UI/menu automation, character control, and full gameplay automation. Reachability and confidence are recorded separately. These findings describe capability evidence and do not prove that the associated runtime branch executes during normal use.

# Security policy

## Supported version

Security fixes are made against the current Omega release line. Users should update to the newest published `Omega.zip` through Dalamud when a security-related release is available.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability that could put users at risk. Use GitHub's private vulnerability reporting for the `dalagab/omega` repository when available, or contact the project maintainers privately through the contact route published on the repository.

Include the affected Omega version, the component involved, reproduction details, expected impact, and any logs or proof-of-concept material that can be shared safely.

## Repository security controls

The repository ships workflows for CodeQL code scanning, dependency review, OpenSSF Scorecard analysis, Dependabot updates, signed build provenance attestations for release artifacts, and repository regression tests for workflow permissions/handoffs and the Python catalog tooling. These controls reduce risk but do not constitute a guarantee that Omega or third-party plugins are free of vulnerabilities.

Workflow-critical SQLite/hash validation is implemented in importable Python modules and unit-tested separately from GitHub Actions orchestration. Static workflow-contract tests verify that Sigmascope remains read-only, the compaction workflow controls both database publications, upstream workflow names and success gates remain aligned, the client release cannot advance ahead of a required evidence release, and release publication stays behind both Python and .NET regression gates.

Omega's runtime SQLite catalog is separately hash-checked and integrity-checked before replacement. A failed online catalog update leaves the last-known-good local database active.

## Third-party plugin scanning

Omega's repository-side **Sigmascope** engine is intentionally static-only. Sigmascope is a small twist on *Sigmascape*: Omega's data-driven test world for studying unexpected results and gathering evidence. A scope examines closely; the name is deliberately evidence-oriented rather than a claim of final judgement. It runs after successful catalog builds and on a twice-daily recovery schedule. Third-party plugin packages are downloaded as untrusted data, hashed, inspected without execution, and discarded with the ephemeral GitHub-hosted runner. The workflow receives repository write permission only for its final fail-closed Security Evidence v2 snapshot publication and source-follow-up maintenance; scanning itself treats repository and package inputs as untrusted read-only data.

Security Evidence v2 is the authoritative detailed Sigmascope state. The production Sigmascope workflow checks out the last-known-good `security-evidence-v2` snapshot, materializes a disposable bounded SQLite working projection, performs the Sigmascope/OSV/dependency/IPC work, merges only successful new content-addressed analyses into a temporary candidate tree, and validates/audits that candidate before publication. Failed revalidations keep their previous validated current evidence. The client marketplace database is projected separately and published to `catalog-latest` only after the v2 gates pass. The old `security-evidence-latest` SQLite release is archival v1 evidence and is no longer part of the production handoff.

## Catalog, security, and evidence revision identity

Published marketplace catalogs expose a **Catalog Revision**, **Security Revision**, and **Evidence Revision** in SQLite metadata and release descriptors. The Catalog Revision identifies the logical marketplace plus user-facing security state. The Security Revision identifies the normalized static-analysis conclusions and includes the Sigmascope engine version in its identity. The Evidence Revision identifies the detailed server-side evidence state, including managed symbols, IL call sites, and reachability material. Exact file integrity continues to use separate SQLite and ZIP SHA-256 values.

Operational timestamps alone do not advance the semantic revisions. Meaningful catalog or security conclusions advance Catalog/Security Revision; detailed forensic evidence changes can independently advance Evidence Revision. The small marketplace database is refreshed when Evidence Revision changes so its troubleshooting identity continues to identify the published evidence state. `catalog_changelog` records each published semantic Catalog Revision and the previous revision IDs with bounded change counters. Publication is skipped when the relevant semantic state and database representation are unchanged.

Operational revalidation freshness is carried by the current v2 variant/analysis state and Sigmascope metadata rather than by a separate production scan-ledger release asset. Timestamp-only rescans do not change the semantic Security Revision; only materially different normalized conclusions do.

Sigmascope reports observable capabilities such as network access, filesystem writes, process launching, registry/native API use, dynamic code loading, process-memory APIs, game hooking/signature scanning, local listeners, clipboard access, and credential/protected-data APIs. It also records declared and compiled dependency evidence, preserves required/soft/optional dependency semantics, inventories managed assembly references and P/Invoke metadata, records bounded IL call sites and local reachability evidence, resolves current dependencies against the Omega catalog, evaluates conservative version compatibility, and records dependency/permission drift between completed scans.

Dalamud IPC is tracked directionally. `GetIpcProvider` observations register exact channel strings exposed by the scanned plugin, while `GetIpcSubscriber` observations create consumer edges. The current dependency graph resolves subscribers only against an exact registered channel; a unique provider becomes a plugin-to-plugin link, multiple providers remain ambiguous, and missing providers remain unresolved rather than being guessed from naming conventions. Source-assisted consumer edges are conservatively classified as `required`, `feature`, `optional`, or `unknown` with bounded confidence and evidence. A subscriber observation alone is never considered proof of a mandatory provider: High/VeryHigh required status needs strong startup/fatal/direct-use evidence, while availability guards and feature gates lower the relationship to feature/optional; insufficient control-flow evidence stays unknown. Missing or ambiguous high-confidence required providers become dependency issues and are surfaced before installation, but Omega does not automatically install an inferred provider. Provider observations do not by themselves count as consuming another plugin's automation capability.

Additional static enrichment records redacted literal HTTP(S) endpoints, hard-coded filesystem paths outside known FFXIV/Dalamud locations when filesystem API evidence is present, and cross-source artifact-hash consensus for matching plugin/version identities. The security workflow also queries OSV for publicly known vulnerabilities affecting the exact resolved NuGet dependency versions observed for a plugin package. Confirmed advisory matches produce a visible **Known risk** marker and add weight to Omega's bounded internal risk score; the numeric score is intentionally not presented as a safety verdict. These records are evidence for review: a literal endpoint is not proof of a connection, a path literal is not proof of an access, and a hash mismatch is not by itself proof of tampering.

A static reference, call site, or reachable local path is evidence, not proof that a runtime branch executes. Source inspection is kept separate from published-artifact evidence unless source-to-binary correspondence has actually been verified. Compound rules highlight combinations with higher potential impact, such as network access together with process execution. These findings are security-relevant context, not allegations of malicious behavior.


## Security intelligence storage

Omega separates client-facing marketplace state from detailed static-analysis evidence. `catalog-latest` publishes the small marketplace SQLite projection used by the plugin. The `security-evidence-v2` branch publishes the detailed sharded evidence/index snapshot used by repository automation and developer inspection. The archived `security-evidence-latest` SQLite release remains only as a v1 reference. The Omega runtime has no detailed-evidence endpoint and does not download either evidence store.

Static automation findings distinguish observational access, game UI/menu automation, character control, and full gameplay automation. Reachability and confidence are recorded separately. These findings describe capability evidence and do not prove that the associated runtime branch executes during normal use.

### Security evidence v2 migration tooling

The single detailed evidence SQLite file is being prepared for replacement as the **server-side transport/storage format only**. Omega 0.8.78 adds operator-run migration tooling that can convert a downloaded v1 evidence SQLite database into `omega.security-evidence.v2`: per-variant JSON, content-addressed artifact analyses, bounded gzip JSONL forensic shards, and small NuGet/IPC/plugin/artifact indexes. The client-facing marketplace/Definitions database remains SQLite.

Security Evidence v2 is now the production detailed evidence transport. The migration tool remains available for reproducible v1 archival conversion and parity checks; production Sigmascope runs update a staged v2 candidate and can publish it only after intrinsic validation and the independent developer audit pass.

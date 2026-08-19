# Omega security

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could put users at risk. Use GitHub private vulnerability reporting for `dalagab/omega` when available, or contact the project maintainers privately through the repository contact route.

Include the affected Omega version, the component involved, reproduction details, expected impact, and logs or proof-of-concept material that can be shared safely.

## Supported version

Security fixes target the current Omega release line. Users should update Omega through Dalamud when a security-related release is available.

## Sigmascope

Omega's repository-side security evidence engine is **Sigmascope**. Sigmascope performs deterministic static inspection of third-party plugin packages and source material. Plugin packages are treated as untrusted data and are not executed by the scanner.

Sigmascope records evidence such as package hashes, dependencies, reachable APIs, filesystem/network/process indicators, IPC relationships, source provenance, and public advisory matches. Its output is evidence for informed decisions, not a trust verdict or certification.

Security Evidence v2 is the detailed repository-side evidence state. Candidate evidence is staged, validated, independently audited, and published fail-closed: a failed candidate must not replace the last-known-good evidence. The daily `catalog-data` snapshot publishes an immutable queue seed; continuous workers persist only bounded lease/retry progress with Evidence v2 and record the exact catalog, Definitions, rule-set, queue reason, and frozen source commit used for each scan. Continuous Sigmascope workers publish evidence only; they never republish Omega's client database. The daily/manual catalog workflow compiles the smaller marketplace SQLite projection from canonical JSON and the latest already-validated Evidence v2, then reapplies that day's frozen Definitions-derived advisory/catalog conclusions without executing another artifact scan.

## Runtime catalog safety

Omega consumes a small SQLite marketplace database through the catalog descriptor declared in `catalog/catalog-endpoint.json`. The canonical catalog and frozen Definitions live as public JSON on the dedicated `catalog-data` branch; the database is a once-daily (or deliberately manual) compiled projection containing everything the client needs. Downloaded catalog bundles are hash-checked and SQLite integrity-checked before replacement. If an online Definitions/catalog update fails validation, Omega retains the previous local database.

## Repository controls retained in the lean production tree

The production source keeps the workflows and tools required for:

- Omega/.NET regression testing;
- catalog construction and publication;
- Sigmascope and Security Evidence v2;
- plugin-source submission validation;
- release generation and publication.

Website-only build tooling and retired installer helpers are intentionally maintained outside the lean application source tree.

## Third-party plugin risk

Plugins are executable software and may have broad access to data and resources available to the FINAL FANTASY XIV process and the Windows user running it. Automation or other plugin behavior may also place a FINAL FANTASY XIV account at risk.

Omega's presence, indexing, security evidence, or compatibility information is not an endorsement or guarantee that a plugin is safe. The complete user-facing risk disclosure is maintained in `EULA.md`.

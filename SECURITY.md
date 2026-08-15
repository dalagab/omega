# Security policy

## Supported version

Security fixes are made against the current Omega release line. Users should update to the newest published `Omega.zip` through Dalamud when a security-related release is available.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability that could put users at risk. Use GitHub's private vulnerability reporting for the `dalagab/omega` repository when available, or contact the project maintainers privately through the contact route published on the repository.

Include the affected Omega version, the component involved, reproduction details, expected impact, and any logs or proof-of-concept material that can be shared safely.

## Repository security controls

The repository ships workflows for CodeQL code scanning, dependency review, OpenSSF Scorecard analysis, Dependabot updates, and signed build provenance attestations for release artifacts. These controls reduce risk but do not constitute a guarantee that Omega or third-party plugins are free of vulnerabilities.

Omega's runtime SQLite catalog is separately hash-checked and integrity-checked before replacement. A failed online catalog update leaves the last-known-good local database active.

## Third-party plugin scanning

Omega's daily plugin security scanner is intentionally static-only. Third-party plugin packages are downloaded as untrusted data, hashed, inspected without execution, and discarded with the ephemeral GitHub-hosted runner. The scan job has read-only repository permissions; a separate publish job receives write permission only after the scan artifact has been produced and validated.

The scanner reports observable capabilities such as network access, filesystem writes, process launching, registry/native API use, dynamic code loading, process-memory APIs, game hooking/signature scanning, local listeners, clipboard access, and credential/protected-data APIs. It also records declared and compiled dependency evidence, preserves required/soft/optional dependency semantics, inventories managed assembly references and P/Invoke metadata, records bounded IL call sites and local reachability evidence, resolves current dependencies against the Omega catalog, evaluates conservative version compatibility, and records dependency/permission drift between completed scans.

A static reference, call site, or reachable local path is evidence, not proof that a runtime branch executes. Source inspection is kept separate from published-artifact evidence unless source-to-binary correspondence has actually been verified. Compound rules highlight combinations with higher potential impact, such as network access together with process execution. These findings are security-relevant context, not allegations of malicious behavior.

# Security policy

## Supported version

Security fixes are made against the current Omega release line. Users should update to the newest published `Omega.zip` through Dalamud when a security-related release is available.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability that could put users at risk. Use GitHub's private vulnerability reporting for the `dalagab/omega` repository when available, or contact the project maintainers privately through the contact route published on the repository.

Include the affected Omega version, the component involved, reproduction details, expected impact, and any logs or proof-of-concept material that can be shared safely.

## Repository security controls

The repository ships workflows for CodeQL code scanning, dependency review, OpenSSF Scorecard analysis, Dependabot updates, and signed build provenance attestations for release artifacts. These controls reduce risk but do not constitute a guarantee that Omega or third-party plugins are free of vulnerabilities.

Omega's runtime SQLite catalog is separately hash-checked and integrity-checked before replacement. A failed online catalog update leaves the last-known-good local database active.

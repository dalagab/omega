# DeltaScope

**DeltaScope 4.21.8** is the local, read-only investigation and SRL authoring client for Omega security evidence.

This source tree is intentionally independent from the SigmaScope scanner/security-services source tree. DeltaScope consumes published, versioned data contracts and Security Evidence v2 over HTTPS, verifies frozen resource hashes, caches last-known-good revisions, and never downloads or executes SigmaScope worker code.

## Run

```bash
python deltascope.py
```

The first run creates `.deltascope-venv` and installs the pinned dependencies from `deltascope/requirements.txt`. By default the local browser workbench streams published Security Evidence v2 and synchronizes hash-verified Definitions resources.

Useful commands:

```bash
python deltascope.py sync-resources
python deltascope.py serve-online
python deltascope.py rule-schema --json
python deltascope.py capabilities --json
```

Use `--offline-resources` to prohibit resource refresh and use only an already verified cached Definitions snapshot.

## Boundary

DeltaScope may write only local user state (My Rules and Investigator cases). It has no catalog, scanner, evidence-publication, queue, broker, or production-rule authority. Production migration parity and Evidence-v2 reprojection tooling remain in the SigmaScope tree because they depend on production implementation semantics.

The wire boundary is documented in `deltascope/runtime-contract.json`.

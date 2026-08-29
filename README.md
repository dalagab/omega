# DeltaScope

**DeltaScope 4.21.12** is the local, read-only investigation and SRL authoring client for Omega security evidence.

This source tree is intentionally independent from the SigmaScope scanner/security-services source tree. DeltaScope consumes published, versioned data contracts and Security Evidence v2 over HTTPS, verifies frozen resource hashes, caches last-known-good revisions, and never downloads or executes SigmaScope worker code.

## Run

The preferred packaged desktop entry point is the Go shell:

```text
DeltaScope.exe
```

From a source checkout, build it on Windows with `desktop\build.ps1` or run `deltascope-desktop.cmd`. The normal `DeltaScope.exe` is a quiet GUI-subsystem application: Python probes, environment setup, WebView host, and backend processes run without separate console windows and write diagnostics to the desktop log. `DeltaScope-console.exe` is built alongside it for explicit developer/CLI diagnostics. The shell owns the dedicated app window, loopback front door, Python process lifecycle, and shell-side universal downloader. On Windows it prefers a native pywebview/WebView2 window (with Chromium app mode and the normal browser as fallbacks), so the desktop client has DeltaScope application chrome rather than an Edge app-window identity. See `docs/platform/DESKTOP-SHELL.md`.

The independent Python launcher remains supported for development and headless use:

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

# DeltaScope changelog

## 4.21.13 — platform comprehension

- Add a first-class evidence-coverage matrix to each selected plugin so retained, partial, missing, unavailable, not-linked, not-requested and reanalysis-required states stay distinct instead of being mentally reconstructed from several tabs.
- Extend Journey with semantic source-behavior and endpoint threat-intelligence stages while preserving the rule that absent evidence is never presented as a negative/clean result.
- Add semantic behavior chains for retained source operations/value-flow/control-flow, including the current market-data → market-board behavior rules; chains are explicitly static evidence paths rather than runtime claims.
- Verify the published service and semantic-API registries against their SHA-256 descriptors in the current frozen Definitions index before using them as explanatory UI context.
- Add an Operations work-state board over the durable `security-work-state` queues so operators can follow reason → queue → lease → result → settlement without inferring orchestration state from GitHub Actions names.
- Keep all additions consumer-only and fail-soft: no scanner code, Evidence-v2 writer, queue mutation, repository mutation, or new security authority is introduced.

## 4.21.12 — quiet Windows desktop process model

- Make the normal Windows `DeltaScope.exe` a zero-console desktop application and suppress console allocation for Python probes, venv/pip setup, the native window host, and the Python backend.
- Redirect desktop bootstrap/backend diagnostics to a rotating local `desktop.log` instead of flashing command windows at users.
- Build a separate `DeltaScope-console.exe` for explicit developer diagnostics and CLI commands while keeping the ordinary desktop executable quiet.
- Make the source-tree `.cmd` wrapper launch an already-built desktop executable asynchronously so it does not leave a console window open.

## 4.21.11 — fixed research rail + native desktop window

- Keep the desktop left navigation rail fixed and non-scrolling; compact Security Researcher navigation at shorter viewport heights while workspace panels retain their own scrolling.
- Prefer a native pywebview/WinForms WebView2 window on Windows so DeltaScope no longer presents as a Microsoft Edge app-window process.
- Add a shell-only pinned pywebview runtime layer while Go continues to own process lifecycle, reverse proxying, downloads, health, and fallbacks.
- Support a DeltaScope/Omega desktop icon via `--icon`, `desktop/assets/deltascope.ico|png`, or `images/title-icon.png` / `images/icon.png` when those assets are present; PNG artwork is wrapped into ICO without redrawing it.
- Retain Chromium app mode and the system browser as compatibility fallbacks; no desktop window layer gains security authority or a browser-side download endpoint.

## 4.21.10 — Go desktop shell

- Add a Go desktop host that owns a loopback front door and supervises the existing Python DeltaScope backend on an ephemeral private port.
- Open DeltaScope in a dedicated Chromium app window when Edge/Chrome/Chromium is available, with a normal-browser fallback.
- Add a reusable HTTPS-first downloader with SHA-256 verification, byte limits, atomic writes, host restrictions, and safe ZIP/tar.gz extraction.
- Let the Go shell bootstrap/reuse the private `.deltascope-venv` while preserving the standalone Python launchers.
- Keep all evidence, Rules/Stigma-1, triage, Investigator, and security-authority semantics in the Python application; the desktop shell remains transport/lifecycle only.

## 4.21.9 — behavior evidence pivots

- Add a first-class plugin Behaviors view that groups retained matched rows by observed capability/finding.
- Preserve Intelligence pivot context when entering a plugin and show matched evidence inline in the corpus pivot.
- Normalize path, URL, symbol, metadata and manifest evidence so the observed value is the primary researcher datum.
- Add explicit bounded reverse fan-out from one retained evidence value to other current plugins carrying that evidence.
- Keep pivot acquisition read-only and explicit; ordinary navigation never fans out across plugin dossiers.

## 4.21.8 — physical source split

- Package DeltaScope as an independent Python source tree.
- Keep the verified published-resource cache, consumer SDK, local Rules workspace and Investigator cases.
- Remove normal-runtime dependencies on SigmaScope scanner/security-service source.
- Keep production SRL migration parity and Evidence-v2 reprojection in SigmaScope rather than duplicating scanner semantics into the client.
- Move the DeltaScope GitHub Actions workflow contract to the future `deltascope` branch.
- Preserve the rule/registry/topology download boundary: data only, no remote Python/worker code.

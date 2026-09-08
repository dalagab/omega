# DeltaScope Desktop shell

DeltaScope Desktop adds a small Go process around the existing Python research application. The shell owns desktop lifecycle and transport concerns; it does not become security authority and does not reimplement Evidence-v2, SRL, Stigma-1, triage, or Investigator semantics.

```text
Dedicated desktop app window
          |
          v
Go loopback front door (127.0.0.1:8765 by default)
          |
          | reverse proxy
          v
Python DeltaScope backend (127.0.0.1, private ephemeral port)
          |
          v
Published read-only security contracts + local researcher state
```

## Why Go owns the outer shell

The shell gives DeltaScope one place for process supervision, native/platform paths, startup health, bounded downloads, update/runtime acquisition, and future desktop integration. The Python application remains independently runnable through `deltascope.py`, `deltascope.cmd`, and `deltascope.sh`.

The Go front door keeps the historical `127.0.0.1:8765` origin by default so browser-local researcher preferences/history survive the desktop transition; `--port 0` is available when an ephemeral origin is explicitly desired. The Go front door opens before Python. While Python is bootstrapping the private environment or synchronizing startup state, the desktop window shows a local startup page. Once Python prints its loopback ready URL, the Go host switches to a reverse proxy. A backend startup or proxy failure becomes an explicit desktop error page instead of a vanished browser tab.


## Quiet Windows process model

The normal Windows `DeltaScope.exe` is linked as a GUI-subsystem executable and owns no console. Every console-subsystem helper that the shell starts (Python version probes, venv creation, pip, pywebview host, and the Python backend) is created with Windows `CREATE_NO_WINDOW`; output is redirected to `%LOCALAPPDATA%\Omega\DeltaScope\logs\desktop.log` (via the platform user-cache directory) instead of opening terminal windows. The log rotates to `desktop.log.1` after 5 MiB.

`desktop\build.ps1` also produces `DeltaScope-console.exe`. That diagnostic build has one intentional developer console, but its child helpers are still no-window processes whose output is redirected into that single console and the same log. This keeps user launches visually quiet without removing observable startup diagnostics.

## Window strategy

On Windows the preferred presentation layer is a small Python `pywebview` host running a native WinForms window over the installed WebView2 runtime. The Go shell still owns process lifecycle, the loopback front door, proxying, downloads, and shutdown; the Python window helper is presentation-only and exposes no JavaScript API. pywebview is pinned separately in `desktop/requirements.txt` so headless/core DeltaScope dependencies stay minimal.

The native window uses a persistent DeltaScope storage path, preserving the same researcher browser-local state as the previous dedicated app window. The Windows process also sets a DeltaScope application identity instead of presenting as a Microsoft Edge app window.

Desktop artwork can be supplied with `--icon PATH`. Without an override the shell checks, in order, `desktop/assets/deltascope.ico`, `desktop/assets/deltascope.png`, `images/title-icon.png`, and `images/icon.png`. A <=256px PNG is wrapped losslessly into an ICO container for Windows; no artwork is redrawn. This standalone source package does not invent a replacement icon if none of those assets is present.

If the native helper is unavailable, the shell falls back to installed Edge/Chrome/Chromium app-window mode and finally the normal system browser. The backend/downloader contracts do not change when the window adapter changes.

## Runtime ownership

Developer/source-tree launches keep the repository-local `.deltascope-venv`. Managed desktop launches keep one shared private environment under the per-user DeltaScope managed directory so a normal Python/HTML/JavaScript source revision does not rebuild the environment. The requirements digest still controls when pip is run.

Go discovers Python 3.10+, installs `deltascope/requirements.txt`, and starts `tools/security/deltascope.py` directly. Release packaging may place a self-contained interpreter under `runtime/python/`; the runtime resolver already prefers that location before system Python.

No third-party Python runtime is downloaded implicitly by the source updater. A future runtime package may use the universal downloader only after its URL and SHA-256 are pinned by the release process.

## Universal downloader

`desktop/internal/download` is a reusable shell-side downloader with:

- HTTPS-only transport by default;
- optional host allowlists across redirects;
- maximum-size enforcement before and during transfer;
- optional required SHA-256;
- verified destination reuse when a SHA is supplied;
- atomic temporary-file + rename writes;
- bounded ZIP and tar.gz extraction;
- rejection of traversal paths, symlinks, and hard links.

It is deliberately **not** exposed as a same-origin browser endpoint. The desktop CLI can invoke it explicitly:

```text
DeltaScope-console.exe fetch --url https://example.invalid/runtime.zip --out runtime.zip --sha256 <64-hex>
DeltaScope-console.exe fetch --url ... --out package.zip --extract-to runtime/python
```

This package is intended to become the common transport for desktop runtime/update packages and other shell-owned downloads. Existing Evidence/Definitions acquisition remains in Python until a specific acquisition contract is migrated; merely adding the desktop shell must not change evidence semantics.

## Managed DeltaScope source updater

The Go shell is long-lived while the Python/HTML/JavaScript DeltaScope application changes frequently. Ordinary application changes therefore **do not require a new Go build**.

When the executable is not launched from an existing source tree and no explicit `--root` is supplied, it uses managed-source mode. It stores the exact installed `deltascope` branch commit under the per-user DeltaScope cache, checks the public GitHub branch on startup, and checks again every 30 minutes while the application remains open. The branch response is ETag-aware; no GitHub credential is stored or required.

A newer exact commit is downloaded from GitHub's codeload endpoint over HTTPS and through the existing bounded archive extractor. The extracted tree must contain the DeltaScope runtime contract, Python entry point, requirements and canonical DeltaScope icon before it is accepted. The archive SHA-256 is retained as local acquisition provenance.

A startup update is activated before Python starts. An update discovered while DeltaScope is already running is only staged and becomes active on the next start, so source files are never replaced underneath a live backend. The immediately previous revision is retained as known-good; if a newly activated revision cannot start the Python backend, the launcher rolls back and quarantines that failed commit until the branch advances. Other old source directories are pruned.

`--no-update` skips the GitHub check and uses the already installed managed revision. If GitHub is unavailable, the launcher uses the installed valid revision and records the bounded acquisition error; first install still requires GitHub.

Launcher and application versions are separate. `desktop/launcher-version.txt` versions the Go shell, while `deltascope/runtime-contract.json` versions the Python application. The Go executable therefore needs rebuilding only when `desktop/**` or launcher delivery behavior changes. The branch-local `.github/workflows/deltascope-desktop.yml` follows that rule and uses the canonical `desktop/assets/deltascope.ico` artwork for packaged launchers.

A small default-branch registration copy of that workflow is still required so manual dispatch remains available from the repository default branch; it is intentionally a separate patch because it has a different base revision.

Managed state contains only source/update provenance and health: active, previous and staged commits, archive hashes, ETag, timestamps and bounded errors. It contains no GitHub credentials and has no security-authority role.

## Commands

```text
DeltaScope.exe                 # run desktop shell; managed mode checks deltascope branch when no source tree is present
DeltaScope.exe run --no-update  # use the installed managed revision without a GitHub check
DeltaScope.exe run -- --offline-resources
DeltaScope-console.exe doctor
DeltaScope-console.exe fetch ...
DeltaScope-console.exe version
```

Arguments after `--` are passed to the Python `serve-online` command.

From the source tree on Windows:

```powershell
.\desktop\build.ps1
.\dist\DeltaScope.exe              # quiet user-facing app
.\dist\DeltaScope-console.exe doctor # developer diagnostics
```

or, without building first:

```text
deltascope-desktop.cmd
```

The existing Python launchers remain supported fallback/developer entry points.

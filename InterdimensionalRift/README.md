# Interdimensional Rift

> [!IMPORTANT]
> **Do not execute untrusted plugins by invoking `interdimensional-rift` directly.**
> The C# host is instrumentation, not the security boundary. On Linux/GitHub
> use `tools/run-rift-bwrap.sh`; it fails closed unless Bubblewrap can create
> the required namespaces. See `docs/INTERDIMENSIONAL-RIFT-HARDENING.adoc`.
> The current API-15 host/shim also still needs the lifecycle/service-injection
> repair described in that plan before wild-plugin execution is considered
> production-ready.


A Linux-friendly smoke-test runner for opted-in Dalamud plugins. Loads a
plugin DLL outside FFXIV, stubs the full service surface, captures
init-time behaviour, and emits a JSON findings report.

The host never opens a window. ImGui calls go to a no-op stub. The host by
itself does **not** provide OS isolation. The supported hostile-code execution
path is the Bubblewrap supervisor described below. The prototype currently
needs an API-15 lifecycle/service-injection repair before real-world coverage is
considered reliable.

## What it ships

```
InterdimensionalRift.DalamudShim   generated API-15 compatibility surface
InterdimensionalRift               CLI host + instrumentation prototype
samples/SamplePlugin               development fixture
tests/InterdimensionalRift.Tests    xUnit tests (to be tightened in Phase 3)
tools/                             fail-closed Bubblewrap runner/probes
docs/                              hardening and integration plan
Dockerfile                         development image; not the hostile-code boundary
```

## Build

```bash
dotnet build Sigmascope.sln -c Release
```

Requires the .NET 10 SDK (`10.0.101` or newer). The target framework is
`net10.0` — no `-windows` suffix, runs on Linux, Windows, and macOS.

Plugins compiled against `net10.0-windows` will load too. The .NET IL is
portable; only Windows-specific P/Invoke breaks, and that is captured
as a finding rather than crashing the sandbox.

## Development-only direct run

Direct execution is refused by default because the managed host is not the
security boundary. For a local fixture that you explicitly trust:

```bash
RIFT_ALLOW_UNSANDBOXED=1 dotnet run --project InterdimensionalRift -- \
    path/to/SamplePlugin.dll \
    --out report.json \
    --timeout 10
```

Do not use that opt-out for catalog/wild plugins. Use the Bubblewrap path below.

JSON goes to `--out` if set, otherwise to stdout. Human summary (plugin
name, load outcome, finding counts, wall time) goes to stderr.

Exit codes:

| Code | Meaning |
|------|---------|
| 0    | Plugin loaded and `Initialize` completed |
| 1    | Load / init failed; report still emitted |
| 2    | Tool error (bad arg, can't read file) |

## Bubblewrap / GitHub Actions (required for untrusted plugins)

First verify the boundary:

```bash
sudo ./tools/enable-userns-github.sh   # ephemeral GitHub Ubuntu runner only
./tools/verify-bwrap.sh
```

Then run a **self-contained Linux-x64** Rift publication around one read-only
plugin artifact:

```bash
./tools/run-rift-bwrap.sh \
  --runtime-dir ./artifacts/rift-linux-x64 \
  --plugin ./staging/SomePlugin.dll \
  --out ./results/rift.json \
  --init-timeout 10 \
  --wall-timeout 20
```

The wrapper creates separate user/PID/IPC/network/UTS namespaces, clears the
environment, disables nested user namespaces, mounts only the Rift runtime and
plugin input, uses bounded tmpfs scratch areas, and supervises the whole bwrap
process tree with an external wall timeout. There is intentionally no
unsandboxed fallback.

The boundary itself is regression-tested by
`.github/workflows/rift-bubblewrap-boundary.yml`.

## Docker (development only)

The Dockerfile is retained as a development/runtime packaging path. It is **not**
the approved boundary for hostile plugins, and the current generated API-15 shim
still needs its dependency/build-path cleanup before this is considered a
reproducible production image. Do not replace the Bubblewrap executor with a raw
`docker run` fallback.

If Docker is later retained, it should package a self-contained Rift runtime
which is then consumed by the outer fail-closed execution policy described in
the hardening plan.

## Honest limitations

The generated `InterdimensionalRift.DalamudShim` mirrors a current API-15
surface, but the host/stubs still contain lifecycle assumptions from an older
generation. In particular, API-15 constructor/service injection and
`IAsyncDalamudPlugin.LoadAsync(CancellationToken)` are not fully wired yet.
Therefore a `not_a_plugin`, `load_failed`, or static-only report is **not** proof
that a plugin was dynamically exercised.

Rift is also not allowed to become a duplicate static security scanner. The
current `HttpReferenceScanner` is prototype code scheduled for retirement once
the runtime observation contract is landed; SigmaScope remains authoritative for
static analysis. See `docs/INTERDIMENSIONAL-RIFT-HARDENING.adoc`.

## Findings shape

```json
{
  "schema_version": "1",
  "scanner_version": "0.1.0",
  "ran_at": "2026-08-21T12:00:00Z",
  "plugin": {
    "path": "...",
    "assembly_name": "SamplePlugin",
    "internal_name": "SamplePlugin",
    "load_outcome": "ok | init_threw | init_timeout | load_failed | not_a_plugin",
    "load_error": null,
    "init_duration_ms": 142,
    "dispose_outcome": "ok | threw | timeout",
    "dispose_error": null
  },
  "findings": [
    {
      "id": "...",
      "kind": "service_access | log | assembly_reference | reflective_load | init_exception | timeout | capability",
      "severity": "info | low | medium | high",
      "ts_offset_ms": 42,
      "service": "IClientState",
      "method": "get_LocalPlayer",
      "message": null,
      "exception_type": null,
      "exception_message": null,
      "context": "SamplePlugin.Plugin.Initialize",
      "parameters": { "name": "..." }
    }
  ],
  "summary": {
    "total_findings": 12,
    "by_severity": { "high": 1, "medium": 2, "low": 3, "info": 6 },
    "by_kind": { "service_access": 8, "log": 2, "reflective_load": 1, "init_exception": 1 }
  }
}
```

## What gets instrumented

`AccessTracker` is the thread-safe sink. Stubs call into it from the
following services; everything else is recorded at `info`/`low`
severity on call:

| Service              | Severity cap | Why |
|----------------------|--------------|-----|
| `IPluginLog`         | per-level    | Log messages are the most direct signal |
| `ISigScanner`        | low          | Pattern scans are suspicious outside FFXIV |
| `IGameNetwork`       | low          | Network access is high value |
| `IFramework`         | low          | Tick subscriptions reveal the plugin's update strategy |
| `IAddonLifecycle`    | low          | Addon event registration is a UI-affecting surface |
| `IDataManager`       | low          | Excel sheet lookups leak the data the plugin cares about |
| `IChatGui`           | low–medium   | Error/print to chat is a low-trust signal |

`IUiBuilder` is a no-op stub. The plugin can subscribe but nothing
ever draws; the subscription is recorded.

## Static side of the scan

`HttpReferenceScanner` runs *before* load. It reads the DLL's metadata
tables for `AssemblyRef` / `TypeRef` rows that look like network
capability, and walks the user-string heap for URL literals and host
names. The user-string scan is what catches the case where a plugin
bakes `https://attacker.example.com` into a log line — the `AssemblyRef`
walk alone is unreliable on .NET 10 because the SDK type-forwards most
BCL types into `System.Runtime`.

## Tests

```bash
dotnet test InterdimensionalRift.sln -c Release
```

`SmokeTest` builds the sample plugin (via the project reference) and
asserts the report contains the expected log messages, the URL literal
finding, the reflective load attempt, the `init_threw` outcome, and
the `IClientState.LocalPlayer` touch.

## Next steps

See `docs/INTERDIMENSIONAL-RIFT-HARDENING.adoc` and `BRANCH_HANDOVER.md`.


## Pass 2 hostile-code executor

Untrusted runs now require all three outer controls: a cgroup-v2 transient
systemd service, Bubblewrap namespaces/mounts, and a precompiled seccomp BPF
policy. The exact staged artifact directory is mounted read-only so plugin-local
dependencies and content remain available without exposing the repository.

[source,bash]
----
./tools/build-rift-seccomp.sh ./artifacts/rift-seccomp.bpf
./tools/run-rift-bwrap.sh \
  --runtime-dir ./artifacts/rift-linux-x64 \
  --artifact-dir ./staging/plugin \
  --plugin ./staging/plugin/Plugin.dll \
  --seccomp-policy ./artifacts/rift-seccomp.bpf \
  --out ./results/rift.json
----

There is no production fallback when systemd/cgroup-v2, Bubblewrap, or the
seccomp policy is unavailable.

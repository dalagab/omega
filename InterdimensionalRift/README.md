# Interdimensional Rift

> [!IMPORTANT]
> **Do not execute untrusted plugins by invoking `interdimensional-rift` directly.**
> The C# host is instrumentation, not the security boundary. On Linux/GitHub
> use `tools/run-rift-bwrap.sh`; it fails closed unless Bubblewrap can create
> the required namespaces. See `docs/INTERDIMENSIONAL-RIFT-HARDENING.adoc`.
> Rift uses a frozen trusted real `Dalamud.dll` only as the CLR contract/type-identity
> assembly. Real Dalamud host/game services are never instantiated; plugin-facing
> services are Rift instrumentation proxies.


A Linux-friendly smoke-test runner for opted-in Dalamud plugins. Loads a
plugin DLL outside FFXIV, supplies instrumented service proxies against the real
Dalamud API contract, captures lifecycle behaviour, and emits a JSON runtime-observation report.

The host never opens a window. ImGui calls go to a no-op stub. The host by
itself does **not** provide OS isolation. The supported hostile-code execution
path is the Bubblewrap supervisor described below. 
## What it ships

```
InterdimensionalRift               CLI host + instrumentation runtime
build/Rift.Dalamud.Contract.props   fixture compile-time real-contract reference
InterdimensionalRift.DalamudShim    historical generator + DalaInspect metadata tooling
samples/SamplePlugin               API-15 development fixture
tests/InterdimensionalRift.Tests    strict execution regression tests
tools/                             fail-closed Bubblewrap runner/probes
docs/                              hardening and integration plan
Dockerfile                         development image; not the hostile-code boundary
```

## Build

```bash
dotnet build InterdimensionalRift.sln -c Release -p:HooksDir=/path/to/Hooks
```

Requires the .NET 10 SDK. Fixture/test builds also require `HooksDir` (or
`RIFT_HOOKS`) pointing at a frozen trusted Dalamud runtime containing `Dalamud.dll`.
The Rift host itself has no compile-time dependency on Dalamud.

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
| 0    | Plugin reached its API-15 initialization boundary successfully |
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
  --contract-dir ./artifacts/dalamud-hooks \
  --artifact-dir ./staging \
  --plugin ./staging/SomePlugin.dll \
  --seccomp-policy ./artifacts/rift-seccomp.bpf \
  --out ./results/rift.json \
  --init-timeout 10 \
  --wall-timeout 20
```

The wrapper creates separate user/PID/IPC/network/UTS namespaces, clears the
environment, disables nested user namespaces, mounts only the Rift runtime and
plugin input plus the trusted Dalamud contract directory read-only, uses bounded tmpfs scratch areas, and supervises the whole bwrap
process tree with an external wall timeout. There is intentionally no
unsandboxed fallback.

The available fixture reviews are:

* `.github/workflows/rift-canary.yml` — environmental Canary;
* `.github/workflows/rift-alpha.yml` — observation calibration subject.

Only `.github/workflows/rift.yml` runs automatically on direct pushes to `rift`.
It builds Rift and scans the published Omega artifact. Alpha and Canary are
explicit regression runs.

See `docs/RIFT-SANDBOX-PROFILE.adoc` for the current boundary profile.

## Docker (development only)

The Dockerfile is retained as a host-only development/runtime packaging path. It is
**not** the approved boundary for hostile plugins. A real run must receive the frozen
Dalamud contract directory separately and still use the Bubblewrap executor; do not
replace it with a raw `docker run` fallback.

If Docker is later retained, it should package a self-contained Rift runtime
which is then consumed by the outer fail-closed execution policy described in
the hardening plan.

## Honest limitations

Rift does not emulate FFXIV or the full Dalamud runtime. It uses the real frozen
Dalamud assembly only for contract identity and supplies safe instrumentation proxies
for requested service interfaces. Concrete host/game objects generally resolve to
default/null values. A plugin may therefore take a different branch, throw, or stop
early compared with a live game session. `not observed` is never evidence that a
capability cannot be used.

The former generated full-surface C# shim is retired from the active path after CI
proved reflection metadata cannot be naively round-tripped into legal C# for all
Dalamud public shapes. DalaInspect remains metadata/provenance tooling.

Rift is also not allowed to become a duplicate static security scanner. The
`HttpReferenceScanner` has been retired; SigmaScope remains authoritative for static analysis. See `docs/INTERDIMENSIONAL-RIFT-HARDENING.adoc`.

## Runtime observation shape

Rift reports neutral runtime evidence. It does not assign security severity and does
not repeat SigmaScope's static capability analysis.

```json
{
  "schema_version": "rift.runtime-observation.v2",
  "producer": "interdimensional-rift",
  "producer_version": "0.4.1",
  "ran_at": "2026-08-22T08:00:00Z",
  "execution": {
    "executor": "bubblewrap-v2",
    "artifact_tree_sha256": "...",
    "entry_sha256": "...",
    "network": "isolated",
    "seccomp": "enforced",
    "memory_max": "768M",
    "tasks_max": "64",
    "cpu_quota": "100%",
    "memory_swap_max": "0",
    "wall_timeout_seconds": "20",
    "tmpfs_tmp_bytes": "134217728",
    "tmpfs_home_bytes": "16777216",
    "tmpfs_work_bytes": "67108864",
    "boundary_profile": "rift-linux-bwrap-v3",
    "contract_mode": "real-dalamud-contract-failfast",
    "exercise_profile": "post-init-safe-v1",
    "framework_ticks": "3"
  },
  "plugin": {
    "path": "/input/SamplePlugin.dll",
    "assembly_name": "SamplePlugin",
    "internal_name": "SamplePlugin",
    "load_outcome": "ok",
    "init_duration_ms": 101,
    "dispose_outcome": "ok"
  },
  "exercise": {
    "schema_version": "rift.exercise.v1",
    "profile": "post-init-safe-v1",
    "status": "completed",
    "framework_ticks_requested": 3,
    "registrations_discovered": 2,
    "registrations_exercised": 1,
    "registrations_unexercised": 1,
    "by_kind": { "event": 2 },
    "registrations": []
  },
  "observations": [
    {
      "id": "0000000000000001",
      "kind": "service_access",
      "ts_offset_ms": 42,
      "phase": "startup",
      "component": "IClientState",
      "operation": "get_IsLoggedIn",
      "outcome": "observed"
    }
  ],
  "summary": {
    "total_observations": 12,
    "by_kind": {
      "service_access": 8,
      "service_injection": 2,
      "lifecycle": 2
    }
  }
}
```

## What gets instrumented

`AccessTracker` is the thread-safe runtime sink. Current observation kinds are:

| Kind | Meaning |
|---|---|
| `service_injection` | a Dalamud-facing service proxy was injected into plugin code |
| `service_access` | the plugin invoked a method/property/event on an instrumented service |
| `lifecycle` | constructor, `LoadAsync`, framework scenario, or disposal progress |
| `log` | plugin output through `IPluginLog` |
| `assembly_load` | runtime managed assembly resolution or load attempt |
| `native_library` | unmanaged library resolution/load attempt |
| `native_game_state` | explicitly synthetic FFXIVClientStructs state model activity |
| `registration` | event/command/framework/IPC behavior registration or unregistration |
| `exercise` | bounded synthetic post-init trigger and callback outcome |
| `signature_scan` | inert signature/address request observation |
| `hook` | inert synthetic hook lifecycle observation |
| `exception` | plugin initialization/disposal threw |
| `timeout` | a managed lifecycle phase exceeded its bounded timeout |
| `boundary` | Rift recorded an execution-boundary compatibility mode or invariant |

Rift intentionally has no `severity` field. Downstream rules may correlate observations
with SigmaScope/YARA/other evidence, but Rift itself does not decide whether an observation
is malicious.

## Static analysis ownership

Static capability analysis belongs to SigmaScope. The former `HttpReferenceScanner` and
its static `capability` findings have been removed from Rift's active source and report.
A missing runtime observation means only **not observed in the exercised scenario**; it
must never be interpreted as proof that the plugin cannot perform that action.

## Tests

```bash
dotnet test InterdimensionalRift.sln -c Release
```

`SmokeTest` builds the API-15 fixtures against the frozen real Dalamud contract and
requires successful constructor/service injection, framework callbacks, async
`LoadAsync`/`DisposeAsync`, Alpha's inert/armed behavior, Canary's inert behavior, and inert-by-default containment stress fixtures. Positive
fixtures cannot pass as `not_a_plugin`, `load_failed`, or `init_timeout`.

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
  --contract-dir ./artifacts/dalamud-hooks \
  --artifact-dir ./staging/plugin \
  --plugin ./staging/plugin/Plugin.dll \
  --seccomp-policy ./artifacts/rift-seccomp.bpf \
  --out ./results/rift.json
----

There is no production fallback when systemd/cgroup-v2, Bubblewrap, or the
seccomp policy is unavailable.


## Runtime observation contract

Current reports use `schema_version: rift.runtime-observation.v2`. They contain neutral `observations`, per-observation phase attribution, the `rift.exercise.v1` post-init inventory, and a `by_kind` summary. Rift does not emit a security severity, static capability inventory, or malware verdict.


## Platform compatibility evidence

Rift reports the analysis host OS/architecture/RID and native-library resolution attempts. `tools/platform/PlatformEvidenceTool` combines those observations with package RID/native assets and managed metadata into `omega.player-environment-support.v1`. See `docs/PLATFORM-COMPATIBILITY.adoc`.

## Pass 3.4.0 — deterministic post-init exercise

Rift now inventories callback registrations and, after successful initialization, runs the bounded `post-init-safe-v1` exercise profile. It can trigger pinned framework updates, deferred framework callbacks, non-rendering UI open/show/hide callbacks, registered slash commands with empty synthetic arguments, and zero-argument IPC callbacks. `IUiBuilder.Draw` and stateful events remain explicitly unexercised until a matching model exists.

Reports include `phase` on every observation plus a top-level `rift.exercise.v1` inventory with exercised/unexercised registrations and reasons. The default world remains empty, no local player is fabricated, real game memory is absent, native hooks remain inert, and the outer cgroup/Bubblewrap/seccomp boundary is unchanged.

See `docs/POST-INIT-EXERCISE.adoc`.

## Pass 3.4.1 — framework-thread and empty-inventory fidelity

Published Artisan qualification exposed two exercised post-init fidelity gaps: KamiToolKit calls `Dalamud.Utility.ThreadSafety.AssertMainThread()` from deferred framework work, while Artisan's real Framework.Update path initializes `CraftingListUI` through `InventoryManager.Instance()`. Rift now mirrors Dalamud's trusted `[ThreadStatic]` main-thread identity only for the duration of a synthetic framework invocation and restores the previous per-thread value before the worker can be reused. This does not claim to run on the real game thread.

The FFXIVClientStructs model advances to `bounded-empty-v3` by adding a Rift-owned zeroed `InventoryManager`. `Inventories` remains null and no slots, items, currencies, character inventory, or inventory member functions are fabricated. The post-init regression executes both `ThreadSafety.AssertMainThread()` and `InventoryManager.Instance()` from Framework.Update/deferred framework work and verifies that command exercise sees the non-framework thread identity afterward.

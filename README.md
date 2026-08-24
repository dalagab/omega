# Rift

Rift is Omega's isolated **runtime evidence collector** for Dalamud plugins.
It loads a plugin outside the game, gives it a deliberately limited and observable
Dalamud-shaped environment, and writes evidence about what the plugin attempted to
do. It is an inspection tool, not a claim that a plugin is safe.

> **Never run an untrusted plugin by calling the C# executable directly.**
> The supported path is `tools/run-rift-bwrap.sh` on Linux. Bubblewrap, cgroups,
> seccomp, a read-only artifact mount, isolated networking, and an outer observer
> form the execution boundary. The managed host is instrumentation inside that
> boundary, not the boundary itself.

## What this repository contains

| Path | Responsibility |
| --- | --- |
| `InterdimensionalRift/` | .NET host, lifecycle loader, service proxies, evidence reporter, and bounded post-init exercise engine. |
| `InterdimensionalRift.DalamudShim/` | Historical contract/metadata tooling; the live host uses a frozen trusted `Dalamud.dll` for type identity. |
| `build/` | Shared project properties that point fixtures at the frozen Dalamud contract. |
| `tools/run-rift-bwrap.sh` | Fail-closed Linux supervisor: Bubblewrap, cgroup limits, seccomp, artifact staging, timeouts, and report provenance. |
| `tools/collect-rift-observer.py` | Outer `strace` observer for file, process, and network syscall evidence. |
| `tools/collect-rift-runtime.py` | Converts a Rift runtime report into Omega's `omega.collector.rift.runtime.v1` collector record. |
| `tools/scan-rift-components.py` | Records managed and native files shipped with an artifact. |
| `tools/build-headless-cimgui.py` | Builds the inert ImGui ABI shim used by the explicit `headless-ui-v1` profile. |
| `tools/build-rift-minimal-game-data-fixture.py` | Builds a tiny synthetic, non-game-data fixture for explicitly staged Lumina reads. |
| `tests/fixtures/RiftAlpha/` | Deliberately suspicious but harmless calibration plugin. |
| `tests/fixtures/RiftCanary/` | Environmental boundary sentinel. |
| `tests/fixtures/` | Focused service, game-data, native-state, lifecycle, and containment regression fixtures. |
| `tests/InterdimensionalRift.Tests/` | Host and fixture unit/integration regressions. |
| `schemas/` | Versioned schemas for runtime observations, attestations, coverage, and collector output. |
| `docs/` | Boundary, evidence, and operating-profile documentation. |
| `.github/workflows/rift.yml` | Omega production-artifact scan; use this when Rift is integrated at the root of the Omega repository. |
| `.github/workflows/rift-alpha.yml` | Manual Alpha fixture review. |
| `.github/workflows/rift-canary.yml` | Manual Canary fixture review. |

There is intentionally **no fixed workflow for a third-party plugin** in this
repository. Alpha and Canary are the only selectable review fixtures. Production
plugin acquisition belongs to the Omega catalog workflow, where the exact manifest
entry and artifact hash are the ground truth.

## Evidence Rift can produce

Rift records observations rather than verdicts. Depending on the selected profile,
it can record:

- plugin load/init/dispose results and bounded callback exercise;
- Dalamud service, IPC, hook, command, configuration, and game-data API access;
- filesystem, child-process, socket, bind/listen/connect, and dynamic-library
  syscall evidence from the outer observer;
- hashes and inventory of the exact managed/native artifact tree;
- artifact identity, trusted Dalamud contract identity, rule/profile version, and
  supervisor attestation;
- synthetic-only UI and game-data fixture use, where explicitly enabled.

## Important limits

- Rift does **not** run FFXIV, supply real game memory, or use a player's game data.
- `headless-ui-v1` provides an inert ABI shim; it does not render plugin UI.
- `isolated-observed-v1` has no egress. It observes syscall-level network attempts;
  it is not a traffic proxy and does not claim DNS/HTTP payload capture.
- A successful load shows only that the exercised path completed in this synthetic,
  bounded environment. It is not proof of full functionality or safety.
- Do not use real malware, credentials, exploit code, persistence, or destructive
  payloads as test inputs. The included fixtures prove boundary behaviour without
  introducing harmful code into the repository.

## Requirements

Use a disposable Linux machine or an Ubuntu GitHub runner for untrusted input.

- .NET SDK 10
- `bubblewrap`, `libcap2-bin`, `libseccomp-dev`, `gcc`, `pkg-config`, `unzip`, `zip`
- `strace` when collecting outer-observer evidence
- cgroup v2 and a host policy that permits the required unprivileged namespaces
- a **trusted, frozen** Dalamud runtime directory containing `Dalamud.dll`

The GitHub Actions workflows install their own Linux dependencies. The helper
`tools/enable-userns-github.sh` is intended for ephemeral GitHub Ubuntu runners;
do not use it as a generic host-hardening bypass.

## Quick start

Fetch the trusted Dalamud API contract, then run the source and fixture checks:

```bash
mkdir -p .local/dalamud
curl --fail --location --proto '=https' --tlsv1.2 \
  https://goatcorp.github.io/dalamud-distrib/latest.zip \
  -o .local/dalamud.zip
unzip -q .local/dalamud.zip -d .local/dalamud
export RIFT_HOOKS="$PWD/.local/dalamud"

python3 tools/check-rift-source-contract.py
dotnet test tests/InterdimensionalRift.Tests/InterdimensionalRift.Tests.csproj \
  --configuration Release -p:HooksDir="$RIFT_HOOKS"
```

Use GitHub's **Run workflow** control for Alpha or Canary when you want the
full Linux qualification path. They are manual on purpose.

## Publish this folder

Upload the **contents** of this `rift-upload` folder as the root of a Git
repository. Do not upload the surrounding Omega checkout, `out/`, downloaded
plugin artifacts, reports, `.local/`, or a local `.git` directory.

```bash
cd rift-upload
git init
git add .
git commit -m "Add Rift runtime evidence collector"
git branch -M main
git remote add origin <your-git-url>
git push -u origin main
```

Before enabling `.github/workflows/rift.yml`, integrate this repository at the
root of the Omega repository or adapt its explicit Omega release-acquisition
contract. Alpha and Canary do not acquire any external third-party plugin.

## Running an artifact safely

The manifest defines the artifact that runs. Stage the exact downloaded package in
a dedicated directory, record its hash, and do not substitute source or a moving
branch for that identity.

```bash
export RIFT_HOOKS="$PWD/.local/dalamud"
dotnet publish InterdimensionalRift/InterdimensionalRift.csproj \
  --configuration Release --runtime linux-x64 --self-contained true \
  -p:HooksDir="$RIFT_HOOKS" --output .local/rift-runtime

bash tools/build-rift-seccomp.sh .local/rift-seccomp.bpf
bash tools/run-rift-bwrap.sh \
  --runtime-dir .local/rift-runtime \
  --contract-dir "$RIFT_HOOKS" \
  --contract-track release \
  --artifact-dir .local/artifact \
  --plugin .local/artifact/Plugin.dll \
  --seccomp-policy .local/rift-seccomp.bpf \
  --exercise-profile post-init-safe-v1 \
  --framework-ticks 3 \
  --network-profile isolated-observed-v1 \
  --observer-out .local/results/observer.json \
  --out .local/results/rift.json \
  --init-timeout 10 --wall-timeout 20 \
  --memory-max 256M --tasks-max 32 --cpu-quota 100%

python3 tools/collect-rift-runtime.py \
  --report .local/results/rift.json \
  --out .local/results/omega.collector.rift.runtime.json
```

`--network-profile isolated-observed-v1` still denies egress. It requires
`--observer-out`. Add `--ui-profile headless-ui-v1` only to deliberately test a
plugin's UI initialization path. Add `--game-data-fixture-dir` only with a staged,
synthetic fixture created by the Rift tool; never mount real game files.

## Creating a hostile test fixture

Use a **harmless adversarial fixture**, not malware. `RiftAlpha` is the reference:
it contains static vocabulary that security scanners should notice, but its armed
runtime attempts are bounded to sandbox-local temporary files, loopback, missing
executables/libraries, and read-only/nonexistent sentinels.

1. Copy `tests/fixtures/RiftAlpha/` to `tests/fixtures/RiftYourTest/`.
2. Rename the assembly, namespace, and marker prefix (for example, `RIFT_YOUR_TEST`).
3. Keep the plugin inert unless `RIFT_EXECUTOR=bubblewrap-v2` is set by the trusted
   supervisor.
4. Give each probe one controlled purpose and a short timeout. Good examples are:
   a temporary-file write under `/tmp`, a loopback-only connection attempt, a
   missing-library load, an inert API registration, or a bounded background task.
5. Catch and log expected failures. A denied/failed probe is evidence, not a test
   failure by itself.
6. Keep probe targets synthetic and local. Do not access browser profiles, user
   home directories, real game files, credentials, arbitrary Internet endpoints,
   or host services.
7. Build a DLL-only ZIP, stage it as an opaque artifact, and execute it only through
   `tools/run-rift-bwrap.sh` with fixed resource/time limits.
8. Add a small contract checker that asserts the fixture remains inert outside Rift
   and that its expected markers are present. Add a unit test for its expected
   evidence. Do not add a new fixed third-party workflow; use the existing Alpha
   and Canary workflows for baseline qualification.

For resource-boundary testing, reuse the existing `RiftMemoryPressure`,
`RiftTaskPressure`, `RiftTmpfsPressure`, and `RiftHangTree` fixtures. Keep them
non-distributable and run them only on a disposable Linux qualification host.

## Suggested pull-request checklist

- [ ] Artifact identity is keyed by plugin, version, and SHA-256.
- [ ] Source attribution is recorded separately from the published artifact.
- [ ] The test has no real-network endpoint, credential path, destructive action,
      persistence mechanism, or unbounded resource loop.
- [ ] The test remains inert outside the Bubblewrap supervisor.
- [ ] New evidence fields have a schema and an explicit provenance/limit statement.
- [ ] Alpha, Canary, unit tests, source-contract checks, and YAML parsing pass.

## Further reading

- `InterdimensionalRift/README.md` — host behavior and command-line details.
- `docs/RIFT-PENTEST-PROFILES.adoc` — current execution profiles and boundaries.
- `docs/OUTER-OBSERVER.adoc` — outer-observer evidence model.
- `docs/RUNTIME-OBSERVATION-SCHEMA.adoc` — runtime observation format.
- `docs/INTERDIMENSIONAL-RIFT-HARDENING.adoc` — Bubblewrap hardening constraints.

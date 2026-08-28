# Rift Alpha Client

`RiftAlpha.exe` is the downloadable local offensive-security runner. It deliberately does **not** contain Rift's normal Dalamud plugin loader.

The executable recognizes only `Omega.Alpha.IAlphaScenario` workloads. `static-only` Alpha fixtures are refused by the runtime and must be sent to defensive scanners instead.

## Commands

```text
RiftAlpha.exe doctor
RiftAlpha.exe list --corpus <alpha-checkout>
RiftAlpha.exe validate alpha.runtime.sentinels --corpus <alpha-checkout>
RiftAlpha.exe run alpha.runtime.sentinels --corpus <alpha-checkout>
RiftAlpha.exe new alpha.example.my-test --corpus <alpha-checkout>
RiftAlpha.exe registry build --corpus <alpha-checkout>
```

On Windows, runtime execution is delegated to the bundled Linux build under WSL2. The Linux worker then creates a fresh Bubblewrap user/process/network namespace inside a constrained systemd user scope. The Alpha assembly is mounted read-only and the only writable host mount is the run output directory.

Local output is stored under `.alpha/runs/<run-id>/alpha-run.json` and is marked `authority=local-alpha`, `published=false`. It is useful for development and defensive comparison but cannot become production Security Evidence.

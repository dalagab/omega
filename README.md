# Omega Alpha offensive-security calibration corpus

This branch is a **calibration corpus**, not a plugin repository and not production security evidence.

Alpha subjects are deliberately suspicious but harmless test plugins used to prove that Omega's independent security components still observe and classify known behavior. Alpha code may declare what it *expects* to trigger, but those declarations have **zero finding authority**: SigmaScope/Stigma-1 must independently produce every finding.

## Fixed branch model

Use one protected `alpha` branch for the corpus and one durable `security-alpha-evidence` branch for results. Do **not** create a branch or workflow per test.

```
alpha
├── client/RiftAlpha/
├── sdk/Omega.Alpha.Sdk/
├── shared/rift-boundary/
├── tests/<test-id>/alpha.json
├── registry/registry.json        # generated
├── tools/
└── schemas/

security-alpha-evidence
├── index.json
└── runs/<run-id>/...
```

The `alpha` branch owns the downloadable local Rift Alpha runner and its auto-build workflow. Trusted CI can use one Alpha-suite dispatcher to send static artifacts to SigmaScope/SRL and runtime scenarios through the dedicated Rift Alpha execution path. DeltaScope reads Alpha state only when its Operations `Show ALPHA` flag is enabled.

## Trust boundary

* Alpha artifacts are never admitted to PluginMaster, Omega catalog discovery, or normal release feeds.
* Embedding `Omega.Alpha.Sdk` or an `ALPHA:` string in an ordinary plugin does **not** make it Alpha.
* Alpha identity comes only from a selected, revision-bound entry in this registry and the protected Alpha runner.
* Alpha findings are stored separately from production Security Evidence v2.
* Every displayed Alpha finding is namespaced as `ALPHA:<production-finding-id>` while retaining the underlying production rule/finding ID separately.
* The bundled SDK helpers expose only bounded probes (sandbox-local temporary files, isolated loopback, deliberately missing targets, read-only registry access, and harmless process metadata). New candidate scenario code is still treated as untrusted and runs only inside the Rift Alpha boundary.

## Rift Alpha local client

The Alpha branch now contains a dedicated `client/RiftAlpha` executable. It is intentionally a different workload host from production Rift: it references `Omega.Alpha.Sdk` only and has no Dalamud/normal-plugin loader.

A contributor can create and exercise a runtime Alpha locally:

```text
RiftAlpha.exe new alpha.example.my-test --corpus <alpha-checkout>
RiftAlpha.exe validate <alpha-folder> --corpus <alpha-checkout>
RiftAlpha.exe run <alpha-folder> --corpus <alpha-checkout>
RiftAlpha.exe registry build --corpus <alpha-checkout>
```

Every test folder owns an `alpha.json` manifest. `registry/registry.json` is generated from those manifests rather than hand-authored. Runtime tests implement `IAlphaScenario`; static-only tests remain plugin-shaped scanner fixtures and the local client refuses to execute them.

`.github/workflows/alpha-client-build.yml` rebuilds the Windows controller plus bundled Linux/WSL worker whenever the client source, shared Alpha SDK, client/source contracts, or workflow changes. Pushes to `alpha` update the rolling `rift-alpha-client-edge` release.


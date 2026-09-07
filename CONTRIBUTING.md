# Contributing to Omega

Omega is developed across several long-lived branches because its client, security services, runtime sandbox, website, and generated data have different authority and release boundaries. Choose the owning branch before making a change.

## Choose the right branch

| Work | Branch | Start here |
| --- | --- | --- |
| Omega client or client regression tests | `omega` | `Omega/`, `Omega.RegressionTests/`, `Omega.sln` |
| SigmaScope, DeltaScope, Stigma-1/SRL, catalog or security definitions | `sigmascope` | `tools/security/`, `tools/catalog/`, `security-definitions/`, `docs/` |
| Runtime observation or sandboxing | `rift` | `InterdimensionalRift/`, `InterdimensionalRift.DalamudShim/`, `tools/`, `docs/` |
| Public website | `website` | `site/`, `tools/site/` |
| Default-branch workflow registration, release metadata, or issue forms | `main` | `.github/`, `repository/`, `tools/release/` |

`catalog-data`, `security-evidence-v2`, and `deep-scan-state` are publication/state branches. Reviewed tooling and workflows write them; do not treat them as normal source branches.

## Development workflow

1. Fetch the repository and check out the branch that owns your change.
2. Read the README and documentation on that branch.
3. Keep the change inside the component's existing authority boundary.
4. Run the narrowest relevant tests first, then the branch's broader validation.
5. Explain behavioral, schema, authority, or publication changes in the pull request.

Do not mix generated evidence or queue updates into an implementation change unless the documented publication process requires them.

## Omega client

The client source is on `omega`, not `main`. It targets Windows and .NET 10 and expects the Dalamud development runtime used by the regression workflow.

```powershell
git switch omega
dotnet build .\Omega.sln -c Release
```

The solution build includes the client regression project. See [the registered regression workflow](https://github.com/dalagab/omega/blob/main/.github/workflows/regression-tests.yml) for the CI environment and current Dalamud setup.

## Security platform

Before changing security logic, read the [platform overview](https://github.com/dalagab/omega/blob/sigmascope/docs/platform/README.md), [security architecture](https://github.com/dalagab/omega/blob/sigmascope/docs/platform/ARCHITECTURE.md), [extension guide](https://github.com/dalagab/omega/blob/sigmascope/docs/platform/EXTENDING-OMEGA.md), and [security-service boundaries](https://github.com/dalagab/omega/blob/sigmascope/SECURITY-SERVICES.md).

Specialist guides cover [plugin-developer behavior](https://github.com/dalagab/omega/blob/sigmascope/docs/plugin-developers/README.md), [investigations](https://github.com/dalagab/omega/blob/sigmascope/docs/investigators/README.md), [security research](https://github.com/dalagab/omega/blob/sigmascope/docs/security-researchers/README.md), [rule authoring](https://github.com/dalagab/omega/blob/sigmascope/docs/rule-authors/README.md), and [operations](https://github.com/dalagab/omega/blob/sigmascope/docs/operations/README.md).

Prefer reusable observations over scanner-specific conclusions. Preserve source/artifact separation, deterministic rule evaluation, evidence provenance, expected-parent publication, and the read-only boundary of developer and research tools.

## Workflows and publication

GitHub discovers scheduled and manually dispatched workflows from the default branch. Some files under `main/.github/workflows/` delegate to reusable workflows on `sigmascope` or check out source from `omega`.

When changing a delegated workflow:

1. Change the implementation on its owning branch.
2. Change the `main` registration only when its trigger, permissions, inputs, display name, or delegation contract also changes.
3. Keep publication serialized and retain expected-parent and fast-forward protections.
4. Treat generated branches as outputs, not development worktrees.

The [Actions page](https://github.com/dalagab/omega/actions) shows the authoritative status of individual runs.

## Plugin and finding contributions

- Submit a public PluginMaster feed with the [plugin source form](https://github.com/dalagab/omega/issues/new?template=plugin-source.yml).
- Describe expected behavior with the [Omega plugin profile example](https://github.com/dalagab/omega/blob/sigmascope/docs/plugin-developers/examples/plugin.yaml).
- Report incorrect evidence or classifications with the [scanner result form](https://github.com/dalagab/omega/issues/new?template=scanner-result.yml).

Developer declarations provide context but never suppress independent findings or change severity.

## Security reports

Use [GitHub private vulnerability reporting](https://github.com/dalagab/omega/security/advisories/new) for vulnerabilities that could place users at risk. Use the public scanner-result form for non-sensitive corrections. See [SECURITY.md](SECURITY.md) for the client trust boundary.

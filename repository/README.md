# Omega Dalamud repository

`pluginmaster.json` is the public third-party Dalamud repository endpoint registered by the Omega installation script.

When published from the `main` branch its source URL is:

```text
https://raw.githubusercontent.com/dalagab/omega/main/repository/pluginmaster.json
```

The manifest intentionally delegates install/update handling to Dalamud. The stable `Omega.zip` asset on the `omega-latest` GitHub release is maintained by `.github/workflows/release.yml` for each tagged Omega version.

## Optional Omega presentation metadata

A plugin source repository may add `.omega/index.json` for Omega-specific presentation/indexing hints. Version 1 currently recognizes `OmegaBannerUrl`; a 16:9 HTTPS image is recommended. GitHub repositories may use a relative repository path. The metadata is read by the Definitions builder and does not change Dalamud installation authority. Unknown keys are retained server-side for forward-compatible future indexing features.

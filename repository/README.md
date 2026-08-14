# Omega Dalamud repository

`pluginmaster.json` is the public third-party Dalamud repository endpoint registered by the Omega installation script.

When published from the `main` branch its source URL is:

```text
https://raw.githubusercontent.com/dalagab/omega/main/repository/pluginmaster.json
```

The manifest intentionally delegates install/update handling to Dalamud. The stable `Omega.zip` asset on the `omega-latest` GitHub release is maintained by `.github/workflows/release.yml` for each tagged Omega version.

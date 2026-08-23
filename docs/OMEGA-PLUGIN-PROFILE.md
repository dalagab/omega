# Omega plugin profile (`.omega/plugin.yaml`)

The Omega plugin profile is optional developer-authored metadata that explains a plugin’s purpose, expected security-relevant capabilities and project links.

Schema: `omega.plugin-profile.v1`

## Trust model

The profile is **untrusted explanatory context**. SigmaScope parses it with strict size/type/feature bounds, but the author’s declarations are not treated as proof.

A profile cannot suppress independent findings, lower severity, override secondary security engines or establish source-to-binary correspondence.

## Location

Place the file at:

```text
.omega/plugin.yaml
```

in the attributable source repository.

## Top-level fields

```yaml
schema: omega.plugin-profile.v1
profile: {}
capabilities: []
services: []
nativeComponents: []
ipc: []
media: {}
```

Only supported fields are accepted; unknown/unsafe YAML features fail validation.

## Profile metadata

`profile` may include descriptive fields such as:

- `tagline`
- `description`
- `categories`
- `tags`
- `homepage`
- `documentation`
- `support`
- `source`
- `license`
- `securityPolicy`
- `vulnerabilityReporting`

These fields help Omega explain and index the plugin.

## Capability declarations

A capability declaration uses a canonical capability ID from the Omega capability registry.

```yaml
capabilities:
  - id: network.http
    expected: true
    required: true
    reason: Retrieves user-selected metadata from the service.
    destinations:
      - api.example.org
```

Important fields:

- `id` — canonical capability ID;
- `expected` — whether the developer expects the capability to be observed;
- `required` — whether it is necessary for the plugin’s intended function;
- `reason` — human-readable justification;
- `destinations` — expected hostnames for network capabilities where useful.

## Observed versus declared behavior

SigmaScope can compare retained observations with the profile and report states such as:

- observed and explained;
- observed but undeclared;
- observed even though declared not expected;
- declared expected but not observed;
- observed destination not covered by the developer declaration.

These consistency results are context for users/reviewers. They do not replace the underlying scanner evidence.

## Building a profile in DeltaScope

Open Plugin Developer → Omega Profile. DeltaScope pre-populates what it can from the retained profile and observed capability set. You can add explanations, expected destinations and project metadata, then validate and copy/download the YAML.

The browser does not write the profile to your repository. Commit the generated file through your normal source-control workflow.

# Enriching an Omega plugin with `.omega/plugin.yaml`

Status: implemented in SigmaScope 2.15.0 (`omega.plugin-profile.v1`).

Omega can read optional, source-controlled developer metadata from a plugin's public source repository. The purpose is transparency: developers can improve the plugin profile and explain why permission-like capabilities are expected, while SigmaScope independently records what the artifact/source actually demonstrates.

## The trust boundary

`.omega/plugin.yaml` is **developer-provided context**, not scanner authority. It cannot mark a plugin safe or trusted, change SigmaScope severity, suppress a finding, override YARA/ClamAV/OSV evidence, claim source-to-artifact verification, or alter review coverage. Omega should display the explanation as developer-provided text so users can decide for themselves whether it is persuasive.

A declaration such as `process.execute: expected` means only "the developer says this behavior is intentional." SigmaScope still records process-execution evidence independently. Conversely, `expected: false` is useful: if SigmaScope later observes that capability, Omega can show a strong behavior-consistency mismatch without claiming malicious intent.

## Where the file goes

The preferred location is:

```text
<plugin project>/.omega/plugin.yaml
```

When SigmaScope can identify a primary project file, it first checks `.omega/plugin.yaml` next to that project. It then falls back to repository-root `.omega/plugin.yaml`. This allows monorepositories to give each plugin its own profile without forcing one repository-wide declaration onto every project.

Only source material that has passed SigmaScope's existing public-source retrieval/attribution boundary is considered. The profile observation records its repository context through the enclosing source evidence, plus the exact profile path, SHA-256, byte count, validation status, and capability-registry revision.

## Starter file

Copy `docs/plugin-developers/examples/plugin.yaml` into your repository and remove anything you do not need.

Validate it from an Omega Security Services checkout:

```bash
python -m pip install -r tools/requirements-security.txt
python tools/catalog/plugin_profile.py validate path/to/.omega/plugin.yaml
```

For machine-readable diagnostics:

```bash
python tools/catalog/plugin_profile.py validate path/to/.omega/plugin.yaml --json
```

Print the bundled example:

```bash
python tools/catalog/plugin_profile.py example
```

List the currently accepted capability IDs:

```bash
python tools/catalog/capability_registry.py list
```

## Schema

The root object accepts exactly:

```yaml
schema: omega.plugin-profile.v1
profile: {}
capabilities: []
services: []
nativeComponents: []
ipc: []
media: {}
```

Unknown fields are rejected so typos do not silently become meaningless metadata.

### `profile`

Optional fields:

| Field | Meaning |
| --- | --- |
| `tagline` | Short profile line, max 180 characters. |
| `description` | Longer developer description, max 8,000 characters. |
| `categories` | Up to 16 short developer categories. |
| `tags` | Up to 32 short developer tags. |
| `homepage` | Public HTTPS URL. |
| `documentation` | Public HTTPS URL. |
| `support` | Public HTTPS URL. |
| `source` | Public HTTPS source/project URL. This is a developer link, not source verification. |
| `license` | Short license identifier/text. |
| `securityPolicy` | Public HTTPS security-policy URL. |
| `vulnerabilityReporting` | Public HTTPS vulnerability-reporting URL. |

URLs must be HTTPS, must not embed credentials, and cannot use localhost/private/reserved IP literals.

### `capabilities`

Each capability declaration accepts:

```yaml
- id: network.http
  expected: true
  required: false
  reason: Retrieves data from the documented service.
  destinations:
    - api.example.com
```

`id` must resolve through the shared SigmaScope capability registry. Historical aliases are accepted and normalized to the canonical ID. `reason` is mandatory. `expected` defaults to `true`; `required` defaults to `false`.

`destinations` is only accepted for registry entries marked destination-aware. Values are hostnames, not URLs. A leading wildcard such as `*.example.com` is allowed by the schema. Declared destinations are explanatory expectations; observed network endpoints remain independent evidence.

### `services`

A service documents an external service the plugin expects to use:

```yaml
- id: universalis
  name: Universalis
  url: https://universalis.app
  purpose: Market-board data used by an optional feature.
  required: false
```

The service does not automatically whitelist its host. Future behavior-consistency rules can compare declared services/destinations with SigmaScope endpoint observations.

### `nativeComponents`

```yaml
- name: Example.Native.dll
  purpose: Image codec used for profile rendering.
  required: true
```

This is an explanation for expected native material. SigmaScope's binary/import evidence remains authoritative about what is actually bundled or referenced.

### `ipc`

```yaml
- plugin: AllaganTools
  channel: AllaganTools.GetInventory
  purpose: Reads optional inventory information.
  required: false
```

At least `plugin` or `channel` is required. The declaration does not create or alter an IPC relationship in SigmaScope evidence.

### `media`

```yaml
media:
  icon: .omega/media/icon.png
  banner: https://example.com/banner.png
  screenshots:
    - .omega/media/settings.png
```

Media values may be safe repository-relative paths or public HTTPS URLs. Repository-relative paths cannot be absolute or contain `..`. SigmaScope records the references; consumers decide how/when to fetch or render media.

## Shared capability vocabulary

The canonical registry lives at:

```text
security-definitions/capabilities/registry.json
```

Its schema is `omega.sigmascope.capability-registry.v1`. Every entry has a stable ID, category, end-user label, description, aliases, optional attributes, and deprecation/replacement fields. `.omega`, DeltaScope, future SRL rules, and Omega UI should normalize through this same vocabulary.

Do not invent arbitrary IDs in a profile. If a capability is missing, propose a registry addition rather than creating a private spelling. A registry change is reviewed security-definition data because it affects the common language used by developers, rule authors, and users.

## Parsing and safety limits

Profiles are untrusted input. SigmaScope uses PyYAML SafeLoader plus stricter rules:

- maximum profile size: 64 KiB;
- UTF-8 only;
- maximum nesting depth: 8;
- maximum structural nodes: 1,024;
- YAML token ceiling: 4,096;
- no anchors or aliases;
- no explicit YAML tags;
- no merge keys;
- no duplicate mapping keys;
- no custom object construction;
- no includes/templates/environment expansion;
- no filesystem reads initiated by YAML content;
- no network requests initiated by YAML content.

Collection limits include 64 capabilities, 32 services, 64 native-component declarations, 64 IPC declarations, 32 tags, 16 categories, 12 screenshots and 32 destinations per capability.

A malformed profile is **fail-soft**. The plugin/source analysis remains usable and records profile diagnostics; profile enrichment does not make a plugin disappear and does not turn source retrieval into a scanner failure.

## Forbidden authority claims

The validator rejects authority-like fields anywhere in the document, including variants of concepts such as `safe`, `trusted`, `riskScore`, `severity`, `verdict`, `suppress`, `allowlist`, `yaraSafe`, `clamavSafe`, `sourceVerified`, `sourceToBinaryVerified`, `reproducible`, artifact SHA overrides, review coverage and attribution confidence.

If Omega later needs reviewed exceptions or policy, that belongs in an Omega-controlled Definition/Policy surface with provenance—not in developer-authored metadata.

## What users should eventually see

The intended UI compares declarations with observations rather than replacing them:

- **Declared + observed** — developer says it is expected and SigmaScope sees it.
- **Observed + undeclared** — SigmaScope sees a capability with no developer explanation.
- **Declared + not observed** — developer documented an optional/conservative capability that current static evidence did not establish.
- **Not expected + observed** — developer explicitly says it should not occur, but SigmaScope sees it; this deserves review.

Security hygiene (YARA/ClamAV/OSV/etc.), capability evidence, behavior consistency, and source/artifact provenance remain separate dimensions.

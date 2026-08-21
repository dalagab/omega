# `.omega` developer profile architecture

Status: **v1 implemented in the unreleased 2.15 development line**. Deterministic observed-vs-declared comparison is also implemented locally as `omega.sigmascope.behavior-consistency.v1`; future Omega client UI and SRL-based correlation remain planned.

## Purpose

`.omega/plugin.yaml` lets plugin developers enrich their Omega profile and explain expected capabilities, external services, native components and IPC relationships from source-controlled metadata. It is deliberately separated from SigmaScope's independent evidence.

The invariant is:

> `.omega` is developer claim/context. SigmaScope is independent observation. Omega shows both. The user decides what they are comfortable with.

Developer metadata cannot suppress findings, lower severity, declare trust/safety, override YARA/ClamAV/OSV, claim artifact hashes, or claim source-to-artifact verification.

## Implemented discovery

The canonical file is:

```text
.omega/plugin.yaml
```

For monorepositories SigmaScope first checks the `.omega/plugin.yaml` adjacent to the selected primary project file, then repository root. The profile is only parsed from source already obtained through the existing attributed public-source path. The source evidence retains repository/ref/provenance; the profile observation adds exact path, SHA-256, byte count, validation status and normalized profile content.

Invalid metadata is fail-soft and never makes the plugin/source scan disappear.

## Implemented schemas

Developer document:

```text
omega.plugin-profile.v1
```

Scanner observation wrapper:

```text
omega.plugin-profile-observation.v1
```

The exact public schema, limits, examples and validator commands live in `docs/plugin-developers/README.md`.

The implemented root shape is:

```yaml
schema: omega.plugin-profile.v1
profile: {}
capabilities: []
services: []
nativeComponents: []
ipc: []
media: {}
```

A representative capability declaration is:

```yaml
capabilities:
  - id: network.http
    expected: true
    required: false
    reason: Retrieves optional data from the documented service.
    destinations:
      - api.example.com

  - id: process.execute
    expected: false
    required: false
    reason: This plugin does not intentionally start external processes.
```

`expected: false` is an explicit negative expectation. It does not make absence/provenance claims; it gives future behavior-consistency logic useful developer context if independent evidence observes the capability.

## Shared capability registry

The v1 source of truth is:

```text
security-definitions/capabilities/registry.json
```

Contract:

```text
omega.sigmascope.capability-registry.v1
```

SigmaScope, profile validation, DeltaScope and future SRL/Omega UI normalize against the same IDs. The registry currently carries stable ID, category, label, description, aliases, optional semantic attributes, and deprecation/replacement metadata. Its content is canonicalized into a `capabilities-v1-...` revision.

The implementation deliberately treats the capability vocabulary as descriptive, not verdict-bearing.

## Parser/security boundary

The implementation uses pinned PyYAML SafeLoader plus stricter deterministic checks. Profiles are bounded to 64 KiB, UTF-8, nesting depth 8, 1,024 nodes and 4,096 YAML tokens. Anchors, aliases, explicit tags, merge keys and duplicate mapping keys are rejected. URLs must be public HTTPS where URL fields are permitted. YAML never gets filesystem/network/process/environment authority.

Authority-like fields are rejected recursively, including safety/trust/risk/verdict/severity/suppression/allowlist/AV override/source-verification/artifact-hash/review-coverage concepts.

## Evidence and marketplace projection

The normalized profile is stored with source analysis and carried through compact Evidence-v2 source transport. Marketplace projection exposes bounded profile status/SHA/JSON for future Omega UI use. DeltaScope already renders the developer profile separately and labels explanations as developer-provided.

Phase 3 declared-vs-observed comparison is now implemented locally without altering native findings.

## Implemented behavior-consistency layer

`omega.sigmascope.behavior-consistency.v1` currently compares:

- declared expected + observed;
- observed + undeclared when a valid profile exists;
- declared expected + not observed;
- explicitly not expected + observed;
- explicitly not expected + not observed;
- observed capability with no valid profile (`observed-no-profile`);
- concrete observed endpoint hosts vs declared capability destinations/services.

Native-component and IPC explanations remain retained developer context. Phase 4 now provides stable typed observation collections for these families; direct native/IPC declaration comparison is still a later behavior-consistency enhancement and must use those registered observations rather than ad-hoc derived data.

The comparison preserves analysis coverage/provenance and does not overinterpret absence as proof. `.omega/plugin.yaml` is excluded from normal source-code evidence scanning so developer declarations cannot create their own observed endpoints/capabilities. See `docs/BEHAVIOR-CONSISTENCY.md`.

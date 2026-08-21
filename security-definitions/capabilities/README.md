# SigmaScope capability registry

`registry.json` is the source-controlled vocabulary shared by SigmaScope observations,
`.omega/plugin.yaml` declarations, DeltaScope rule-author tooling, and eventually the
Omega client.

The registry is descriptive, not a verdict system. Capability IDs describe what static
evidence says code can access or control. They do not mean a behavior executed at runtime
and they do not imply malicious intent.

Rules for changes:

- IDs are stable once published.
- Renames use aliases/deprecations; do not silently recycle an ID for new semantics.
- Labels are user-facing and may improve without changing the ID.
- A registry change is validated at the Definitions boundary.
- Developer declarations may reference canonical IDs or documented aliases, but stored
  normalized profiles always use the canonical ID.

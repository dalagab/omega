# DeltaScope changelog

## 4.21.8 — physical source split

- Package DeltaScope as an independent Python source tree.
- Keep the verified published-resource cache, consumer SDK, local Rules workspace and Investigator cases.
- Remove normal-runtime dependencies on SigmaScope scanner/security-service source.
- Keep production SRL migration parity and Evidence-v2 reprojection in SigmaScope rather than duplicating scanner semantics into the client.
- Move the DeltaScope GitHub Actions workflow contract to the future `deltascope` branch.
- Preserve the rule/registry/topology download boundary: data only, no remote Python/worker code.

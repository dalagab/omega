# Omega security architecture and authority model

This document is the concise technical architecture contract. For the broader platform manual, start with `docs/platform/README.md`.

## Component boundary

```text
Public ecosystem → Omega Discovery collectors → typed candidate observations → Catalog
                                                                    ↓
                                              SigmaScope → retained security observations
                                                                    ↓
                                              Stigma-1 ← collector observation bundles
                                                   │       │
                                      analysisRequest       observationRequest
                                                   │       │
                                                   ↓       ↓
                                            orchestrated evidence acquisition
                                                   │
                                                   ↓
                                          Security Evidence v2 → DeltaScope / Omega
```

Rift is a separate experimental execution branch; Alpha is a component inside Rift. Neither is part of the ordinary SigmaScope scan path.

## Authority rules

- External/project data is untrusted until normalized and attributed.
- The installable artifact is the primary security subject.
- Public source is separate evidence unless source-to-artifact correspondence is verified.
- Developer declarations explain expected behavior but cannot suppress evidence.
- Secondary engines provide supplemental evidence.
- SRL rules can only consume registered bounded inputs; collector implementation identity remains provenance/provider metadata rather than an executable rule hook.
- `observationRequest` can name only a logical registered collector observation type; provider resolution is non-executable and orchestration retains execution authority.
- Local DeltaScope rules have no production authority.
- Current active plugin state drives current totals; historical snapshots are archive evidence.
- Evidence integrity failures fail closed.

## Change/reanalysis rules

A plugin/artifact may need new analysis when its artifact identity changes, when a required observation was never retained, or when a scanner primitive changes. A rule/Definitions-only change can be reprojected over retained observations when the observation contract says those inputs are sufficient.

## Reviewability

Every published conclusion should be traceable through:

finding → rule/detector → fact/selector → retained observation → artifact/source identity → Definitions/scanner provenance.

# External analysis research sources

This registry tracks public analyzer projects that may inform **native SigmaScope detector development**. It is a research/provenance surface, not a runtime rule feed and not a security authority.

The intended flow is:

`external source -> reviewed detector concept -> native SigmaScope implementation -> observation/evidence -> SRL / Stigma-1 interpretation`

Rules and implementation code are **not** automatically imported. Every entry records its current license class and an explicit usage policy. Restricted source-available or rules-only licenses are kept metadata-only so tooling cannot silently ingest code that the license does not permit us to use that way.

Changing this registry alone must not trigger artifact rescans or alter SRL findings. A detector only becomes authoritative input after it is independently implemented in SigmaScope, covered by tests, and emitted through the normal observation/evidence contracts.

Use `python tools/security/external_analysis_sources.py validate` to validate the registry and print its deterministic revision.

A durable `external-analysis-sources` orchestration lane refreshes this registry once per day. That worker records HEAD revisions only for entries that explicitly allow both automated inspection and AI ingestion. Restricted entries, including metadata-only rule/source-available projects, are carried forward as registry metadata without source-body fetches, rule imports, or analyzer execution.

Catalog freeze consumes the settled lane result as `external-analysis-sources.json` inside frozen Definitions so scanner runs can prove which external research inputs were current, while still treating native SigmaScope code and SRL packs as the only rule authority.


# Security Researcher guide

The Security Researcher perspective is for ecosystem-wide questions, rule development and low-level evidence analysis.

## Common workflows

### Find patterns across plugins

Use Intelligence and Relationships to pivot through endpoints, dependencies, advisories and shared components. Use global search for exact hashes, rule IDs, CVEs or endpoint text.

### Compare plugin versions

Use Compare to inspect security-semantic changes such as new/removed findings, capabilities, endpoints, source coverage and artifact identities. Historical snapshots remain available even though only the current version contributes to current headline totals.

### Inspect raw evidence

System/Data exposes the raw Evidence-v2/database browser. Use it when the higher-level projection does not expose enough detail. Raw evidence is read-only.

### Author rules

Rules provides both repository System Rules and local My Rules. System Rules are read-only. Local rules can be created, forked, validated, visualized, dry-run, replayed and exported without production authority.

## Research discipline

- Do not infer runtime execution from static capability evidence.
- Keep source and artifact conclusions separate unless correspondence is verified.
- Check observation completeness before using absence as evidence.
- Distinguish current plugin state from historical archive snapshots.
- Preserve exact rule and Definitions provenance when reproducing a conclusion.
- Use developer declarations as context, not as a security override.

## Extending the detection system

Read **Detection systems**, **Tagging and classification**, **Extending Omega security logic**, the **Rule data reference**, and **Definition Packs** before adding new logic. Prefer retaining a reusable primitive observation over embedding a one-off hard-coded conclusion in the scanner.

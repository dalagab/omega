# Security Researcher guide

The Security Researcher perspective is for ecosystem-wide questions, rule development and low-level evidence analysis.

## Common workflows

## Researcher landing page

The Overview is a hypothesis-oriented landing page rather than an operations dashboard. It keeps the production authority strip visible, then prioritizes:

- **Research delta** against the previous Evidence revision observed by this local DeltaScope instance. This is local comparison context, not a claim that DeltaScope has a complete global publication history.
- **Pattern clusters** from the bounded newest-finding window, ranked by spread and severity so recurring techniques are more visible than individual plugin rows.
- **Coverage gaps worth researching** from the exact current producer/revision coverage projection, especially where active rules depend on the affected observation family.
- **TONI research leads**, which are deterministic hypotheses assembled from those same retained signals and never become findings.
- **Your research context**, using local Investigator cases, pins and notes.

Corpus/queue throughput metrics remain available in a collapsed operational-context section. Components & Actions and plugin-by-plugin operational priority lists belong to the Operations perspective; per-plugin deep dives belong to Investigator or Plugin Developer.

DeltaScope deliberately does not label a rule “dead” merely because it is absent from a bounded recent-finding window. Exact 30/60/90-day rule-frequency and unmatched-finding research requires a publication-level frequency/time-series index. Until that index exists, the researcher landing page surfaces exact producer coverage gaps and labels bounded novelty honestly.

### Triage the Findings inbox

Findings is a **case inbox**, not a flat database view. One row represents one current derived plugin case; the right-hand panel contains the contributing findings and resolution paths. Published findings remain immutable. DeltaScope stores triage metadata separately under the local Findings triage store.

Local case/finding states are `new`, `triaging`, `investigating`, `escalated`, `resolved`, or `dismissed`. Owner, disposition reason, and last-activity time are local workflow metadata only; they never suppress SigmaScope evidence, alter severity, feed SRL/Stigma-1, or write to GitHub. Escalated and dismissed states require a reason. A new scan produces a new derived incident identity, so prior local disposition is not silently applied to new evidence.

The default saved view is **Since last visit**. **My open findings** becomes available after a local researcher name is set. Severity, time, status, and owner filters operate over the exact derived case list. Rule/category/pattern filters use the explicitly bounded 100-newest-finding context window; DeltaScope labels this boundary and does not claim corpus-wide first-seen or historical-baseline semantics without a publication-level time-series index.

Case resolution is finding-oriented: **Confirm expected** opens the Plugin Developer context and marks the local finding triage as in progress; **Trace lineage** opens the retained evidence/rule explanation; **False positive** and **Real concern · escalate** require a local reason. Bulk case triage is also local-only.

### Find patterns across plugins

**Intelligence** is the fast corpus-pivot surface: answer a lookup question in seconds, then move to Research when the question needs deep study. The default right-hand pane is a corpus intelligence brief rather than an empty state. It highlights local snapshot novelty, strong co-occurrence pairs, visible source-lineage families, author clusters and bounded behavior signals before you select a row.

Available pivot axes include:

- endpoints, with published first/last-seen timestamps when the relationship publication carries them and a clearly-labelled local-observation fallback otherwise;
- capabilities when compact current plugin summaries expose exact capability IDs, otherwise an explicitly bounded newest-finding behavior view;
- source lineage/families using exact catalog plugin identity and normalized shared source repositories;
- authors/publisher text retained in compact plugin identities;
- shared dependency/components and frozen advisories; and
- current-snapshot co-occurrence, computed from inverted variant postings rather than a global entity-by-entity N×N matrix.

A selected endpoint/component/capability pivot includes **Co-occurs with** relationships so infrastructure/library clusters are one click away. Co-occurrence is bounded per high-cardinality variant and reports that bound in the UI.

DeltaScope does **not** currently claim cross-repository fork/rename identity or code reuse merely from names. Those pivots require a published commit-ancestry or code/string/resource fingerprint index. The Code reuse option therefore remains visible but disabled, with the missing prerequisite explained. Likewise, local endpoint observation history is not presented as authoritative corpus first-seen history.

**Threat Intelligence** under Research remains the external/frozen IOC and reputation side; Intelligence under Explore is the current Omega corpus side. Threat Intelligence leads with the **intersection** between frozen feeds and current corpus endpoints, separates exact IOC identity hits from shared DNS/CDN infrastructure adjacency, promotes unlisted/unrecognised infrastructure as research leads, and cross-links indicators to the Findings inbox. The raw frozen feed inventory is reference data and is collapsed by default. Use global search for exact hashes, rule IDs, CVEs or endpoint text.

### Audit detection coverage

Use **Detection Coverage** to inspect SigmaScope's own observation-producer coverage across current plugin versions. The matrix shows stale/incomplete producer revisions, source-conditional scope, active Stigma-1 rules that depend on each collection, and whether a gap needs targeted re-analysis or a different repair. Read **Detection coverage and blind spots** for the exact semantics.

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

## Audit finding causality

Use **Trace lineage** to inspect the retained evidence path behind a current conclusion, including exact Stigma-1 selector/fact replay when collection completeness permits it. See [Finding lineage](../platform/FINDING-LINEAGE.md).

## Pivot from corpus intelligence into plugin behaviors

The plugin dossier has a **Behaviors** view that answers a different question from Network, Code & native, or Supply chain. Those origin-oriented views answer where evidence came from; Behaviors answers **what specific behavior was observed and which retained rows support it**.

Each behavior groups its matched retained evidence into a common presentation: evidence kind, the researcher-relevant observed value (for example a path, URL, target symbol, declaration, or manifest value), source location/callsite, linked rule/confidence, and source-line availability. If a published capability has no specific matched row in the current snapshot, DeltaScope keeps the capability visible and labels it as collection/summary-derived instead of inventing a callsite.

Selecting an Intelligence pivot performs an explicit bounded acquisition of matched evidence for the affected variants. The pivot panel shows those rows inline, so reading the value does not require opening every plugin. **View behavior in plugin** carries the pivot context into the dossier, opens Behaviors, and filters it to the originating endpoint/component/advisory/capability where that mapping is available. The context banner provides Show only this behavior, Show all behaviors, Back to pivot, and Clear actions.

Evidence rows can pivot back to the corpus through **Other plugins with this evidence**. That action is also an explicit bounded acquisition over retained current finding evidence. DeltaScope prefers exact retained evidence identity and labels contained-string matches; it does not treat similar-looking paths, URLs, symbols, or strings as equal evidence.

Family and author pivots are relationship axes rather than behaviors. Their context is preserved in the dossier, but DeltaScope does not pretend an author or source family is itself a runtime/static capability. Ordinary dossier navigation does not fan out across other variants.

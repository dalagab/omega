# Investigator guide

The Investigator perspective is for answering a concrete question about one plugin or one security signal.

## Start from a case or plugin

Use **Cases** for your local Investigator notebook: create an investigation, add notes, and pin the findings, observations, pivots or Evidence-v2 snapshots you want to revisit. Case reference health tells you whether each pin is still current, retained, re-observed, changed or no longer resolvable, and the Timeline keeps the local investigation chronology together. These cases are local-only and never become findings, policy input, queue requests or published evidence. Use **Published findings**, **Plugins**, or global search to start from authoritative/derived security state.

Once a plugin is selected, DeltaScope keeps it as the current subject while you move between evidence views. See [Local Investigator cases](LOCAL-CASES.md) for the storage and authority contract.

## Recommended investigation order

1. **Overview** — read the current severity, coverage and strongest signals.
2. **Journey** — see which collection/analysis stages actually ran for this plugin.
3. **Findings** — inspect each deterministic conclusion and its evidence.
4. **Network** — review endpoints and destination classifications.
5. **Relationships** — pivot through shared components, endpoints and advisories.
6. **Events** — place findings/observations in the retained timeline.
7. **Published Evidence** — inspect exact raw identities when you need reproducibility.

## Journey explanations

Clicking a Journey stage explains **that exact stage for the selected plugin**: what the stage does, why it has its current state, what evidence it consumed, what it produced and where to open the relevant detail.

Use raw technical evidence only after the stage explanation tells you which dataset matters.

## Interpreting static findings

A static finding describes code/evidence present in the artifact or source. It is not automatically runtime proof. For example, a correlation between network and process-launch capabilities means those capabilities were observed according to the rule inputs; it does not by itself prove that the plugin downloaded and executed a payload during a real session.

## Version history

The plugin dossier groups retained versions. The active version is marked **CURRENT** and drives current severity/counts. Older versions are **ARCHIVE**. Archive findings remain valuable for timeline/comparison work but are excluded from current totals.

## Source provenance

Always distinguish:

- source repository found;
- source revision selected;
- source appears consistent with the plugin identity;
- source-to-binary correspondence verified.

The UI should show which claim is actually supported.

## When evidence is incomplete

Treat missing/incomplete evidence as a coverage question, not a negative result. DeltaScope can show missing source, unavailable secondary engines, bounded observation transport or a rule requiring re-analysis.

## Trace why a finding exists

Use **Trace lineage** on a current finding to follow its producer, retained observation collection, selector/fact chain, rule evaluation and publication state. See [Finding lineage](../platform/FINDING-LINEAGE.md).

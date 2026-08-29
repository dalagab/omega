# Plugin Developer guide

The Plugin Developer perspective is designed around one question:
By default **My Plugins** shows logical plugins that have a stable variant matching the selected current Dalamud API target (**15** by default). Entries whose API metadata is unknown remain visible rather than being guessed unsupported. Open the plugin-picker preferences and enable **Show old / unsupported** to include testing-only, outdated, future-API, hidden and retired identities. The API target and legacy toggle are browser-local DeltaScope display settings only; they do not change Omega installation compatibility, Catalog identity, SigmaScope scan eligibility or published security evidence.


> What did Omega observe about my plugin, what needs explanation, and what can I provide to make the record more accurate and useful?

Select your plugin once from **My Plugins** in the global header. This picker is the logical Omega catalog: one row per canonical catalog `plugin_id`, even when the security system retains several source/build/version variants underneath it. Assembly name/version is context only and does not merge different plugin IDs. Developer pages stay scoped to that logical plugin; the corpus-wide variant browser belongs to the Investigator and Security Researcher perspectives.

Catalog plugins are shown even before a current security scan exists. **UNSCANNED / NO CURRENT EVIDENCE** means Omega knows the catalog identity but does not yet have matching current Evidence-v2 coverage; it is not a safe/clean verdict.

After selecting a plugin, **Current catalog variants** shows what the single My Plugins row represents underneath: every active source/build variant, its version/API and repository context, and whether that exact variant has current Evidence-v2. Use **Inspect variant** to drill into a sibling. Partial coverage stays partial: evidence for one sibling never makes another sibling look scanned.

### Cross-source comparison

Above that matrix, DeltaScope summarizes how the siblings differ without inventing a security verdict. It can call out:

- partial current Evidence-v2 coverage;
- different assembly versions across current sources;
- mixed/unknown Dalamud API metadata;
- same-version + same-API siblings whose published artifact SHA-256 differs;
- same-version + same-API siblings whose compact severity/finding counts differ.

A same-version difference is a **review cue**, not proof that either source is malicious or incorrect. Different artifact hashes across *different plugin versions* are treated as ordinary version/release skew. Use the exact variant buttons to inspect the source/build involved before drawing conclusions.

## Overview

The Overview summarizes:

- the current active plugin version;
- highest current static result;
- current findings;
- source coverage and source-to-artifact verification state;
- developer-profile coverage;
- observed capabilities that lack an explanation;
- current indexing context.

Older versions remain available as archive history but do not inflate current HIGH/CRITICAL totals.

## Resolution workflow

The developer landing page is resolution-first. It treats each observed capability as something the developer should deliberately understand and respond to rather than merely navigate past.

The flow is:

1. **Understand** — inspect the canonical capability, related finding/rule context and retained evidence.
2. **Decide** — choose whether the behavior is legitimate and should be explained, should be changed in code, or should be disputed with reproducible evidence.
3. **Act** — write the explanation or make the code change.
4. **Verify** — publish `.omega/plugin.yaml` or a new artifact and wait for the normal acquisition/scan path to observe the change.

The per-capability editor on the landing page and the full **Omega Profile** builder share the same browser-local draft. Writing an explanation in either place updates the other. The draft has no security authority: it never changes findings, severity, queue state, Definitions or published Evidence-v2.

### Marketplace preview

**As users see you** previews the public-facing plugin presentation using the current independent security result plus developer-authored context. It shows the plugin/version, scan/index time, finding count and capability explanations. The preview updates while explanations are drafted so the developer can see the trust/context value of explaining expected behavior.

Developer explanations add context for users. They do **not** remove the independent severity badge or finding count.

### Suggest phrasing

DeltaScope can generate a deterministic starter explanation from the observed capability and known destinations. It does not claim the wording came from peer plugins unless a future acquired explanation index can actually support that statement.

## Security Review

Security Review explains each current finding in developer-oriented language:

- what Omega observed;
- what rule/detector produced the finding;
- why the condition matters;
- what static analysis does **not** prove;
- where the exact evidence came from.

If a finding is expected behavior, the correct response is usually to explain the behavior in the Omega profile or improve source/build provenance. Developer context does not suppress the independent finding.

## Journey

Journey shows the actual stages retained for your plugin: discovery, artifact acquisition, source attribution, static analysis, secondary engines, rule evaluation, optional deeper analysis and Evidence-v2 publication.

Select **Explain this step** to see the exact stage-specific explanation for your plugin. Use the evidence buttons in that explanation to reach the relevant finding, source, endpoint or rule data.

## Changes

Changes compares the current version with a retained older version using security semantics rather than only raw source diffs. Look for:

- new/removed findings;
- new/removed capabilities;
- endpoint changes;
- dependency/advisory changes;
- source coverage changes;
- artifact identity changes.

## Omega Profile

`.omega/plugin.yaml` is optional developer-authored context. DeltaScope can build and validate it using the same parser SigmaScope uses.

A profile can explain:

- what the plugin does;
- expected capabilities;
- why those capabilities are needed;
- expected network destinations;
- project/homepage/documentation/support links;
- categories and descriptive tags;
- security policy/vulnerability reporting links.

A profile cannot:

- mark a plugin safe;
- suppress a finding;
- lower severity;
- override YARA/ClamAV/OSV evidence;
- prove that public source produced the shipped artifact.

### Example

```yaml
schema: omega.plugin-profile.v1
profile:
  tagline: Synchronizes user-configured appearance metadata.
  categories: [social, utility]
  tags: [sync, profiles]
  source: https://github.com/example/plugin
  securityPolicy: https://github.com/example/plugin/security/policy
capabilities:
  - id: network.http
    expected: true
    required: true
    reason: Retrieves and synchronizes user-configured profile metadata.
    destinations:
      - api.example.org
```

## Source & Build

Omega treats source attribution and artifact verification as separate questions.

### Improve source attribution

- publish the canonical source repository clearly;
- keep repository/project links in the manifest/profile current;
- use stable release tags or commits;
- avoid ambiguous mirrors unless their relationship is documented.

### Improve source-to-artifact traceability

- build releases in public CI where practical;
- associate the artifact with a commit/tag;
- publish deterministic build instructions;
- keep version metadata consistent between manifest, assembly and release;
- retain checksums/provenance for published release artifacts.

## Descriptive metadata and tags

Manifest tags/category tags and profile tags help discovery. Use them to describe what the plugin is, not to argue away security observations. Security capabilities use a separate canonical vocabulary.

## If you think Omega is wrong

1. Open the finding and inspect the exact evidence.
2. Check whether the evidence is from the current version or an archive version.
3. Check whether the finding is static capability evidence versus a runtime claim.
4. Improve source/build provenance if Omega cannot associate the right source.
5. Add or correct `.omega/plugin.yaml` if the behavior is expected but unexplained.
6. If the detector itself is incorrect, open a support/GitHub issue with the plugin version, artifact identity, finding/rule ID and why the evidence is a false positive.

## Behaviors and matched evidence

**Behaviors** is the plugin-centric view of what Omega actually observed. It complements the origin-oriented Network, Code & native, and Supply chain views by grouping the retained rows underneath the capability/finding they support.

For example, a hard-coded external-path behavior should place the retained path string first, followed by the IL callsite or metadata location and the linked rule. Endpoint behaviors place the URL/host first; native/import behaviors place the library or target symbol first. Source lines are shown only when a source mapping is actually retained; artifact-only evidence is labelled accordingly.

The capability summary on Overview remains a compact summary. **View evidence** opens Behaviors. A capability that is known from collection metadata or a compact capability summary but has no published row-level callsite stays visible with an explicit no-specific-row state.

When a researcher arrives from a corpus Intelligence pivot, DeltaScope preserves that context in a banner and can filter Behaviors to the originating signal. This navigation context is local/read-only and never changes the independent finding, severity, scanner evidence, or developer profile.

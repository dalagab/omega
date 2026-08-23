# Plugin Developer guide

The Plugin Developer perspective is designed around one question:

> What did Omega observe about my plugin, what needs explanation, and what can I provide to make the record more accurate and useful?

Select your plugin once from the plugin picker in the global header. Developer pages stay scoped to that plugin; the corpus-wide plugin browser belongs to the Investigator and Security Researcher perspectives.

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

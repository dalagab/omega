# Omega / SigmaScope security architecture

Status: architecture contract. On the **unreleased 2.15 development line**, the shared capability registry, `.omega/plugin.yaml` ingestion, deterministic observed-vs-declared behavior-consistency projection, observation/projection replay boundary, SRL v1 compiler/evaluator, Definition Pack v1 Daily freezing, and the first end-to-end Phase-7 static-observation migration/replay path are implemented. Production remains on 2.14 while data collection continues. Five reviewed primitive fact producers and two compound correlations have fail-closed parity and retained-Evidence replay tooling; a real compatible 2.15 corpus replay remains before production cutover/expansion. Phase 8 DeltaScope Rule Lab is implemented locally and remains read-only with respect to production state; Phase 9 provides the separate authorization-gated GitHub candidate issue/normal-PR promotion path without enabling production projection.

## Purpose

Omega should help a user answer two different classes of questions without conflating them:

1. **Software security hygiene:** does the plugin contain known malicious material, known vulnerable dependencies, suspicious signatures, or integrity/provenance problems?
2. **Behavior transparency:** what can the plugin statically be observed to access or control, does that fit its stated purpose, what did the developer say those capabilities are for, and is the user comfortable with them?

SigmaScope does not replace endpoint protection, YARA, ClamAV, OSV, package advisory systems, signing/integrity checks, or similar security tools. Those are complementary inputs to a healthy software-security process. SigmaScope's distinctive role is deterministic static capability and behavior transparency over Dalamud plugins.

## Four independent dimensions

Omega must present security information in four independent dimensions rather than collapsing everything into a single opaque risk score.

### Security hygiene

Examples:

- ClamAV results.
- YARA matches with reviewed rule provenance.
- OSV/dependency advisories.
- artifact hashes and integrity failures.
- future Authenticode verification state.
- suspicious binary/package structural evidence.
- known-malicious indicators.

These remain separate evidence families. A YARA or antivirus result must not silently rewrite SigmaScope capability evidence, and a capability finding must not pretend to be antivirus evidence.

### Capabilities

Capabilities describe permission-like access observed statically. They are not OS sandbox permissions: a Dalamud plugin executes inside the game process and inherits access from the process/user context.

Examples:

- `network.http`
- `network.socket`
- `filesystem.read`
- `filesystem.write`
- `filesystem.external-write`
- `process.execute`
- `registry.access`
- `native.interop`
- `dynamic.code`
- `memory.process`
- `memory.remote-thread`
- `clipboard.read`
- `credential.access`
- `game.memory.read`
- `game.ui.read`
- `game.ui.callback`
- `game.automation`
- `ipc.consume`
- `ipc.provide`

Internally these should be called capabilities. Omega may explain them to end users in permission-like language such as "This plugin can access the network".

A capability is evidence of ability/access, not proof of malicious intent and not necessarily proof that a runtime branch executes during ordinary use.

### Behavior consistency

Behavior consistency compares independently observed capability/evidence with the plugin's purpose and developer-provided declarations.

Useful states include:

- declared and observed;
- observed but undeclared;
- declared but not currently observed;
- explicitly declared as not expected but observed;
- observed destination explained by the developer;
- observed destination not explained by the developer;
- newly introduced capability compared with the previous artifact;
- newly introduced endpoint, process/native access, or automation behavior;
- source behavior that differs materially from artifact behavior;
- dependencies/components that do not fit the declared functionality.

Behavior consistency is a review aid, not an accusation. A mismatch should be shown precisely and let the user decide whether the explanation is credible.

The current implementation is `omega.sigmascope.behavior-consistency.v1`; see `docs/BEHAVIOR-CONSISTENCY.md`. It is deliberately a derived presentation/research projection. Future production rules must compare immutable observations and `developerProfile` directly rather than consuming the behavior-consistency output recursively.

### Evidence and provenance

Every conclusion must retain the evidence boundary that produced it:

- artifact scanned or not;
- exact artifact SHA-256 and package identity;
- source found or not;
- source repository and selected ref/commit;
- source attribution confidence;
- source-to-artifact correspondence state;
- reproducible verification state;
- analysis coverage/truncation state;
- Definitions/rule-set revision;
- rule identity and provenance;
- observation-contract revision and per-variant observation digest;
- secondary-engine identity and frozen definitions.

Finding source does not prove that every mirror artifact was built from that source.

## Developer claims are not scanner authority

The optional source-controlled `.omega/` directory is the developer's space for presentation, declared capabilities, expected behavior, service descriptions, native-component explanations, IPC explanations, support links, and other profile enrichment.

The trust boundary is strict:

- `.omega` content is **developer-provided metadata**.
- SigmaScope observations are **independent static evidence**.
- Omega presents the two side by side.
- The user decides what they are comfortable with.

A developer declaration must never suppress an observation, lower a scanner finding, mark a plugin safe, set trust, forge source verification, or override antivirus/YARA/OSV evidence.

## Capability comparison model

The intended presentation model is:

| State | Meaning |
| --- | --- |
| Declared + observed | Developer says the capability is expected and SigmaScope independently sees evidence for it. |
| Observed + undeclared | SigmaScope sees capability evidence but the developer has not explained it. |
| Declared + not observed | Developer discloses a capability that the current static analysis did not observe; this can be conservative disclosure or an optional/runtime-only path. |
| Explicitly not expected + observed | Developer says the capability should not be present but SigmaScope observes it; this is a strong consistency-review signal. |

Developer-provided reasons should be visually labelled as such. The UI should never make the explanation look like a SigmaScope conclusion.

## Separation of observations, facts, correlations, findings, and policy

The long-term deterministic flow is:

```text
artifact/source
    -> bounded parsers and classifiers
    -> immutable normalized observations
    -> SigmaScope rule selectors
    -> typed capability/fact records
    -> bounded correlation rules
    -> findings / behavior-consistency signals
    -> presentation or user policy
```

Rules must not recursively consume arbitrary findings. Correlation should operate on normalized observations or typed facts. This prevents conclusion-on-conclusion feedback loops and makes every result reproducible.

A later user/org policy layer may decide what deserves attention (for example, "warn me about process launch"), but policy must never mutate the underlying evidence.

## Observation/projection identity and rule-only replay

Phase 4 implements the semantic split without destructively rewriting historical Evidence-v2. See `docs/OBSERVATION-PROJECTION-CONTRACT.md`.

- **Artifact/source analysis revisions** still identify the parser/analysis semantics that produced retained evidence.
- **`observationContractRevision`** identifies the stable logical collection contract; each variant carries an `observationDigest` over the collection descriptors it actually retains.
- **Current scanner `ruleSetRevision`** continues to identify the hard-coded analysis semantics used by queue/evidence during migration.
- **`srlDefinitionPacks.ruleSetRevision`** identifies the exact frozen active SRL Definition Pack content. The two identities remain separate until parity migration is complete.
- **`projectionContractRevision` / `projectionRevision`** identify deterministic evaluator semantics plus rule-set/capability-registry identity; output record digests are audited separately.

A future rule declares the logical observation collections it requires. Replay audit succeeds without rescanning only when those collections are retained with sufficient completeness. Historical bounded compact transport remains usable for research/presentation but cannot masquerade as a complete collection for exact rule evaluation.

The existing Definitions field `sourceObservationRevision` is unrelated: it identifies source-repository ref observations and is deliberately not reused for the security observation contract.

A rule-only change is not itself a rescan reason. A new parser/observation primitive, or a concrete required collection that is missing/bounded in retained evidence, may require targeted artifact/source re-analysis.

## Secondary engines remain independent

YARA remains the byte/string/file-signature engine. ClamAV remains antivirus evidence. OSV remains dependency-vulnerability evidence. Future signing/integrity engines remain their own evidence families.

SigmaScope Rule Language should not attempt to emulate or replace these engines. It may correlate their **typed result records** with other facts only when the rule explicitly says so, and such correlations remain supplemental deterministic evidence.

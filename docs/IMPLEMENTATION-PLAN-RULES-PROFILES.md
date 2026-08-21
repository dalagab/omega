# Implementation plan: `.omega`, capabilities, Definition Packs, SRL, and DeltaScope Rule Lab

Status: active implementation plan on the **unreleased 2.15 development line**. **Phases 1–11 are implemented locally through the first end-to-end Phase 7 migration path, the developer-only DeltaScope Rule Lab, the authorization-gated GitHub candidate review path, retained-observation rule-only reprojection, and the complete read-only DeltaScope workbench.** Five reviewed primitive fact producers and two compound correlations have exhaustive parity plus retained-Evidence replay tooling. Production remains on 2.14 while scans continue; no live catalog/evidence state is changed by this development tree. The post-Phase-11 read-only cutover-readiness gate is now implemented as the operational prerequisite: a real full published corpus must reach `ready-for-human-review`, after which activation still requires explicit human approval and a separate reviewed change. Phase 12 remains the Omega client capability/profile UI.

## Phase 0 - architecture and vocabulary

Deliverables:

- freeze the four-dimension security model: hygiene, capabilities, behavior consistency, provenance;
- define the capability-registry naming convention;
- define developer-claim vs scanner-evidence UI language;
- document `.omega` and SRL/Definition Pack trust boundaries;
- add architecture regression assertions where practical (for example, developer profile cannot set scanner authority fields).

No scanner behavior change. No Catalog rebuild required for documentation-only work.

## Phase 1 - shared capability registry — IMPLEMENTED

Implemented in `security-definitions/capabilities/registry.json` (`omega.sigmascope.capability-registry.v1`) with validator/normalizer in `tools/catalog/capability_registry.py`. DeltaScope exposes the registry via `deltascope.py capabilities`.

Needed work:

- stable capability IDs and categories;
- aliases/deprecations;
- labels/descriptions for end-user presentation;
- optional attributes such as destination-aware, filesystem-scope-aware, automation level;
- validator and tests;
- adapter from current legacy capability labels/permission IDs.

Do this before `.omega` so developer declarations and observations cannot drift into two vocabularies.

## Phase 2 - `.omega/plugin.yaml` ingestion — IMPLEMENTED

Implemented as `omega.plugin-profile.v1` plus `omega.plugin-profile-observation.v1` in `tools/catalog/plugin_profile.py`, integrated into attributed source analysis, compact Evidence-v2, marketplace projection and DeltaScope. Public documentation lives in `docs/plugin-developers/`.

Needed work:

- safe YAML dependency/parser policy;
- strict byte/depth/count/string/URL limits;
- schema validator;
- source-repository `.omega/plugin.yaml` discovery;
- provenance/hash/ref storage;
- normalized profile data model;
- validation diagnostics that do not block plugin ingestion;
- marketplace projection fields;
- tests for malicious YAML constructs, oversized profiles, unsupported fields, invalid URLs, unknown capabilities, and authority-field rejection;
- public `docs/plugin-developers/` guide and starter example.

Initial implementation can expose the data in DeltaScope before the Omega C# client consumes it.

## Phase 3 - observed-vs-declared comparison — IMPLEMENTED LOCALLY

Implemented as `omega.sigmascope.behavior-consistency.v1` in `tools/catalog/behavior_consistency.py`, transported through compact Evidence-v2/marketplace projection and rendered in DeltaScope. Full semantics are documented in `docs/BEHAVIOR-CONSISTENCY.md`.

Implemented work:

- normalize current scanner capability IDs onto the shared registry;
- compute declared+observed, observed+undeclared, declared+not-observed, and not-expected+observed states;
- compare declared service destinations with observed endpoint hosts;
- preserve developer reason as separately labelled developer text;
- expose comparison in Evidence/marketplace projection without letting declarations change native severity;
- DeltaScope presentation and regression tests.

This gives end users substantial transparency before the new rule language exists. It also establishes an important Phase 4 boundary: `behaviorConsistency` is a derived projection and must not become an input to future production SRL rules.

## Phase 4 - observation/projection contract split — IMPLEMENTED LOCALLY

Implemented in `tools/security/observation_projection.py` and integrated with Evidence-v2 migration/synchronization/validation plus DeltaScope's authoring reference. The detailed contract is `docs/OBSERVATION-PROJECTION-CONTRACT.md`.

Implemented work:

- freeze `omega.sigmascope.observation-contract.v1`, `omega.sigmascope.observation-collection.v1`, `omega.sigmascope.projection-contract.v1`, and `omega.sigmascope.projection-replay-audit.v1`;
- register 17 stable logical observation/provenance/developer-claim/hygiene collections and explicitly mark legacy findings/permission/automation datasets as non-SRL projections;
- retain useful scan-report-only observations as first-class immutable datasets for new 2.15 analyses, including native imports, full endpoint rows, source files, binary classifications, developer profile/provenance, artifact/manifest identity and secondary-security evidence;
- annotate existing physical datasets with logical collection/schema/semantic/SRL-eligibility metadata without deleting backward-compatible transport;
- add per-analysis/per-variant observation digests and deterministic projection evaluator identity;
- add replay auditing so a future rule can state required logical collections and receive an exact answer: reusable from retained evidence, missing, historically bounded, or forbidden derived input;
- adapt historical 2.14-style Evidence-v2 at candidate synchronization time without downloading plugin bytes or rewriting retained analysis records;
- mark historical compact endpoint transport as `bounded-transport`, preventing an exact full-endpoint rule from silently treating a truncated historical summary as complete evidence;
- expose `python tools/security/deltascope.py observation-schema` as the machine-readable future SRL input boundary;
- preserve optional contract validation so existing published 2.14 Evidence-v2 remains intrinsically valid until migration is intentionally performed.

The transport remains physically backward compatible during migration: legacy `findings`, `permissions`, and `automation` datasets may still live beside observations, but are now semantically classified as projection data and are forbidden future raw SRL inputs. Physical cleanup can happen after rule migration/parity is proven.

Do **not** reuse the existing Definitions name `sourceObservationRevision` for this feature. That field already identifies source-repository ref observations. Phase 4 uses `observationContractRevision` / `projectionContractRevision` and per-variant `observationDigest` / `projectionRevision`.

No live 2.14 migration is executed in this phase. Retained 2.14 Evidence is migration input; only a future rule's specific missing/bounded required collection may justify targeted re-analysis.

## Phase 5 - SRL compiler/evaluator v1 — IMPLEMENTED LOCALLY

Implemented in `tools/security/srl.py` with DeltaScope CLI integration. Phase 6 freezes reviewed Definition Packs; the first Phase-7 primitive+compound chain now proves equivalent hard-coded/SRL behavior and has retained-Evidence replay tooling, while production projection remains disabled pending compatible 2.15 corpus replay and cutover review.

Implemented work:

- `omega.sigmascope.rule.v1`, `omega.sigmascope.ruleset.v1`, compiled-rule/ruleset and fixture contracts;
- hardened bounded YAML parsing with duplicate-key, anchor/alias and explicit-tag rejection;
- typed collection/field checking against the registered Phase-4 authoring boundary;
- exact/CI equality and membership, bounded contains/prefix/suffix, existence/missing, numeric comparisons, boolean conditions and count thresholds;
- mandatory same-record matching for collection selectors and same-element matching for repeated `.omega` arrays;
- named selectors and deterministic `all`/`any`/`not`/`count` condition AST;
- observation/classification rules emit typed facts; correlation rules may consume facts/observations but emit findings only;
- structural recursion prevention: observation rules cannot consume facts and correlations cannot emit facts/findings as inputs;
- deterministic evaluator/resource limits, stable ordering, canonical semantic hashes (`ruleRevision` / `ruleSetRevision`);
- positive/negative `omega.sigmascope.rule-fixture.v1` execution;
- Phase-4 replay audit gating for real retained Evidence so bounded/missing inputs request targeted re-analysis rather than produce false negatives;
- DeltaScope commands `rule-compile`, `rule-test`, and `rule-eval`;
- compileable examples under `docs/rule-authors/examples/`;
- focused compiler/evaluator/safety/same-record/replay regression coverage.

`python tools/security/deltascope.py rule-schema` now advertises the exact implemented SRL engine contract while keeping `productionRuleEvaluationEnabled: false`.

## Phase 6 - Definition Pack v1 and Daily Catalog compiler — IMPLEMENTED LOCALLY

Implemented in `tools/security/definition_packs.py` and integrated into `tools/catalog/definitions_snapshot.py`. Phase 7 now adds fail-closed primitive+compound migration parity to the freeze; production rule projection remains disabled pending compatible 2.15 retained-corpus replay and cutover review.

Implemented work:

- `security-definitions/packs/<pack-id>/pack.yaml` contract (`omega.sigmascope.definition-pack.v1`);
- trust tiers `core`, `reviewed`, `experimental`, and developer-only `local`;
- bounded pack-relative regular-file loading with traversal/symlink rejection;
- pack/rule provenance, license and reviewer metadata, with mandatory review metadata for production tiers;
- minimum SRL engine / observation-contract compatibility checks;
- exact declared rule-ID matching, duplicate rule-ID prevention and duplicate emitted-fact prevention across packs;
- exact source/fixture SHA-256, rule revisions, pack revisions, Definition Pack revision, and active SRL `ruleSetRevision`;
- fixture execution through the exact Phase-5 SRL evaluator, fail-closed for any mismatch;
- production-tier rule gating: only SRL `reviewed` rules in `core`/`reviewed` packs are eligible for the active compiled ruleset;
- `experimental` packs are frozen for provenance/research but inactive; Daily freezing excludes `local`;
- Daily Definitions freeze under `srl/index.json`, `srl/compiled-ruleset.json`, and exact copied pack source/fixtures;
- a verified frozen-ruleset loader that never reads the development `security-definitions/packs` tree at worker runtime;
- DeltaScope `definition-packs --definitions-root ...` inspection of exact frozen provenance;
- parent Definitions semantic revision now includes the Definition Pack identity.

Migration compatibility is explicit: the existing top-level Definitions `ruleSetRevision` continues to identify the current hard-coded scanner semantics used by queue/evidence provenance. Phase 6 adds the SRL ruleset identity under `srlDefinitionPacks.ruleSetRevision`; it does not repurpose the existing field and therefore cannot cause pack-only artifact rescans. That field migration belongs to the parity/reprojection phases.

YARA and ClamAV remain separate engines. Existing YARA metadata may later be represented by the same provenance UI without changing YARA's language or engine.

## Phase 7 - migrate low-risk rules first — FIRST END-TO-END PATH IMPLEMENTED LOCALLY

Implemented first path:

- `omega-core-static-primitives` core pack with reviewed observation rules for `network.http`, `network.socket`, `process.launch`, `shell.powershell`, and `credential.api`;
- rule-neutral retained `staticPatternMatches` rows generated from the scanner's legacy literal matcher, with no rule ID/severity/capability/finding conclusion;
- `staticPatternMatchContractVersion=1` completeness marker, including explicit empty retained datasets for zero-hit new scans;
- `omega-core-compound` core pack with reviewed `compound.network-execute` and `compound.credential-network`, preserving exact legacy finding identity/payload semantics;
- migration parity over 59 primitive literal cases and all 32 primitive-fact combinations, using only scanner-produced observations;
- DeltaScope `rule-parity` and Daily Definitions fail-closed parity freeze;
- retained Evidence-v2 replay through `srl_evidence_replay.py` / DeltaScope `rule-replay`; legacy findings are comparison baseline only and never recursive SRL input;
- historical 2.14 variants missing the new complete observation are classified `rescanRequired` for targeted re-analysis rather than fabricated as negative;
- production SRL evaluation remains disabled and current hard-coded logic remains the baseline.

The implementation is therefore cutover-ready **in mechanism**, but not yet operationally cut over. The next production prerequisite is to collect compatible 2.15 evidence for the intended corpus and require clean replay (`mismatchedVariants=0`, `rescanRequiredVariants=0`) before any projection switch/removal of hard-coded semantics.

Recommended subsequent migration order:

1. automation call mappings and IPC automation hints;
2. managed metadata/service/package permission mappings;
3. endpoint/component classifications;
4. additional low-level pattern families only after an explicit retained-observation primitive/completeness contract exists.

For every migrated rule:

- prove old and new outputs match on regression corpus unless a deliberate semantic change is documented;
- preserve rule IDs where semantics are equivalent;
- change parser/analysis identity when a new retained observation primitive or producer vocabulary changes;
- change only projection/ruleset identity for pure rule changes over already-compatible observations;
- never infer a negative from an absent collection;
- remove Python hard-coding only after parity passes **and** the replacement observation-to-fact path has a clean compatible retained-corpus replay and explicit cutover approval.

## Phase 8 - DeltaScope Rule Lab — IMPLEMENTED LOCALLY

`tools/security/rule_lab.py` plus the DeltaScope browser now use the production SRL compiler/evaluator in local/experimental mode. Implemented:

- YAML editor/import;
- structured parse/compile diagnostics;
- one-plugin dry run against retained Evidence-v2;
- selector match explorer with bounded exact evidence rows;
- candidate-owned baseline finding diff;
- bounded selected-set and corpus replay;
- exact retained-observation fixture creation/editing/testing;
- deterministic evaluator-state explanation view;
- deterministic hash-pinned candidate ZIP export;
- explicit no-production-write-back boundary.

Missing/bounded required observations are surfaced as replay/rescan requirements, not false negatives. The Rule Lab server exposes no promotion endpoint and candidate export carries no authorization. Promotion remains Phase 9.

## Phase 9 - GitHub candidate-rule workflow — IMPLEMENTED

GitHub issues/PRs are now the review path while untrusted candidate data stays away from privileged execution.

Implemented flow:

1. DeltaScope exports/helps author inert candidate YAML and fixtures.
2. `.github/ISSUE_TEMPLATE/sigmascope-rule-candidate.yml` collects pack identity, candidate SRL, positive/negative fixtures, rationale, false-positive expectations, provenance and license.
3. `.github/workflows/rule-candidates.yml` `validate` re-fetches the issue, parses it as bounded data with `tools/security/rule_candidate.py`, compiles the exact SRL, runs fixtures and cross-pack Definition Pack validation, and comments diagnostics. The job has no contents-write permission.
4. Promotion is a separate reusable-workflow mode. Before checkout or candidate re-fetch it resolves the triggering `github.actor` against GitHub repository collaborator permissions and accepts only repository write-equivalent authority. Self-declared author/reviewer/status fields and issue authorship do not count.
5. Authorized promotion re-fetches the issue, revalidates from scratch, stamps the materialized source copy `reviewed`, records the verified GitHub actor and issue-body SHA-256, refuses existing pack overwrite/path escapes/cross-pack identity collisions, and materializes only `security-definitions/packs/<new-pack>/...`.
6. The workflow creates a dedicated branch and normal PR against `sigmascope`; it never auto-merges. Normal regression CI and branch protection remain authoritative.
7. GitHub issue/comment events originate on the default branch, so the companion `main` overlay needs the thin caller shown in `docs/workflow-callers/rule-candidates-main.yml`. The reusable workflow still performs the decisive permission check.
8. A merged source pack does not directly activate production. The next deliberate Daily Catalog/Definitions freeze is a separate fail-closed boundary.

`pull_request_target` and contribution-controlled executable code are deliberately absent from this path. Candidate YAML remains inert data.

## Phase 10 - rule-only replay/reprojection

Implemented locally and validated after observation/projection separation stabilized:

- compare new rule requirements with available observation schema/revision;
- if compatible, re-evaluate retained immutable observations and publish a new projection without artifact download/reparse;
- if incompatible, enqueue only variants missing required observation primitives;
- report why a rescan is required (`missing observation collection X`), not simply `rules changed`.

This prevents Definition growth from causing needless full scans.

## Phase 11 - DeltaScope read-only security-information workbench

Build the investigator-facing SIEM-style information architecture described in `docs/DELTASCOPE-SECURITY-WORKBENCH.md` without changing DeltaScope's authority boundary:

- Dashboard;
- Incidents;
- Events;
- Intelligence;
- Assets (plugins first);
- Rules + local Rule Lab;
- Reports;
- System / raw Evidence-v2.

DeltaScope may correlate, explain, replay and create local candidate/fixture state. It must not activate/disable rules, edit authoritative findings/severity, mutate queue/evidence/catalog/Definitions state, or directly publish changes. Any proposed change leaves DeltaScope as inert candidate data and enters the Phase-9 GitHub permission/CI/review path.

All eight Phase-11 slices are implemented: stable read-only navigation, deterministic incident/event/intelligence projections, selected-case timelines, ecosystem intelligence/Asset relationships, the exact frozen active-rule/provenance browser, deterministic Reports/System health surfaces, and the final URL-only GitHub proposal handoff from Rule Lab. Candidate data is locally validated and pre-filled into GitHub's normal Issue Form; DeltaScope never submits it or gains repository mutation authority. The existing Phase-9 permission/CI/review/normal-PR boundary remains authoritative.

## Operational SRL cutover-readiness gate — IMPLEMENTED, ACTIVATION NOT AUTHORIZED

Before Phase 12/client presentation work can imply that SRL is authoritative, run the exact published corpus through `tools/security/srl_cutover_readiness.py`. The gate:

- intrinsically verifies the frozen Daily Definitions and Security Evidence v2 snapshots;
- loads only the exact frozen reviewed SRL ruleset;
- runs legacy-baseline replay and retained-observation rule-only reprojection across every current variant;
- requires zero hard-coded-vs-SRL mismatches, zero audit errors, zero missing/bounded observation re-analysis requests, and complete replay/reprojection classification agreement;
- refuses to declare a filtered/limited run cutover-ready;
- emits exact collection-level re-analysis reasons for repair planning;
- never mutates queue/evidence/catalog/Definitions state.

A fully green report means only `ready-for-human-review`. `manualApprovalRequired=true`, `activationAuthorized=false`, and `hardCodedBaselineRemovalAuthorized=false` are invariant output fields. `.github/workflows/srl-cutover-readiness.yml` is a read-only reusable/manual workflow; the default-branch caller reference is `docs/workflow-callers/srl-cutover-readiness-main.yml`. Actual activation/removal of the hard-coded baseline must be a separate reviewed pass after the real corpus is clean.

## Phase 12 - Omega client capability/profile UI

Present the model clearly in the marketplace/client:

- Security hygiene;
- Capabilities;
- Behavior consistency;
- Provenance.

For each capability show observed/developer-declared state and developer-provided reason. Clearly label developer text. Surface new capability changes between versions and unexplained destinations where supported.

The client must consume published normalized fields; it must not run security rules itself.

## Release and Catalog rules

- Documentation-only or DeltaScope-only UI changes: no Catalog rebuild unless frozen worker/Definitions content changes.
- `.omega` scraper, SRL engine, production rule loader, projection logic, or workflow behavior frozen into the worker: cut the appropriate Security Services release and run Daily Catalog Launcher.
- Rule/Definition content change with no engine change: no SigmaScope engine release should be necessary once Definition Packs are implemented, but Daily Catalog must compile/freeze a new Definitions/rule-set revision.
- New observation/parser primitive: SigmaScope engine release + Daily Catalog + targeted re-analysis for affected variants.

## Acceptance criteria for the architecture

The implementation is complete only when all of these are true:

- developers can add a bounded `.omega/plugin.yaml` with capability reasons;
- Omega/SigmaScope never treats developer claims as authority;
- observed/declaration mismatches are reproducible and explainable;
- reviewed SRL rules are declarative and non-executable;
- DeltaScope can dry-run the exact production evaluator against existing evidence;
- candidate rules can be exported with fixtures and submitted as YAML;
- only authorized repository actors can promote a candidate into a Definition Pack PR;
- Daily Catalog validates and freezes exact rule identities fail-closed;
- a rule-only change can reuse compatible immutable observations instead of automatically rescanning artifacts;
- YARA, ClamAV, OSV and future endpoint/integrity tools remain independent complementary evidence systems.

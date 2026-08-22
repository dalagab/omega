# Omega security services · SigmaScope + DeltaScope

This package is the source intended for the **`sigmascope` branch** of `dalagab/omega`. It contains repository discovery/catalog generation, frozen Definitions, SigmaScope, DeltaScope, Security Evidence v2 publication, source submissions, and their Python regression tests.

It deliberately contains **no Omega C# client source**.

## Services

### Security services 2.15.0 · SigmaScope scanner engine 2.15.0

The unreleased 2.15 development line now implements behavior-transparency architecture Phases 1–10 plus Phase-11 DeltaScope workbench slices 1–7. A source-controlled shared capability registry (`omega.sigmascope.capability-registry.v1`) now gives SigmaScope, DeltaScope, developer profiles and future SRL rules one stable vocabulary. Attributed public source may contain bounded `.omega/plugin.yaml` (`omega.plugin-profile.v1`) metadata so developers can enrich their Omega profile and explain expected/not-expected capabilities, external services, native components and IPC usage. These declarations are untrusted context only: they never suppress findings, lower severity, override YARA/ClamAV/OSV, or claim source-to-artifact verification.

The developer profile is hashed/validated fail-soft, retained in source analysis and compact Evidence-v2, projected for future marketplace UI, and shown separately in DeltaScope. Phase 3 derives `omega.sigmascope.behavior-consistency.v1`, comparing canonical observed capabilities and concrete endpoint destinations with developer declarations without changing native findings/severity. Phase 4 separates retained observation inputs from deterministic projection identity via `omega.sigmascope.observation-contract.v1` / `omega.sigmascope.projection-contract.v1`, including a replay audit that tells SRL/DeltaScope whether a rule can reuse retained evidence exactly or needs targeted re-analysis. Phase 7b adds the rule-neutral complete `staticPatternMatches` observation required by the first migrated primitive rules, so the current development identities intentionally advance to `artifact-analysis-v1-83c69af9c649cc52` and `source-analysis-v1-6dbf8f81962644ba`. This is targeted re-analysis semantics for variants missing that observation, not a version-only mass-rescan trigger. Frozen Definitions still bind secondary-security identity into their artifact-analysis contract as before; engine release identity remains excluded from narrow analysis semantics and legacy freshness scheduling.

2.14.1 improved production source-discovery operations: source-needed issues are plugin-scoped across mirrors, duplicate legacy issues consolidate automatically, and validated source replies can populate all affected feed-specific source mappings.

2.14.0 turns the reviewed-YARA infrastructure into a real production evidence layer. The initial **Omega Core** seed contains 14 first-party compound rules across credential/token theft + exfiltration, process injection, encoded download/execute, security tampering, embedded PE loading, persistence, and contextual anti-analysis clusters. Rules remain supplemental evidence: a YARA match does not silently modify SigmaScope's native severity or source-review coverage.

YARA now scans both the exact downloaded plugin package container and a **bounded generated view of ZIP members**. Code/config/payload-like members are read through strict byte/count/compression limits and written only under generated temporary filenames; original archive paths are never used for extraction. Evidence-v2 records the original member path, member SHA-256/byte count, scan scope, truncation/skip counts, rule provenance, review hash, reviewer, rule class, confidence, license and false-positive expectation.

The YARA review contract advances to v2. Enabled rules must pin the SHA-256 of the exact reviewed rule bytes, declare every rule name exactly, carry reviewer/class/confidence metadata, and pass a real YARA compile check at the Definitions boundary. Regression CI now triggers on `security-definitions/**` and installs YARA before running tests so rule-only changes cannot bypass validation. Third-party packs are not enabled wholesale; candidate upstreams are kept in a review queue for rule-by-rule provenance/license/false-positive assessment.

ClamAV remains operational through the 2.11 immutable database/executable identity path. The 2.13 native/endpoint/component contracts, 2.12 lifecycle/event-driven queue contracts, and 2.10 artifact/source-attribution model remain compatible. Plugin artifacts and source remain untrusted data and are never executed or dynamically loaded.

### DeltaScope
Developer/operator-only investigation and rule-development tooling over published or local SigmaScope evidence. **DeltaScope 4.0** keeps all published Evidence-v2, frozen Definitions, scanner state and production activation strictly read-only, while adding one intentional local-only write surface for versioned **My Rules**. Rules is now a unified **SRL Core** workspace: the left tree shows repository **System Rules** beside locally stored **My Rules**; either opens in the same YAML / Visual / Explain-Test area. System rules are read-only and can be explicitly forked. Local rules default to `~/.omega/deltascope/rules/v1` (override `OMEGA_DELTASCOPE_RULE_HOME`) and every save creates an immutable validated revision. The visual composer is an SRL-specific Node-RED-style authoring view for selectors, ALL/ANY/NOT/COUNT logic and emit nodes; it is not executable. Existing YAML is parsed into a graph and every graph change must compile back through SRL Core before it can be saved or evaluated. Exact published active-rule provenance remains a separate read-only snapshot view, so repository/local availability is never confused with production activation. The rest of the permanent workbench remains Dashboard, Incidents, Events, Intelligence, Assets, Rules, Reports and System, with deep retained-evidence inspection, secondary-security evidence, relationship pivots, reprojection readiness, Rule Lab replay/fixtures/export and the URL-only GitHub proposal handoff.

Online mode remains lazy: plugin lists use the compact published indexes and large forensic shards are fetched only when opened. Historical/pre-summary Evidence-v2 and the legacy read-only SQLite developer mode remain supported. Run it with:

```bash
python tools/security/deltascope.py serve-online
python tools/security/deltascope.py audit --evidence-v2 path/to/security-evidence-v2 --json
python tools/security/deltascope.py capabilities
python tools/security/deltascope.py observation-schema
python tools/security/deltascope.py rule-schema
python tools/security/deltascope.py definition-packs --definitions-root path/to/definitions
python tools/security/deltascope.py rule-parity
python tools/security/deltascope.py rule-replay --evidence-v2 path/to/security-evidence-v2
```

The authoring commands expose the shared capability vocabulary, the Phase-4 legal observation/replay boundary, the machine-readable SRL v1 contract, and exact frozen Definition Pack provenance when a Definitions snapshot is supplied. SRL candidate YAML can be compiled and fixture-tested locally with DeltaScope, and reviewed Definition Packs can now be validated/frozen by Daily Definitions. The first compound migration path now includes reviewed `staticPatternMatches` observation-to-fact rules, 59 primitive-pattern parity cases, all 32 compound combinations, and retained Evidence-v2 replay through `rule-replay`. Production SRL projection remains disabled. The post-Phase-11 cutover-readiness gate is now implemented in `tools/security/srl_cutover_readiness.py`: it audits the complete published current-variant corpus against the exact frozen Daily Definitions and can report `ready-for-human-review`, but it cannot authorize activation, remove the hard-coded baseline, mutate the queue, or write production evidence. The companion read-only Actions workflow is `.github/workflows/srl-cutover-readiness.yml`. Actual cutover still requires a clean real corpus report and explicit human review:

Production SRL projection remains disabled: live 2.14 evidence does not contain this new observation collection, so old variants are reported as requiring targeted 2.15 re-analysis rather than being reconstructed from current findings.

DeltaScope is not part of the production scanner decision path, never scans plugins, and has no publication/write-back step. Its permanent workbench navigation is **Dashboard, Incidents, Events, Intelligence, Assets, Rules, Reports, System**. The second Phase-11 slice moves the first incident/event/intelligence views out of browser-only derivation into deterministic `omega.deltascope.security-workbench.v1` backend projections with stable object IDs/revision, `readOnly=true`, `mutationAuthority=none`, and an explicit GitHub authoritative-change boundary. Assets retain the deep plugin investigation view; incidents/events/intelligence are derived read-only pivots into that evidence; Rules combines read-only active/source provenance with the unified SRL Core workspace; only versioned My Rules are writable locally. DeltaScope does not assign/close incidents, activate rules, edit authoritative findings, rewrite evidence, mutate queues, or save Definitions. Authoritative changes go through the Phase-9 GitHub permission/CI/review/PR path.

Phase 10 adds deterministic **rule-only reprojection** from retained immutable observations. Compatible variants can be re-evaluated against a new frozen SRL ruleset without artifact download/reparse and without consuming legacy findings as rule inputs. Missing required collections produce precise `srl_observation_missing` re-analysis requirements. Evidence-v2 may publish a hash-pinned `rule-projections/` sidecar for inspection, but it is intrinsically validated as non-authoritative (`productionRuleEvaluationEnabled=false`, `productionWriteBack=false`, `queueMutationAuthorized=false`) and cannot replace production findings.

## Architecture documents

The behavior-transparency architecture is documented separately. Phases 1–10 and all eight Phase-11 DeltaScope workbench slices are implemented locally on the unreleased migration line. The Phase-7 migration path is complete through the retained-observation replay gate: `compound.network-execute` / `compound.credential-network`, their five primitive fact producers, fail-closed parity, and Evidence-v2 replay are implemented. Production 2.14 remains untouched while scans continue. Actual cutover still waits for compatible 2.15 observations to be collected/re-analysed. Phase 8 introduced the local Rule Lab; DeltaScope 4.0 turns it into the unified versioned SRL Core workspace; Phase 9 adds the separate authorization-gated GitHub issue/PR path; Phase 10 provides retained-observation rule-only reprojection; Phase 11 completes the read-only SIEM-style investigator workbench and URL-only `Propose on GitHub` handoff. Candidate issue YAML remains inert data, validation has no contents-write permission, promotion re-checks the triggering GitHub actor's repository permission and revalidates from scratch, and the resulting Definition Pack enters a normal non-auto-merged PR. Production SRL projection remains disabled:


SRL v1 local authoring commands:

```text
python tools/security/deltascope.py rule-compile --rule candidate.yaml
python tools/security/deltascope.py rule-test --rule candidate.yaml --fixture positive.fixture.yaml
python tools/security/deltascope.py rule-eval --rule candidate.yaml --observations observations.json
python tools/security/deltascope.py rule-parity
```

These commands use the same deterministic compiler/evaluator intended for future production Definition Packs. They cannot publish or modify production evidence.
- `docs/ARCHITECTURE-SECURITY-MODEL.md` — security hygiene vs capabilities vs behavior consistency vs provenance, and the developer-claim trust boundary.
- `docs/OMEGA-PLUGIN-PROFILE.md` — optional `.omega/plugin.yaml` developer profile, capability reasons, service/native/IPC explanations, validation and sanitisation.
- `docs/BEHAVIOR-CONSISTENCY.md` — deterministic observed-vs-declared capability/service comparison, transport, replay and SRL recursion boundary.
- `docs/OBSERVATION-PROJECTION-CONTRACT.md` — Phase-4 logical observation collections, completeness/replay auditing, projection identity, and 2.14→2.15 targeted migration rules.
- `docs/SIGMASCOPE-RULE-LANGUAGE.md` — Sigma-inspired typed YAML rule DSL; explicitly complementary to YARA/ClamAV/OSV rather than a replacement.
- `docs/DEFINITION-PACKS.md` — implemented Definition Pack v1 trust/provenance/fixture/freezing contract.
- `docs/DELTASCOPE-RULE-WORKBENCH.md` — local rule dry-run, explainability, fixtures and candidate export from DeltaScope.
- `docs/GITHUB-RULE-CANDIDATE-WORKFLOW.md` — Phase-9 inert issue validation, GitHub authorization gate, reviewed-pack materialization, and normal PR lifecycle.
- `docs/IMPLEMENTATION-PLAN-RULES-PROFILES.md` — phased implementation, GitHub candidate-rule promotion workflow and rule-only replay plan.
- `docs/plugin-developers/README.md` — public `.omega/plugin.yaml` authoring/validation guide and exact v1 schema.
- `docs/rule-authors/README.md` — starting point for designing future SigmaScope rules against DeltaScope/SigmaScope data.
- `docs/rule-authors/DATA-REFERENCE.md` — exact current authoring collections/field semantics.
- `docs/rule-authors/RULE-DESIGN.md` — evidence/confidence/same-record/fixture guidance.
- `docs/rule-authors/DELTASCOPE-WORKFLOW.md` — current inspection/Rule Lab workflow and planned GitHub promotion lifecycle.

## Branch model

- `sigmascope` — this source.
- `catalog-data` — generated canonical catalog + frozen Definitions + immutable worker bundle.
- `security-evidence-v2` — generated validated detailed evidence.
- `main` — Omega client plus small default-branch launcher workflows.

GitHub schedules/events run from the default branch, so `main` keeps thin callers that invoke these reusable workflows using `@sigmascope`. Phase 9 also needs the thin issue/comment caller shown in `docs/workflow-callers/rule-candidates-main.yml`. The full implementation remains here.

## Workflows owned here

- `catalog-builder.yml` — daily/manual catalog + Definitions snapshot and client marketplace DB compiler.
- `sigmascope.yml` — bounded continuous SigmaScope worker.
- `source-submissions.yml` — validates and persists public source metadata onto `sigmascope`.
- `catalog-compaction.yml` — manual legacy compatibility self-test.
- `regression-tests.yml` — Python/service regression suite for the `sigmascope` branch.
- `deltascope.yml` — manual read-only developer audit.

The scheduled/event launchers with matching names live on `main`; do not move scanner implementation back there.

## Discord publication notifications

Public publication notices are built from already-sanitised catalog/SigmaScope outputs. The notice builder has no webhook credential; delivery happens in a separate `discord-public` environment job.

- `tools/notifications/discord_notice.py` — deterministic, sanitised notice builder.
- `tools/notifications/post_discord_notice.py` — isolated webhook sender with a Discord-compliant API User-Agent.
- `tools/tests/test_discord_notifications.py` — notification routing, sanitisation, and voice regression tests.

Message wording is selected deterministically from a small compositional phrase grammar rather than a giant pile of canned messages. Each notice family combines six openings, six observations and six closers (**216 combinations per family / 864 base TONI voices total**), then adds event-aware wording for catalog deltas, finding counts, evidence work type and Definitions state. The same publication identity always gets the same wording, so retries remain reproducible. No AI, randomness or generated network copy is used at runtime. Security notices sound mildly irritated, catalog growth sounds wealthy/data-hungry, Definitions updates sound pleased, and ordinary evidence reviews are deliberately a little smug.

The embed panels themselves are operational summaries, not personality filler. Catalog publications show current plugin/variant/source size, exact added/updated/removed counts and up to two deterministic representative plugin names. Definitions publications show active pack/rule vocabulary, capability categories, frozen OSV coverage and source-observation health. Evidence publications show current finding totals and added/cleared deltas. New high/critical security incidents also resolve reviewed SRL rule IDs through the exact frozen Definition Pack index and link straight to the corresponding GitHub YAML source pinned to that Definitions snapshot's `builtFromDevCommit`; legacy findings without a reviewed YAML source are labelled as legacy rather than linked inaccurately.

## DeltaScope antivirus/YARA visibility hotfix

DeltaScope now exposes a permanent top-level **Antivirus & YARA** panel and moves per-plugin ClamAV/YARA results directly below the selected plugin overview. Clean/no-match results are shown explicitly; scans without secondary-security evidence are labelled as unrecorded rather than implied clean. This is developer-view-only and does not alter SigmaScope analysis or publication semantics.

## DeltaScope TONI and metric drill-downs

DeltaScope includes **TONI** as a deterministic evidence guide in the browser. TONI explains the currently loaded Evidence-v2 counts, queue state, selected plugin, source-attribution confidence and ClamAV/YARA state using fixed data-driven wording. It has no model call and no scanner/publication authority.

Headline metric cards are direct navigation controls: immutable-analysis counts open the exact flattened analysis records; artifact/lifecycle/global-index counts open their matching records; queue cards filter to the exact queue state; finding totals open per-variant contribution rows so the displayed total can be reproduced and each variant can be opened for its raw immutable findings. Immutable analysis rows can open their hash-verified manifest in the read-only row inspector.

The refreshed visual system is Tailwind-inspired but compiled into the existing self-contained HTML/CSS so local/offline DeltaScope does not depend on a CDN.


## DeltaScope security researcher workbench

The default DeltaScope interaction is now case-oriented. Select a variant from the research queue, review deterministic TONI triage signals, check ClamAV/YARA and static findings, inspect endpoints and code/native behavior, then validate supply-chain/source correspondence and immutable evidence. Headline cards remain exact drill-downs; the raw table browser is intentionally secondary. No AI/LLM participates in these signals or in SigmaScope decisions.


### Coverage-first queue / DeltaScope coverage visibility

SigmaScope prioritizes never-scanned active variants before revisiting variants that already have published evidence. DeltaScope surfaces this as `Never scanned` coverage and makes `SOURCE CODE` versus `ARTIFACT ONLY` explicit; source availability is not the same thing as source→artifact verification. Online Evidence-v2 cache filenames are short content-derived keys to remain safe on long Windows cache prefixes.

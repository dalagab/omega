# Omega

[![Client regression tests](https://github.com/dalagab/omega/actions/workflows/regression-tests.yml/badge.svg?branch=main)](https://github.com/dalagab/omega/actions/workflows/regression-tests.yml)
[![Release publisher](https://github.com/dalagab/omega/actions/workflows/release.yml/badge.svg?branch=main)](https://github.com/dalagab/omega/actions/workflows/release.yml)
[![Catalog refresh launcher](https://github.com/dalagab/omega/actions/workflows/catalog-builder.yml/badge.svg?branch=main)](https://github.com/dalagab/omega/actions/workflows/catalog-builder.yml)
[![Source submission intake](https://github.com/dalagab/omega/actions/workflows/source-submissions.yml/badge.svg?branch=main)](https://github.com/dalagab/omega/actions/workflows/source-submissions.yml)

**Omega is a Dalamud plugin marketplace and discovery layer.**

Omega helps users find public Dalamud plugins, understand where they come from, inspect metadata and security evidence, and then hand installation back to Dalamud. Omega does **not** replace Dalamud's plugin installer and does **not** guarantee that every listed plugin is safe.

## Quick Links

| Need | Go here |
| --- | --- |
| Install Omega | https://dalagab.github.io/omega/#install |
| Use the public website | https://dalagab.github.io/omega/ |
| Report an incorrect scanner result | https://github.com/dalagab/omega/issues/new?template=scanner-result.yml |
| Work on the Omega client | [`main`](https://github.com/dalagab/omega/tree/main) |
| Work on SigmaScope, DeltaScope, SRL/Stigma-1, or Evidence tooling | [`sigmascope`](https://github.com/dalagab/omega/tree/sigmascope) |
| Work on runtime observation and sandboxing | [`rift`](https://github.com/dalagab/omega/tree/rift) |
| Work on the public website | [`website`](https://github.com/dalagab/omega/tree/website) |

## What Omega Does

Omega collects public Dalamud plugin repository information and presents it as one in-game marketplace. It can show:

- plugin names, descriptions, authors and source repositories;
- available versions, changelogs and project links;
- repository/source provenance;
- dependency and compatibility information;
- published SigmaScope security evidence and findings.

When a user chooses to install something, Dalamud still performs the installation.

## Installation

Use the website installation page:

**https://dalagab.github.io/omega/#install**

The installation page has the current Omega repository link, a copy button, and the steps for adding it to Dalamud. The actual repository URL is intentionally kept there rather than duplicated in this README, so there is one authoritative installation location.

## Safety Model

Omega provides **more information**, not a blanket approval system.

A plugin appearing in Omega does not mean it is approved, recommended, or guaranteed to be safe. Omega and SigmaScope publish evidence, classifications and provenance so users and maintainers can make better decisions and report scanner mistakes.

## Repository Map

Omega uses multiple long-lived branches because the client, security services, generated data, runtime sandbox, and website have different release and authority boundaries.

| Branch | Purpose |
| --- | --- |
| [`main`](https://github.com/dalagab/omega/tree/main) | Omega Dalamud client, client release source, default-branch workflow registrations |
| [`omega`](https://github.com/dalagab/omega/tree/omega) | Active Omega client implementation branch used by client regression workflows |
| [`sigmascope`](https://github.com/dalagab/omega/tree/sigmascope) | Security services: SigmaScope, DeltaScope, SRL/Stigma-1, Evidence-v2, Definitions and orchestration |
| [`rift`](https://github.com/dalagab/omega/tree/rift) | Interdimensional Rift runtime observation, sandboxing, Alpha and canary work |
| [`catalog-data`](https://github.com/dalagab/omega/tree/catalog-data) | Generated catalog, Definitions and queue state |
| [`security-evidence-v2`](https://github.com/dalagab/omega/tree/security-evidence-v2) | Published generated Security Evidence data |
| [`deep-scan-state`](https://github.com/dalagab/omega/tree/deep-scan-state) | Generated deep-scan queue and result state |
| [`website`](https://github.com/dalagab/omega/tree/website) | Public website source |

## Main Workflows

These workflow files live on `main` because GitHub Actions discovers manually dispatched and scheduled workflows from the default branch. Several are launchers or registration copies that immediately hand off to the branch that owns the real implementation.

| Workflow file | Display name | Role |
| --- | --- | --- |
| `.github/workflows/regression-tests.yml` | Omega client - build and regression tests | Builds the client branch and runs client regression checks. |
| `.github/workflows/release.yml` | Omega client - publish release | Builds, attests and publishes tagged Omega client releases. |
| `.github/workflows/catalog-builder.yml` | Omega catalog - scheduled refresh and security handoff | Starts catalog refresh work and security-service follow-up. |
| `.github/workflows/source-submissions.yml` | Omega catalog - source submission intake | Receives source-submission issues/manual input and delegates validation. |
| `.github/workflows/sigmascope.yml` | SigmaScope - scheduled production drain launcher | Scheduled/manual launcher for SigmaScope production drain work. |
| `.github/workflows/sigmascope-drain-wake.yml` | SigmaScope - coalesced drain wake registration | Default-branch registration wrapper for drain wake dispatch. |
| `.github/workflows/sigmascope-parallel-drain.yml` | SigmaScope - parallel drain registration | Default-branch registration wrapper for parallel queue drain dispatch. |
| `.github/workflows/security-orchestration-heartbeat.yml` | Security services - collector heartbeat launcher | Periodically wakes security-service reconciliation. |
| `.github/workflows/security-orchestration-dispatch.yml` | Security services - internal dispatcher registration | Default-branch registration endpoint for internal security workers. |

## What is SigmaScope?

**SigmaScope** is Omega's deterministic production security-analysis service.

Its primary job is static evidence gathering: it examines plugin packages and, where available and attributable, source material as **data**. It does not load the plugin into the game and does not need to execute the plugin to perform its static analysis.

SigmaScope collects and publishes evidence such as:

- package and artifact identity;
- hashes and provenance;
- managed and native components;
- dependencies;
- capabilities and permissions;
- endpoint evidence;
- source-to-artifact attribution;
- YARA and ClamAV secondary evidence;
- normalized observations used by the rules system;
- scan coverage and lifecycle information.

SigmaScope reports evidence. It is not intended to be an unquestionable malware verdict system.

The production SigmaScope implementation does **not** live on `main`. It lives on the [`sigmascope`](https://github.com/dalagab/omega/tree/sigmascope) branch.

## What is the Rift?

The **Interdimensional Rift** is Omega's isolated runtime-observation environment.

Where SigmaScope asks _"what does this artifact contain and what capabilities can we establish statically?"_, Rift is designed to collect bounded runtime observations outside FFXIV.

Rift uses an instrumented Dalamud-compatible host and, for untrusted execution, a fail-closed Linux sandbox boundary. Its observations are deliberately neutral: Rift does not assign security severity and does not replace SigmaScope's static analysis.

Rift lives on the [`rift`](https://github.com/dalagab/omega/tree/rift) branch.

### Alpha

**Alpha is a component inside the Rift**, not a separate top-level Omega branch.

Alpha is used as a controlled/calibration subject for the Rift runtime-observation and containment contracts. Its documentation is in:

- `rift: docs/ALPHA.adoc`
- `rift: tools/package-alpha.sh`

The Rift implementation itself is under:

- `rift: InterdimensionalRift/`
- `rift: InterdimensionalRift.DalamudShim/`
- `rift: tools/`
- `rift: docs/`

## What is SRL / Stigma-1?

Omega's rule system is developed alongside SigmaScope on the `sigmascope` branch.

The core implementation and migration/audit tooling currently lives under `tools/security/`, including:

- `tools/security/srl.py` — the rule-language/evaluation implementation;
- `tools/security/stigma1.py` — Stigma-1 entry point/compatibility surface;
- `tools/security/srl_evidence_replay.py` — replay of rules over retained evidence;
- `tools/security/srl_migration_parity.py` — parity checks during migration;
- `tools/security/srl_cutover_readiness.py` — read-only cutover-readiness audit;
- `tools/security/rule_reprojection.py` — deterministic rule-only reprojection;
- `tools/security/rule_lab.py` — developer rule-authoring and test support.

SRL/Stigma-1 consumes normalized evidence and observations. It does not give developer tooling permission to rewrite published evidence or silently promote a rule into production.

## What is DeltaScope?

**DeltaScope** is the developer/researcher-facing security workbench.

It is intentionally **read-only with respect to production security state**. It consumes already-generated SigmaScope/Security Evidence data so developers and analysts can inspect incidents, events, assets, rules, provenance, relationships, coverage, and rule projections.

DeltaScope lives with the security-service implementation on the [`sigmascope`](https://github.com/dalagab/omega/tree/sigmascope) branch, primarily under:

- `tools/security/deltascope.py`
- `tools/security/deltascope_workbench.py`
- `tools/security/deltascope_operations.py`
- `tools/security/deltascope_provenance.py`
- `tools/security/deltascope_rule_store.py`
- `tools/security/developer_view.py`

DeltaScope is **not part of the production scanning pipeline** and does not get authority to alter SigmaScope findings, scan queues, Definitions, severity, or published Security Evidence.

## Repository and branch layout

Omega is one GitHub repository, but the project is intentionally split across branches because the client, scanners, sandbox, generated data, and website have very different lifecycles.

| Branch | Role | Important locations |
| --- | --- | --- |
| [`main`](https://github.com/dalagab/omega/tree/main) | **Omega Dalamud client** and client-facing release source | `Omega/`, `Omega.RegressionTests/`, `sources/`, `catalog/`, `repository/`, `tools/release/` |
| [`sigmascope`](https://github.com/dalagab/omega/tree/sigmascope) | **Security services**: SigmaScope, DeltaScope, SRL/Stigma-1, deep-scan orchestration, Security Evidence tooling and security definitions | `tools/security/`, `tools/catalog/`, `security-definitions/`, `docs/`, `SECURITY-SERVICES.md` |
| [`rift`](https://github.com/dalagab/omega/tree/rift) | **Interdimensional Rift** runtime observation and hostile-code sandbox work; includes **Alpha** | `InterdimensionalRift/`, `InterdimensionalRift.DalamudShim/`, `tools/`, `docs/ALPHA.adoc`, `docs/RIFT-SANDBOX-PROFILE.adoc` |
| [`catalog-data`](https://github.com/dalagab/omega/tree/catalog-data) | **Published/generated catalog state** consumed by services and clients | `catalog/`, `definitions/`, `scan-queue.json`, `source-inventory.json`, `index.json` |
| [`security-evidence-v2`](https://github.com/dalagab/omega/tree/security-evidence-v2) | **Published Security Evidence v2 data** rather than application source | `variants/`, `artifacts/`, `derived/`, `history/`, `terminal/`, `indexes/`, `rule-projections/`, `scanner-queue.json` |
| [`website`](https://github.com/dalagab/omega/tree/website) | **Public Omega website** | `site/`, `images/`, website build tooling |

Dependabot branches are normal automated dependency-maintenance branches and are not part of Omega's architecture.

### Important consequence

Checking only `main` does **not** show the complete Omega security platform.

`main` is primarily the **client/consumer side**. The active security-service implementation is developed on `sigmascope`; runtime observation and containment live on `rift`; generated operational/catalog state is published to `catalog-data`; immutable/derived security evidence is published to `security-evidence-v2`; and the public site is maintained on `website`.

## High-level security data flow

At a deliberately simplified level:

```text
Public plugin repositories + release artifacts
                    |
                    v
          Catalog/source collection
                    |
                    v
               SigmaScope
        static security evidence
                    |
          +---------+---------+
          |                   |
          v                   v
   catalog-data       security-evidence-v2
          |                   |
          +---------+---------+
                    |
        +-----------+-----------+
        |                       |
        v                       v
   Omega client             DeltaScope
 user-facing view      developer investigation


Additional / escalated runtime investigation:

SigmaScope / rule outcomes
          |
          v
   deep-scan request
          |
          v
 Interdimensional Rift
  sandboxed observation
          |
          v
 retained observations/evidence
          |
          v
 SRL / Stigma-1 correlation and reprojection
```

This diagram is intentionally conceptual. Individual workflows remain fail-closed and preserve the separation between static evidence, runtime observations, rules, published data, and user-facing presentation.

## Security-service ownership at a glance

### SigmaScope owns

- deterministic production static analysis;
- artifact/source evidence gathering;
- security definitions and scanner contracts;
- dependency, native, endpoint and capability evidence;
- secondary YARA/ClamAV evidence;
- scan/evidence lifecycle;
- deep-scan request contracts and queue tooling;
- publication of Security Evidence.

### Rift owns

- isolated execution of opted-in/deep-scan artifacts;
- runtime instrumentation;
- neutral runtime observations;
- containment and sandbox boundary testing;
- Alpha and Canary calibration/containment fixtures.

Rift does **not** duplicate SigmaScope static scanning.

### SRL / Stigma-1 owns

- deterministic rules over normalized observations/evidence;
- rule compilation/evaluation;
- replay/reprojection;
- migration parity and cutover-readiness checks.

### DeltaScope owns

- read-only developer/research presentation;
- investigation and comparison views;
- Rule Lab development workflows;
- evidence, provenance and relationship browsing.

DeltaScope does **not** publish production evidence or mutate production scanner decisions.

### Omega client owns

- user-facing marketplace and library;
- repository/source presentation;
- installation coordination through Dalamud;
- presentation of published security findings and evidence;
- user acknowledgement and permission/risk surfaces.

The client consumes security information; it is not the production scanner.

## Where is the website?

**https://dalagab.github.io/omega/**

The website source lives on the [`website`](https://github.com/dalagab/omega/tree/website) branch.

## Support

For installation help, questions, feedback, or corrections, join the [Omega Discord](https://discord.gg/rMBHbJTjp).

## I am a developer

You are in the right repository, but **make sure you are on the branch that owns the thing you want to change**.

For client work:

- `main: Omega/` — the Dalamud plugin.
- `main: Omega.RegressionTests/` — C# regression tests.
- `main: sources/` — source/repository information used by the client-side project.
- `main: tools/release/` — client release tooling.
- `main: SECURITY.md` — client-facing security/reporting boundary.
- `main: CHANGELOG.md` — client development and release changes.

For security-service work:

- `sigmascope: tools/security/` — SigmaScope, DeltaScope, SRL/Stigma-1, Evidence-v2 and deep-scan tooling.
- `sigmascope: tools/catalog/` — catalog/security-service collection and generation tooling.
- `sigmascope: security-definitions/` — reviewed security definitions and capability/rule data.
- `sigmascope: docs/` — security architecture, rule language, developer profile and workbench documentation.
- `sigmascope: SECURITY-SERVICES.md` — current service boundaries and invariants.

For runtime sandbox work:

- `rift: InterdimensionalRift/` — host, runtime, instrumentation and reporting.
- `rift: tools/` — Bubblewrap/seccomp runners, contract checks and packaging.
- `rift: docs/` — Rift hardening, sandbox profile, Alpha and runtime-observation contracts.

For generated data, do not mistake publication branches for normal application-source branches:

- `catalog-data` — generated catalog/Definitions/queue state.
- `security-evidence-v2` — generated published evidence and history.

## Is Omega wrong about your plugin?

If you maintain a plugin and believe Omega or SigmaScope has described it incorrectly, **please tell us**.

Scanner results are evidence and classifications, not unquestionable verdicts. If a security finding, capability, automation classification, dependency, endpoint, source association, or other result is wrong, we want to know **what was reported and where the scanner went wrong**.

Use the scanner-result correction form:

**https://github.com/dalagab/omega/issues/new?template=scanner-result.yml**

Please include the plugin version, the result you believe is incorrect, what you think the correct result should be, and a link to the source code or other public evidence that lets us verify it.

The goal is not to give individual plugins special treatment. If the scanner logic is wrong, we want to fix the logic so the correction applies consistently to everyone.

## One last thing

Omega is an independent community project. It is not affiliated with Square Enix, Dalamud, XIVLauncher, or FINAL FANTASY XIV.
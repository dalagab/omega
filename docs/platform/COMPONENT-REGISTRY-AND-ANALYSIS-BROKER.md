# Component Registry and Analysis Broker

Omega separates **components**, **collectors**, **observations**, **rules**, and **workflow launch authority**.

## Component boundary

A component is a deployable or trust-boundary unit. A collector is an implementation owned by a component that supplies one or more typed observations. Rules bind to observations, never directly to collector or component implementations.

The authoritative machine-readable registry is `omega.component-registry.v1`. It is frozen into daily Definitions at `definitions/platform/component-registry.json`; the matching collector registry is frozen at `definitions/platform/collector-registry.json`.

Current component states are deliberately honest:

- `omega.platform.main` — active workflow-launch authority;
- `omega.analysis-broker` — active request resolver/state service, callable from `main`, but unable to launch providers itself;
- `omega.analysis-dispatcher` — active `main` queue runner; claims one dispatchable work item with a lease and routes only through explicit allow-listed component jobs;
- `omega.catalog` — active canonical identity authority and client projection builder;
- `omega.discovery` — active, broker-dispatchable full-refresh reusable workflow, currently hosted on the `sigmascope` branch;
- `omega.sigmascope` — active and launchable from `main`; its current workflow consumes the canonical scan queue, so it is not yet directly dispatchable from a generic `omega.analysis-request.v1`;
- `omega.rift` — external from this branch; runtime observation contracts may be known, but Rift launch implementation is owned by the separate Rift workstream;
- `omega.threat-intelligence` — transition target; current reputation collection remains embedded and is not independently dispatchable yet;
- `omega.rebuilder` — planned source-to-artifact build-provenance component;
- `omega.stigma-1` — deterministic rule engine, non-dispatching;
- `omega.evidence-v2` — retained evidence store;
- `omega.deltascope` — read-only developer/research workbench;
- `omega.client` — end-user consumer of compact catalog/security projections, with no security verdict authority.

A component may be present in the registry without being dispatchable. The Analysis Broker must never infer runnable status merely from the existence of a component or collector.

## Generic analysis request

`omega.analysis-request.v1` is the implementation-neutral request envelope. It contains:

- logical observation type;
- exact subject identity;
- reason and priority;
- requesting rule/evaluation lineage;
- freshness/reuse policy;
- no collector ID and no component ID.

Example:

```json
{
  "schema": "omega.analysis-request.v1",
  "observation": "binarySignatureTrust",
  "subject": {
    "type": "artifact",
    "artifactSha256": "<sha256>"
  },
  "reason": "Need signature trust evidence for this exact artifact.",
  "priority": 700,
  "requestedBy": {
    "componentId": "omega.stigma-1",
    "ruleId": "binary.signature-trust-needed"
  }
}
```

Provider implementation fields are rejected. Stigma-1 may request an observation, but it cannot choose or execute its provider.

## Resolution

The broker resolves a request in two steps:

1. Collector Registry: which collectors can provide the logical observation?
2. Component Registry: which components own those collectors, and are those components currently dispatchable?

The result distinguishes:

- **satisfiable** — at least one active provider exists;
- **dispatchable** — at least one active provider belongs to an active reusable-workflow component that this control plane is allowed to queue for launch;
- **planned/external** — visible in architecture and rule authoring, but not runnable from this branch.

Discovery observations use an aggregate strategy: multiple collectors owned by the same component are grouped into one component work item. Most security observations use a single-provider strategy.

## Broker state

`omega.analysis-broker-state.v1` is bounded durable orchestration state. Work item states are:

`requested -> queued -> running -> completed|failed`

with terminal/administrative states `expired`, `superseded`, and `cancelled`. Failed work may be explicitly requeued.

The broker state workflow on `sigmascope` only resolves, queues and atomically publishes state to `analysis-broker-state`. It **does not execute scanner workflows**. The default `main` branch remains the only intended workflow-launch control plane.

## Dispatcher

The dispatcher is deliberately a queue runner, not another decision engine. `analysis-dispatcher-batch-claim.yml` serializes only the short broker-state mutation, recovers expired leases, and atomically reserves as many currently dispatchable `queued` items as fit the configured worker-pool capacity. Every reservation is persisted as `running` before any component workflow is started, so overlapping dispatcher runs see the in-flight work and cannot claim it again. The claim re-resolves the component and collector registries at claim time; any workflow path retained in old queue data is advisory only and cannot select execution.

The `main` runner template at `docs/workflow-callers/analysis-dispatcher-main.yml` polls every five minutes, reserves up to four jobs with a four-job global in-flight ceiling, then asynchronously starts explicit allow-listed worker workflows and exits. Component registry `maxConcurrent` limits are enforced independently of the global pool; Omega Discovery is currently capped at one full refresh at a time. Today only `omega.discovery` is generic-request dispatchable. SigmaScope remains launchable through its canonical scan queue until a separate generic-request adapter is implemented.

Claims use `omega.analysis-dispatch-claim.v1` with a bounded lease and claim token; a multi-reservation pass is reported as `omega.analysis-dispatch-batch.v1`. The default-main Discovery worker calls the reusable component workflow and then settles the exact lease. Successful component jobs settle `completed`; failed jobs are requeued up to the configured attempt bound; a cancelled/dead worker is recovered after lease expiry. `analysis-dispatcher-settle.yml` requires the exact claim token, preventing stale workers from settling a later retry.

The dispatcher never evaluates Stigma-1 rules, chooses providers, executes a workflow path from queue JSON, or writes security findings/evidence.

## Freshness

Observation contracts declare reuse semantics independently of the scanner implementation:

- static artifact observations: immutable with the exact artifact subject;
- build proof: immutable with exact source+artifact identity;
- runtime observations: immutable with exact subject+exercise profile;
- discovery candidates: short TTL snapshots;
- DNS/connectivity/reputation: explicit TTL observations.

This lets the future main dispatcher decide whether an existing retained observation satisfies a request before launching work.

## Security/authority rules

- Components provide observations; they do not gain catalog identity authority from registration.
- Stigma-1 may emit deterministic findings and observation requests, but cannot run a component.
- The broker may resolve and queue work, but cannot execute plugin/scanner code.
- The dispatcher may claim/settle broker work, but its `main` workflow may route only through explicit allow-listed component jobs.
- `main` owns workflow launch policy.
- Evidence-v2 remains the retained security evidence authority.
- DeltaScope is read-only and never participates in production dispatch decisions.

# Platform operations

DeltaScope’s Operations perspective is a read-only view of the platform’s health and recent work. It is designed to show **what is happening and why**, without becoming a second production control plane.

## What Operations should answer

- Is current published evidence healthy and internally consistent?
- Which workflow/component is running or failing?
- Are any production authority gates intentionally closed?
- How much scan work is pending or retrying?
- Are collectors succeeding and producing expected coverage?
- Is Deep Scan accumulating requests?
- Are generic Analysis Broker requests unresolved, queued, running, failed or satisfied by fresh retained observations?
- What Definitions and scanner identities produced the current evidence?

## Dashboard

The Operations dashboard summarizes current evidence, Definitions, SigmaScope, current findings, queue state and important notifications. It should emphasize actionable state; exact revision IDs remain available in System Health for reproducibility.


## Automatic published-state refresh

Online DeltaScope follows verified published security state automatically. It performs an immediate revision check when the workbench opens and then checks at a bounded interval. A newer Evidence, Definitions, rule-set or Definitions-provenance publication is loaded automatically after integrity verification.

A normal successful update is informational history, not an item that requires operator acknowledgement. DeltaScope coalesces it into one `Published security state updated` event. If refresh verification fails, the previous verified snapshot remains active and **Needs attention** shows one retryable failure instead of silently moving to partially published data.

The manual **Refresh now** control is therefore a recovery/explicit-check action. It is normally hidden because healthy publication changes are followed automatically.

## Pipelines

Pipelines shows recent GitHub Actions runs. This data is fetched through the public GitHub API and is read-only. A workflow failure in Pipelines does not itself alter evidence; evidence publication remains subject to its own validation and last-known-good behavior.

## Collectors

Collectors is the component-level data-acquisition view. It maps stable workflow jobs/steps to named collectors and combines recent run history with current evidence metrics. Use it to distinguish “the workflow ran” from “the specific collection stage ran successfully”.

## Analysis Broker

The Analysis Broker is durable **request-resolution state**, not a scanner and not a workflow dispatcher. It records implementation-neutral `omega.analysis-request.v1` work, resolves registered providers, applies observation freshness/reuse policy and retains lifecycle state. `main` remains the workflow-launch authority. An unresolved or non-dispatchable request should remain visible rather than being silently dropped.

SigmaScope now accepts subject-bound generic broker requests through `sigmascope_request_adapter.py`. The adapter merges requested work into the existing canonical SigmaScope scan queue and verifies the requested Evidence-v2 observation before settlement; it does not create a second scanner queue. SigmaScope remains capped at one broker-managed concurrent execution until scan execution is separated from serialized Evidence-v2 merge/publication.

## Scan queue

Queue metrics describe pending work, retry work, completed work and why items were queued. Queue reasons should remain typed and attributable to a concrete invalidation event, such as a new artifact, source revision change, advisory revision change or missing observation.

## Definitions and gates

A **gate** is an intentional authority boundary, not necessarily a fault. For example, a rule system can be available for local replay while production write-back remains gated. DeltaScope should surface gates prominently because they affect what the platform is permitted to publish.

## Current versus archive

Operational totals are current-state metrics. Historical plugin versions remain queryable for research, but they are excluded from current severity totals and current incident counts.

## When a collector or pipeline fails

1. Open Collectors or Pipelines and identify the failing workflow/job/step.
2. Follow the GitHub Actions run link for exact runner logs.
3. Check whether the failed stage published anything; publication jobs should fail closed when required inputs are invalid.
4. Check the current Evidence-v2 revision. Last-known-good evidence can remain valid even while a new run is failing.
5. Check queue retry state for retained failed work.
6. If the failure concerns Definitions or evidence integrity, do not bypass the check merely to publish a newer timestamp.

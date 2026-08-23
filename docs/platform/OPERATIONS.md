# Platform operations

DeltaScope’s Operations perspective is a read-only view of the platform’s health and recent work. It is designed to show **what is happening and why**, without becoming a second production control plane.

## What Operations should answer

- Is current published evidence healthy and internally consistent?
- Which workflow/component is running or failing?
- Are any production authority gates intentionally closed?
- How much scan work is pending or retrying?
- Are collectors succeeding and producing expected coverage?
- Is Deep Scan accumulating requests?
- What Definitions and scanner identities produced the current evidence?

## Dashboard

The Operations dashboard summarizes current evidence, Definitions, SigmaScope, current findings, queue state and important notifications. It should emphasize actionable state; exact revision IDs remain available in System Health for reproducibility.

## Pipelines

Pipelines shows recent GitHub Actions runs. This data is fetched through the public GitHub API and is read-only. A workflow failure in Pipelines does not itself alter evidence; evidence publication remains subject to its own validation and last-known-good behavior.

## Collectors

Collectors is the component-level data-acquisition view. It maps stable workflow jobs/steps to named collectors and combines recent run history with current evidence metrics. Use it to distinguish “the workflow ran” from “the specific collection stage ran successfully”.

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

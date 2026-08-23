# Deep Scan workflow

Deep Scan is Omega’s bounded follow-up analysis path for cases that justify more evidence than the normal scan budget.

## Why it exists

A normal catalog-wide scanner must remain predictable and bounded. Some findings are interesting enough to justify additional comparison or analysis without making every plugin analysis expensive.

## Request model

A Stigma-1 rule can emit a typed `analysisRequest` containing information such as:

- the approved analysis profile;
- requested depth/budget class;
- the rule/reason that triggered the request;
- the target plugin/artifact identity.

The rule cannot provide arbitrary commands, scripts, runner paths, network policy or executable payloads.

## Code-owned profiles

The worker accepts only profiles implemented and approved in code. A request for an unknown or unavailable profile fails closed.

An artifact-differential profile can compare a candidate artifact with an approved baseline using non-executing static inspection. Execution/sandbox profiles must not be enabled until the platform provides an isolation model suitable for untrusted plugin execution.

## Durable queue

Deep-scan requests are published to a durable queue so they survive workflow boundaries. The worker selects a request, resolves a bounded budget, executes the approved profile and writes durable result state.

## DeltaScope

Journey shows whether Deep Scan was:

- not requested;
- requested;
- pending;
- completed;
- unavailable/failed.

The explanation should show the rule/reason, selected profile/depth and resulting evidence when available.

# DeltaScope data acquisition and local snapshots

DeltaScope is a local client. Remote acquisition is deliberately separated from navigation and presentation.

## Core rule

Opening or switching a DeltaScope page must not refresh remote data.

The client reads a locally held snapshot. Remote data changes only when:

1. DeltaScope performs its one initial acquisition for operational GitHub context; or
2. the user explicitly refreshes a source from **9-dot menu → Data sources**; or
3. credentials are changed and the GitHub access snapshot must be rebuilt.

There are no page-driven polling loops and no TTL expiry that silently turns a view render into a network request.

## Source transports

### Published Evidence / Definitions

Security Evidence v2 and frozen Definitions are published Git-backed datasets. DeltaScope currently keeps a verified local snapshot/cache and refreshes it explicitly. A future Git transport may use a shallow/sparse local repository, but the authority boundary does not change: the checked-out commit is still only a local read-only consumer snapshot.

A Git transport is useful here because it can give the client one commit-consistent tree and atomic branch-tip updates. If implemented, prefer a bounded shallow/sparse fetch into DeltaScope's cache root; never run `git pull` from a page renderer.

### GitHub Actions / runner history

Git clone is **not** a substitute for GitHub Actions acquisition. Workflow runs, jobs, step outcomes, artifacts and logs are API data and are not contained in the Git repository.

DeltaScope therefore acquires this operational context through the GitHub API once into a process-local snapshot. Dashboard, Events and Collectors all project the same acquired runner data until the user explicitly refreshes it.

### Public Git endpoint status

Public repository/Actions/Releases/Security page probes are also a snapshot. They are refreshed only by the acquisition controller and never by opening Operations.

## Refresh boundary

The Data sources control owns refresh. A refresh may replace one source or all sources, after which affected local projections are invalidated and recomputed from the new snapshot.

Recomputing a local projection is not remote acquisition. For example, Detection Coverage may be recomputed from the already-loaded Evidence/Definitions snapshot without contacting GitHub.

## Authority

Acquisition changes only what the local DeltaScope client can see. It does not mutate Security Evidence, Definitions, Stigma-1 production state, scan queues, GitHub workflows, or any other production authority.

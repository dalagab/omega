# SigmaScope Phase 4 automatic cutover

`Omega SigmaScope · Phase 4 automatic migration` is the singular normal operator path for the Phase-4B/4C production migration. It replaces the former manual sequence of running a shadow workflow, copying its run ID, authorizing it separately, and rerunning the publisher with write confirmation.

## What one run does

1. Requires `confirm_migration=true` and a bounded `max_workers` value from 1 through 8.
2. Rebuilds and publishes all four current worker images from the exact caller commit and their immutable `@sha256:` manifest.
3. Runs the explicit catalog freeze so the current SigmaScope code is captured in frozen Definitions. The normal freeze contract is unchanged: all required Phase-3 collection lanes must already be settled.
4. Enters the locked cutover core and acquires the same `omega-catalog-sigmascope-exclusive` mutex used by every authoritative Evidence-v2 publisher.
5. Re-verifies all four worker-image references and that the newly frozen Definitions worker contains the fast-forward history helper and parallel-publication authorization support.
6. Requires at least one eligible real-corpus artifact/source queue assignment.
7. Runs the normal read-only Phase-4B parallel shadow, sequential reference, equivalence proof, intrinsic validation, developer audit and storage audit.
8. Passes those immutable artifacts directly to the Phase-4C authorizer in the same Actions run and binds them to the exact run ID/attempt.
9. Reconstructs the candidate from the result bundles and authorizes it only if the Evidence base is still exact.
10. Publishes Evidence-v2 first through the tiny one-writer job, then the authorized Deep Scan state, then source-followup issue reconciliation.
11. Re-checks that Evidence is the exact authorized immediate child (or an explicit identical-tree no-op) and that published Deep Scan state has the exact authorized SHA-256.
12. Uploads `omega-sigmascope-phase4-migration-receipt` for 90 days.

## Fail-closed behavior

The migration does not rebase or silently retry onto a newer Evidence head. Any failed prerequisite, shadow mismatch, audit failure, stale base, authorization mismatch, publication failure, or post-publication hash mismatch fails the run. Because the global Evidence writer mutex is held from the first locked-core prerequisite job through final verification, the existing serialized scanner, Rift Evidence ingestion, and standalone Phase-4C publisher cannot race this migration.

The existing `sigmascope-parallel-shadow.yml` and `sigmascope-parallel-publish.yml` remain independently dispatchable for diagnostics. Normal cutover should use the singular migration workflow.

## After the first successful cutover

Do not immediately delete the serialized fallback. Retain it while additional real-corpus one-writer receipts are observed. Once those remain clean, ordinary artifact/source scheduling can move to the bounded parallel path and its concurrency can be raised. Specialist publisher lanes remain serialized unless separately migrated.

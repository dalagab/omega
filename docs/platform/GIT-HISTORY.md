# Git-backed authoritative history

Omega uses semantic/content-addressed revisions as the authority for catalog and security data. Git is an additional transport, concurrency, audit, and historical reconstruction layer; a Git commit by itself is **not** security authority.

## Authoritative branches

Two branch families deliberately retain normal Git history:

- `security-evidence-v2` — accepted, validated Security Evidence v2 snapshots.
- `catalog-data` — explicit frozen catalog/Definitions/client-publication boundaries.

Before the August 2026 migration these branches were replaced by a new orphan root commit at every publication. The first publication after this migration treats the then-current orphan head as the **genesis parent** and continues from it normally. No previous branch head is rewritten merely to invent unavailable history.

A changed publication is therefore:

```text
existing accepted head A
        |
        v
validated snapshot B
        |
        v
normal fast-forward push
```

If another publisher advances the remote after B was prepared, the normal Git push fails. The publisher must reconcile against the new authoritative head rather than force over it.

If B has exactly the same Git tree as A, publication is a no-op: no empty commit is created and the branch is not pushed.

## Emergency compatibility mode

`publish_catalog_state.py` and `publish_security_evidence_v2.py` retain `--history-mode legacy-orphan` as an explicit emergency/migration fallback. Production workflows pass `--history-mode fast-forward` explicitly and must not select legacy orphan mode during ordinary operation.

The fallback uses the former force-with-lease orphan snapshot behavior. Using it intentionally breaks the normal parent chain from that publication onward and therefore requires an operator reason outside the automated workflow.

## What does not retain forensic Git history

High-churn operational state remains replaceable/bounded state rather than an ever-growing forensic commit chain. Examples include:

- durable work queues and leases;
- per-lane worker state/result branches;
- Analysis Broker replaceable state;
- Deep Scan queue transport;
- worker-image manifest state;
- temporary parallel merge candidates.

Those objects have their own content-addressed revisions, leases, result identities, or retention semantics. Keeping every retry/lease mutation in the authoritative Evidence history would add noise and storage pressure without improving security conclusions.

## Provenance

Each authoritative publication reports:

- `previousHead` — remote head observed before publication;
- `parentHead` — parent used by the new fast-forward commit;
- `newHead` — accepted Git commit after publication;
- `treeSha` — exact Git tree identity;
- `historyMode`;
- `noOp` and `pushed`.

The Evidence/catalog JSON revisions remain the application-level identities. Git identities supplement them and allow an investigator to reconstruct and diff accepted historical snapshots.

## DeltaScope consumer direction

DeltaScope may use this history read-only to answer questions such as:

- what changed between two accepted Evidence revisions;
- when a variant/source/finding first appeared in accepted state;
- whether a catalog freeze changed security/Definitions inputs;
- which Evidence Git head a frozen catalog referenced;
- whether a historical change was an artifact scan, source refresh, TI/SRL reprojection, or catalog-only change.

DeltaScope must not infer safety, finding severity, or publication authority from Git metadata alone.

## Future retention/compaction

Normal history is enabled first so we can measure real growth. Later compaction may move especially high-churn derived/control artifacts out of authoritative history or introduce deliberate archival checkpoints, but it must never silently rewrite accepted forensic history without a separately documented migration.

# SigmaScope Git operations contract for RoboScope

RoboScope operator mutations are Git-backed. No standalone SigmaScope API server is required.
GitHub is the authenticated write boundary, `security-operations` is the append-only intent branch,
and the existing SigmaScope/catalog workflows remain the only production queue, evidence, and
publication authorities.

## Authority model

```text
RoboScope
  |
  | GitHub Contents API: append request JSON
  v
security-operations
  |                       Git commit history = operator audit trail
  +--> requests/scans/    scheduling intent only
  +--> requests/sources/  discovery candidate intent only
              |
              +-------------------------------+
                                              |
            normal scheduled / optional wake workflows
                     |                        |
                     v                        v
          SigmaScope drain planner       catalog discovery
                     |                        |
                     v                        v
          Security Evidence v2       enrichment / catalog freeze
```

RoboScope MUST NOT write `catalog-data`, `security-evidence-v2`, `security-work-state`,
`deep-scan-state`, generated lane-state branches, or frozen queue files. It cannot select scanner
executables, workers, workflows, queue keys, variants, source IDs, leases, branches, priorities,
or publication targets.

A request expresses operator intent. It is not evidence and cannot create, suppress, or alter a
security finding. Source request `type` is requested classification metadata, not trust or safety.

## Bootstrap

Run the existing **Omega security services reconciliation** once after deploying this contract (or wait
for its normal heartbeat). The reconciliation workflow idempotently creates `security-operations` as an
orphan state branch before reading operator requests, with:

```text
README.md
requests/
  scans/.gitkeep
  sources/.gitkeep
```

The bootstrap step is idempotent and does nothing when the branch already exists. Protect the branch
against deletion and force-push. Normal RoboScope operation only creates new JSON files beneath
`requests/scans/` or `requests/sources/`; it never edits an accepted request in place.

## Authentication

RoboScope authenticates directly to GitHub. A fine-grained token used for mutation needs repository
**Contents: read and write** for `dalagab/omega`. Existing read-only screens may continue to use the
same GitHub/Evidence reads they use today.

**Actions: write** is optional. When granted, RoboScope may dispatch the existing SigmaScope drain or
security reconciler after a successful request commit to reduce latency. The Git commit remains the
authoritative request; scheduled launchers are the fallback and requests do not depend on dispatch
succeeding.

Do not place GitHub tokens, credentials, workflow names, or branch names inside request JSON.

## Immutable request identity

Each request is one file and one event. Its `requestId` is content-derived from a canonical semantic
payload. This gives application-level idempotency in addition to Git's commit history and makes an
in-place semantic edit invalid.

Canonical JSON for the identity hash is UTF-8 JSON with:

- object keys sorted lexicographically;
- separators `,` and `:` with no insignificant whitespace;
- non-ASCII text encoded directly, not ASCII-escaped;
- no `requestId` field in the hashed payload.

The identifier is the request-kind prefix plus the first 24 lower-case hexadecimal characters of
the SHA-256 digest.

RoboScope MUST create the file as `<requestId>.json`. Repeating the same semantic request produces
the same path. If it already exists, compare the existing content and treat an exact match as
idempotent success; do not overwrite it.


Reference vectors for client tests:

```text
scan semantic JSON:   {"pluginIds":[476],"reason":"operator-nudge","requestedAtUtc":"2026-08-31T21:30:00Z","schema":"omega.roboscope.scan-nudge.v1"}
scan requestId:       scan-c1acf459c298c473dd145e74
source semantic JSON: {"notes":"","reference":"owner/repository","requestedAtUtc":"2026-08-31T21:31:00Z","schema":"omega.roboscope.source-request.v1","type":"custom"}
source requestId:     source-0202541e4657aa57c4c858d9
```

## Scan nudge request

Path:

```text
requests/scans/scan-<24hex>.json
```

Document:

```json
{
  "schema": "omega.roboscope.scan-nudge.v1",
  "requestId": "scan-0123456789abcdef01234567",
  "requestedAtUtc": "2026-08-31T21:30:00Z",
  "pluginIds": [476],
  "reason": "operator-nudge"
}
```

The semantic identity payload contains exactly `schema`, `requestedAtUtc`, sorted `pluginIds`, and
`reason`. `pluginIds` contains 1-10 unique positive integers and `reason` is exactly
`operator-nudge` in v1. Timestamps are whole-second RFC 3339 UTC.

### Nudge semantics

A scan request is pending for a plugin while no successful current artifact scan for that plugin has
`scanned_at_utc >= requestedAtUtc`. Once Evidence-v2 publishes such a scan, the request is satisfied
automatically. No mutable acknowledgement database is needed.

All unsatisfied request files for a plugin contribute to its scheduling demand:

```text
operatorNudgeCount = number of unsatisfied request events
operatorNudgeScore = min(500, operatorNudgeCount * 25)
```

The score is an ordering input only. It is applied inside the existing
`plugin-coverage-first-v2` scheduling lanes; it does not let a rescan leapfrog the system's minimum
coverage/source-provenance rules. Repeated operator requests therefore increase urgency without
turning RoboScope into a scanner dispatcher.

The drain planner builds a run-local effective queue seed. It never rewrites the frozen
`catalog-data/scan-queue.json`. For an active nudge the effective artifact target fingerprint also
binds the active request IDs. The same outstanding request set preserves retry/backoff state; a new
request creates new demand deliberately.

RoboScope should display a successful Git commit as **requested**, not **running**. Running/attempted
state still comes from SigmaScope workflow/Evidence state.

## Source request

Path:

```text
requests/sources/source-<24hex>.json
```

Document:

```json
{
  "schema": "omega.roboscope.source-request.v1",
  "requestId": "source-0123456789abcdef01234567",
  "requestedAtUtc": "2026-08-31T21:31:00Z",
  "reference": "owner/repository",
  "type": "custom",
  "notes": "optional operator note"
}
```

The semantic identity payload contains exactly `schema`, `requestedAtUtc`, trimmed `reference`,
lower-case `type`, and trimmed `notes` (including an empty notes string). Accepted `type` values are
`official`, `community`, and `custom`; they describe the operator's requested classification only.

Accepted reference forms are:

```text
owner/repository
https://github.com/owner/repository
https://public.example/path/to/pluginmaster.json
```

The Git intake rejects non-HTTPS URL forms, embedded credentials, fragments, local hostnames,
non-public literal IP addresses, control characters, and oversized values without performing
network I/O. The existing discovery worker repeats its public-network/DNS/redirect validation before
fetching anything.

A GitHub repository reference becomes a `catalogRepositoryCandidates` observation and enters the
bounded repository-tree manifest discovery path. A direct HTTPS feed becomes a source candidate.
Both retain `omega.collector.discovery.roboscope-operations` provenance and remain observation-only.
Canonical IDs are assigned only by the ordinary catalog pipeline.

A new source request revision makes durable `catalog-discovery` work due immediately at the next
reconciliation, rather than waiting for the six-hour cadence bucket. It still follows the existing
lease -> discovery result -> enrichment -> freeze chain.

## Invalid requests

Malformed, tampered, unknown-plugin, or otherwise unusable requests never gain production authority.
Scan overlay generation publishes a run artifact describing invalid request files and rejected
plugin intents. Source projection records invalid files in its local projection report and simply
does not pass them into discovery.

Invalid request files are not deleted automatically: their Git history remains useful for operator
audit. Correct them by creating a new valid request with a new content-derived ID.

## Published/read state for RoboScope

No new read API is required. RoboScope can derive control-room status from the existing published
surfaces:

- `security-operations`: immutable operator requests;
- `catalog-data`: canonical plugin/source identity and frozen base scan queue;
- `security-evidence-v2`: current scans, `scanner-queue.json`, retry/completion state, findings and coverage;
- `security-work-state`: durable discovery/enrichment collector leases and settlements;
- GitHub Actions: current workflow/run/job state;
- Git history and workflow links: optional patch tracking.

A source request is not **published** until the canonical catalog contains it. A scan nudge is not
**satisfied** until Evidence-v2 contains a successful scan at or after its request timestamp.

## Optional immediate wake

After committing a scan request, a client with Actions write permission may dispatch:

```text
sigmascope.yml @ sigmascope
```

After committing a source request, it may dispatch:

```text
security-orchestration-dispatch.yml @ sigmascope with mode=reconcile
```

These are latency optimizations only. RoboScope MUST consider the Git commit successful even if the
optional workflow dispatch fails; scheduled launchers will consume durable intent later.

## Audit and idempotency properties

The design has no separate mutable audit service:

- Git commit history identifies actor, commit time, tree content and parent;
- request IDs bind semantic request content;
- filenames bind request IDs to append-only paths;
- branch protection can prohibit history rewriting;
- scan satisfaction is proven by later authoritative Evidence-v2 timestamps;
- source acceptance/publication is proven by later discovery/catalog revisions;
- workflow runs provide execution history without becoming the request authority.

The `security-operations` branch is control-plane intent only. It must never be consumed as security
evidence or a source of trust.

# SigmaScope operations API for RoboScope

> **Superseded for operator mutations.** A standalone API server is not required. RoboScope now
> writes append-only scan/source intent to the `security-operations` Git branch and SigmaScope
> projects that intent into its existing queues. See `docs/sigmascope-roboscope-git-operations.md`.
> This document remains as design history for the earlier HTTP control-plane proposal.

RoboScope already reads published evidence and GitHub Actions state. The UX plan's operator actions require a small authenticated SigmaScope control-plane API; do not expose database writes directly to the client.

## Authentication and safety

- Accept a GitHub fine-grained token or exchange it for a short-lived RoboScope operator token.
- Authorize the single operator explicitly; return `401` for missing authentication and `403` for insufficient scope.
- Keep an immutable audit event for every accepted request: actor, time, request ID, action, affected IDs, and result.
- Return idempotency keys for every mutation. RoboScope will send `Idempotency-Key` for retries.
- Do not accept raw SQL, arbitrary commands, workflow names, branches, or repository URLs from the client.

## Published control-plane state

`GET /v1/operations/state`

Return the authoritative component, run, plugin, source, and patch summaries required by the control-room screens. Include `generatedAt` and per-record `updatedAt`; a record older than 60 seconds can be rendered as stale. This replaces RoboScope deriving component state from several static GitHub documents.

## Queue a scan

`POST /v1/scans/nudges`

Request body:

```json
{ "pluginIds": [123, 456], "reason": "operator-nudge" }
```

Validate one to ten known plugin IDs. Enqueue exactly once per idempotency key and return `202` with a request ID plus each resulting scan state (`queued`, `already_queued`, or `rejected`). The response must not claim a scan started until a worker has leased it.

## Add a source

`POST /v1/sources`

Request body:

```json
{ "reference": "owner/repository or https://...", "type": "official|community|custom", "overrideExisting": false, "notes": "optional" }
```

Validate and normalize the reference server-side. Return `201` with the source summary, `409` for an existing source without an override, and a field-level validation object for `422`. Queue any resulting catalog work asynchronously and expose it through `/v1/operations/state`.

## Patch tracking

RoboScope can continue to validate and commit ZipRunner patches directly through GitHub. To populate the full patch state machine, provide either `GET /v1/patches` and `GET /v1/patches/{id}`, or publish equivalent GitHub pull-request and workflow links. Each patch record needs its state, source/target branches, diff totals, linked run, failure summary, and activity events. Mutation endpoints are only needed if SigmaScope owns review, retry, or deployment; otherwise GitHub remains authoritative.

---

## Contract conventions

This is a control-plane contract, not a new Evidence-v2 authority. RoboScope supplies operator intent; SigmaScope resolves all implementation details server-side. The API MUST NOT permit a client to choose workflow names, branches, queue names, claim tokens, scanner executables, priorities, or result branches. The API MUST NOT edit published Evidence-v2 or the frozen catalog queue directly.

All production endpoints use HTTPS and UTF-8 JSON. `Accept: application/json` is recommended on reads and `Content-Type: application/json` is required on mutations. Timestamps are RFC 3339 UTC strings. Unknown request-body fields MUST be rejected rather than silently ignored.

The v1 base path is `/v1`. Breaking request or response semantics require a new major path such as `/v2`; adding optional response fields is backward compatible.

### Common request identity

The server MUST assign every request an opaque `requestId` and return it as both `X-Request-ID` and a JSON field. RoboScope MAY send `X-Request-ID` for correlation, but the server remains authoritative for collision handling.

Every mutation MUST send an `Idempotency-Key` header. Keys are scoped to the authenticated actor, HTTP method, canonical path, and canonical validated request body.

Idempotency rules:

- repeating the same key with the same canonical request returns the original API response and creates no duplicate work;
- repeating the same key with a different canonical request returns `409 idempotency_conflict`;
- concurrent requests using the same key converge on one accepted mutation;
- the server stores a SHA-256 of the canonical validated request next to the idempotency record;
- idempotency records SHOULD be retained for at least seven days so mobile retries survive app restarts and connectivity changes;
- the response echoes the effective idempotency key.

Idempotency is separate from SigmaScope work identity. A new idempotency key can still return `already_queued` when equivalent authoritative work already exists.

## Authentication and authorization details

All endpoints in this document require authentication, including read-only operations state and patch tracking.

RoboScope sends credentials as:

```http
Authorization: Bearer <token>
```

A deployment MUST support either direct validation of a GitHub fine-grained token or exchange that token for a short-lived RoboScope operator token. The authorization decision MUST explicitly match the configured operator; repository membership or generic repository write access is not sufficient by itself.

Recommended scopes are:

| Scope | Permission |
| --- | --- |
| `operations:read` | `GET /v1/operations/state` |
| `scans:nudge` | `POST /v1/scans/nudges` |
| `sources:create` | `POST /v1/sources` |
| `patches:read` | optional patch tracking reads |

A deployment may collapse these scopes into one operator role, but the server MUST enforce the same effective permissions.

Authentication failures are stable:

- `401` for missing, malformed, expired, revoked, or otherwise invalid authentication;
- `403` for an authenticated actor who is not the configured operator or lacks the required scope.

Tokens MUST NOT be accepted in query strings and MUST be redacted from logs and audit payloads.

### Optional operator-token exchange

If short-lived operator tokens are used, the server SHOULD expose:

```http
POST /v1/auth/exchange
Authorization: Bearer <github-token>
Content-Type: application/json
```

with an empty JSON object body. A successful response contains the short-lived bearer token, expiry, actor identity, and granted scopes. Recommended lifetime is 5–30 minutes; v1 defines no refresh token. The exchange operation is itself audited.

## Server-side validation and error envelope

Mutations are validated against server-owned current state. RoboScope MUST NOT be trusted to supply catalog existence, scan coverage, duplicate-source status, queue state, patch state, work IDs, leases, or claim tokens.

Validation order SHOULD be:

```text
transport bounds
→ authentication
→ authorization
→ request identity
→ JSON/schema validation
→ canonicalization
→ idempotency resolution
→ authoritative-state validation
→ immutable acceptance audit
→ bounded mutation/enqueue
→ immutable result audit
→ response
```

If authoritative state required for a safe decision is unavailable or internally inconsistent, the server returns `503` rather than guessing.

Field validation errors use `422` and do not perform partial mutations:

```json
{
  "error": {
    "code": "validation_failed",
    "message": "One or more fields are invalid.",
    "requestId": "req_01J...",
    "fields": {
      "pluginIds[1]": [
        "plugin ID is not known in the current published catalog"
      ]
    }
  }
}
```

Common status codes:

| Status | Meaning |
| --- | --- |
| `200` | successful read |
| `201` | accepted source registration |
| `202` | accepted asynchronous scan nudge |
| `400` | malformed HTTP or JSON |
| `401` | unauthenticated |
| `403` | unauthorized |
| `404` | API object not found |
| `409` | idempotency or source conflict |
| `415` | unsupported media type |
| `422` | field validation failed |
| `429` | rate limited |
| `500` | unexpected server failure |
| `503` | required authority dependency unavailable |

Client-visible errors MUST NOT include stack traces, tokens, Git credentials, filesystem paths, or raw subprocess output.

## Immutable audit contract

Every authenticated request accepted for API processing MUST produce immutable audit events. Mutations fail closed if the required audit append cannot be completed durably.

Minimum event shape:

```json
{
  "schema": "omega.sigmascope.operations-audit-event.v1",
  "eventId": "audit_01J...",
  "sequence": 1842,
  "occurredAt": "2026-08-31T21:04:00Z",
  "requestId": "req_01J...",
  "actor": {
    "githubUserId": 12345678,
    "login": "operator",
    "authMode": "github-fine-grained"
  },
  "action": "scan.nudge",
  "affected": {
    "pluginIds": [123, 456],
    "sourceIds": [],
    "patchIds": []
  },
  "requestSha256": "6b...",
  "result": {
    "httpStatus": 202,
    "code": "accepted"
  },
  "previousEventSha256": "d1...",
  "eventSha256": "a4..."
}
```

Audit rules:

- events are append-only and cannot be edited or deleted through this API;
- `sequence` is monotonically increasing within one authoritative stream;
- `eventSha256` covers canonical event content except the `eventSha256` field itself;
- `previousEventSha256` SHOULD form a hash chain; the first event uses `null`;
- credentials and authorization headers are never part of `requestSha256`;
- asynchronous mutations SHOULD emit immutable accepted and later state/result events linked by `requestId`;
- storage technology is implementation-specific, but durable ordering and append-only semantics are mandatory.

## `GET /v1/operations/state` response contract

Required scope: `operations:read`.

This endpoint is the canonical RoboScope control-room projection. It replaces client-side reconstruction from multiple GitHub documents, but it does not replace detailed Evidence-v2 reads.

A complete response has this top-level form:

```json
{
  "schema": "omega.sigmascope.roboscope-operations-state.v1",
  "generatedAt": "2026-08-31T21:04:00Z",
  "staleAfterSeconds": 60,
  "revisions": {
    "catalogRevision": "cat-json-v1-...",
    "definitionsRevision": "defs-v1-...",
    "evidenceRevision": "ev-v2-...",
    "queueSeedRevision": "queue-seed-v2-...",
    "selectionPolicy": "plugin-coverage-first-v2"
  },
  "summary": {
    "components": 13,
    "runs": 8,
    "plugins": 1344,
    "sources": 858,
    "patches": 0,
    "unscannedPluginsPending": 478,
    "unscannedRetryPlugins": 37
  },
  "components": [],
  "runs": [],
  "plugins": [],
  "sources": [],
  "patches": [],
  "requestId": "req_01J..."
}
```

Each record MUST contain its own `updatedAt`. Polling the API MUST NOT refresh that timestamp; it reflects the underlying authoritative state transition or observation. The server computes `stale=true` when `generatedAt - updatedAt > staleAfterSeconds`. Staleness is observation age, not failure.

Recommended component states are `operational`, `degraded`, `blocked`, `incomplete`, `planned`, and `unknown`.

Recommended run states are `queued`, `in_progress`, `success`, `failure`, `cancelled`, `skipped`, and `unknown`.

Plugin summaries SHOULD expose `pluginId`, names, active state, source IDs, current artifact-scan coverage, current queue state/reason, representative variant when known, attempt count, next eligibility, and timestamps. A queue item is not `leased` until authoritative worker state contains a lease/claim.

Coverage values describe evidence coverage only. The operations API MUST NOT derive a boolean `safe`, `trusted`, or equivalent security verdict from source provenance or scan coverage.

Source summaries SHOULD expose the current numeric source identity when published, registry ID when present, normalized reference, provenance type, plugin count, catalog-work state, and timestamps. Pending source registrations MAY have `sourceId: null` plus a stable `sourceRequestId` until the catalog assigns identity.

The server SHOULD emit an `ETag` for the coherent projection and honor `If-None-Match`. A `304` remains an authenticated read and is still audited.

## `POST /v1/scans/nudges` normative behavior

Required scope: `scans:nudge`.

The request body defined above remains intentionally small. `reason` is exactly `operator-nudge` in v1; clients cannot select arbitrary SigmaScope queue reasons.

Before acceptance, the server MUST verify that `pluginIds` contains 1–10 unique positive integer IDs, that booleans are not treated as integers, every ID exists in the current published catalog, and every plugin is currently active. Unknown or inactive IDs produce a request-level `422` and no partial enqueue.

After request-level validation, per-plugin policy may still produce `rejected` for bounded reasons such as `no_eligible_artifact`, `terminal_plugin`, or `operator_nudge_disabled`.

Acceptance sequence:

1. authenticate and authorize the operator;
2. validate and canonicalize the full request;
3. resolve idempotency;
4. append immutable acceptance audit data;
5. resolve current plugin/variant state server-side;
6. record one bounded nudge intent per plugin where needed;
7. let SigmaScope's existing scheduler select the actual variant, source, worker, and timing;
8. return `202`.

RoboScope cannot choose variant ID, source ID, priority, scanner revision, worker count, workflow, branch, claim token, or execution host.

An equivalent pending request returns `already_queued` and is not duplicated. An accepted nudge SHOULD appear as the existing server-side manual/operator rescan reason at the next queue reconciliation, without bypassing plugin-coverage-first ordering or retry/backoff.

Example response:

```json
{
  "schema": "omega.sigmascope.scan-nudge-response.v1",
  "requestId": "req_01J...",
  "idempotencyKey": "roboscope-scan-123-456-01",
  "acceptedAt": "2026-08-31T21:04:00Z",
  "scans": [
    {
      "pluginId": 123,
      "state": "queued",
      "workId": "work-v1-...",
      "message": null
    },
    {
      "pluginId": 456,
      "state": "already_queued",
      "workId": "work-v1-...",
      "message": null
    }
  ]
}
```

`queued` means durably queued, never started. The transition to leased/running is observed later through `/v1/operations/state`.

## `POST /v1/sources` normative behavior

Required scope: `sources:create`.

The `reference` field is the sole v1 exception to the general rule that clients do not provide repository URLs: this endpoint exists specifically to register a source. The value is still treated as untrusted source data, never as an instruction to clone a branch, run a command, or dispatch a workflow.

Accepted forms are:

```text
owner/repository
https://github.com/owner/repository
https://<allowed-public-host>/<repository-index-path>
```

The request handler MUST normalize and validate without executing arbitrary synchronous network actions against the supplied host. Network acquisition belongs to bounded catalog/source workers.

The server MUST reject non-HTTPS URL form, embedded credentials, URL fragments, control characters, ambiguous Unicode host tricks, unsupported schemes, loopback/link-local/multicast/private-network/local-domain targets, client-selected branches/refs, and overlong references. GitHub repository forms are normalized to one canonical `owner/repository` identity when applicable. Existing server-side source alias rules are applied before duplicate detection.

Any later worker that fetches a URL MUST repeat network-boundary checks after DNS resolution and every redirect so a public-looking hostname cannot redirect or resolve into a forbidden address.

`type` is exactly one of `official`, `community`, or `custom`. It is registry/provenance metadata, not a safety rating. A deployment MAY impose an additional server policy before allowing `official`; a client does not make a source authoritative merely by asking for that type.

`overrideExisting` is a JSON boolean. `notes` is optional bounded text and is never interpreted as instructions.

Duplicate detection uses normalized canonical identity plus configured aliases. Existing source + `overrideExisting=false` returns `409 source_exists`. With `overrideExisting=true`, the server may update only server-owned registration metadata allowed by policy; it MUST NOT delete evidence history, replace arbitrary source-controlled files, or modify unrelated sources.

A successful create/upsert returns `201` and queues the normal catalog work. Progress is visible in `/v1/operations/state` using states such as `registered`, `catalog_queued`, `catalog_leased`, `published`, or `failed`. `published` is not returned until the authoritative catalog contains the source.

Example response:

```json
{
  "schema": "omega.sigmascope.source-registration-response.v1",
  "requestId": "req_01J...",
  "idempotencyKey": "roboscope-source-01",
  "acceptedAt": "2026-08-31T21:04:00Z",
  "source": {
    "sourceRequestId": "srcreq_01J...",
    "sourceId": null,
    "registryId": null,
    "reference": "owner/repository",
    "normalizedReference": "owner/repository",
    "type": "custom",
    "overrideExisting": false,
    "state": "catalog_queued",
    "updatedAt": "2026-08-31T21:04:00Z"
  },
  "catalogWork": {
    "state": "queued",
    "workIds": ["work-v1-..."]
  }
}
```

## Optional patch-tracking read model

If SigmaScope exposes patch tracking rather than only equivalent GitHub links, both endpoints are read-only and require `patches:read`.

`GET /v1/patches` MAY support `state`, `limit` (1–100), and opaque `cursor` query parameters. A patch summary includes patch ID, state, target component, source/target branch descriptions, file/addition/deletion totals, commit SHA when present, linked run, bounded failure summary, and `updatedAt`.

`GET /v1/patches/{id}` adds immutable activity events. The ID is opaque and MUST NOT be interpreted as a path, branch, or URL.

Recommended states are `received`, `validated`, `applying`, `committed`, `failed`, `superseded`, and `unknown`.

When GitHub/ZipRunner remains authoritative, these are projections only. The API MUST NOT invent a commit, retry, deployment, review, or workflow result. Patch mutation endpoints are deliberately excluded from v1.

## Concurrency, rate limits, and restart safety

Mutation idempotency reservation and authoritative duplicate checks MUST be serialized so concurrent taps cannot create duplicate work. A server restart after durable acceptance MUST preserve enough idempotency and mutation state to return the original response on retry.

Recommended default limits are 60 operations-state reads/minute, 30 scan-nudge requests/hour, 20 source-create requests/hour, 60 patch reads/minute, and 20 auth exchanges/hour. `429` SHOULD include `Retry-After`. Replaying a stored idempotent response SHOULD NOT consume another mutation quota unit.

## Current SigmaScope integration constraints

The current SigmaScope scan queue is workflow-owned and uses deterministic plugin-first coverage. Operator nudges therefore enter as bounded intent and are reconciled into server-owned scan work; they do not rewrite the published queue from the client side.

The current durable orchestration model derives canonical work identities from server-controlled component, kind, bounded subject, and required revision. The API should reuse that principle: RoboScope supplies plugin/source intent, while the server derives any canonical work identity and never accepts a client-provided `workId` as authority.

Source provenance classes remain scheduling/registry metadata. Official or curated provenance MUST NOT be exposed as a security verdict.

## Minimum acceptance tests

A conforming implementation has automated coverage for at least:

1. missing auth returns `401`;
2. authenticated non-operator returns `403`;
3. every endpoint enforces its required scope;
4. mutations without `Idempotency-Key` are rejected;
5. same idempotency key + same body returns the original response and creates no duplicate work;
6. same idempotency key + different body returns `409`;
7. scan nudge rejects 0, more than 10, duplicate, unknown, inactive, non-integer, and boolean plugin IDs;
8. scan nudge never reports started/running before an authoritative lease exists;
9. equivalent existing scan work returns `already_queued`;
10. source normalization detects equivalent GitHub and configured alias forms;
11. source creation rejects forbidden schemes, credentials, fragments, and local/private targets;
12. existing source + `overrideExisting=false` returns `409`;
13. field validation returns `422` with no partial mutation;
14. source creation cannot supply workflow, branch, queue, command, or claim-token authority;
15. audit append failure makes mutation acceptance fail closed;
16. audit-chain verification detects event mutation or reordering;
17. operations polling preserves underlying `updatedAt`;
18. records older than 60 seconds are projected stale;
19. provenance/coverage never becomes a boolean safety verdict;
20. optional patch endpoints remain read-only and never claim GitHub/ZipRunner work that did not occur.

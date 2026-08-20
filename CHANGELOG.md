# Omega security services changelog

## 2.9.6 — Catalog / Sigmascope mutual exclusion

- Give catalog publication and the continuous Sigmascope worker the same GitHub Actions concurrency group.
- Catalog and Sigmascope can no longer execute simultaneously, including manual catalog runs.
- Keep `cancel-in-progress: false`: an already-running operation finishes and the other waits rather than being killed.
- Add a workflow regression contract for the shared lock.

## 2.9.4 — Evidence source-cache transport integrity

- Preserve an unchanged variant's published source-analysis cache descriptor and bytes when the disposable working database has no materialized cache row.
- Continue materializing source-analysis cache datasets for fresh successful variants whose derived files are not yet present in the candidate tree.
- Add a regression reproducing the prior 3-byte `[]` overwrite against a retained non-empty descriptor.
- Scanner rule/scoring semantics remain SigmaScope engine 2.9.0.

## 2.9.3 — Discord delivery compatibility

- Send the Discord HTTP API a valid `DiscordBot (...)` User-Agent instead of Python urllib's default identity, avoiding Cloudflare/API 403 rejection.
- Add an explicit `Accept: application/json` header and preserve `Content-Type: application/json`.
- Include a bounded Discord error response body in failures without logging webhook URLs or secrets.
- Add regression coverage for the exact isolated delivery request headers.
- No scanner, scoring, catalog, or Evidence semantics changed.

## 2.9.2 — Discord publication notifications

- Add isolated Discord notifications for daily catalog publication and SigmaScope Evidence v2 publication.
- Keep webhook credentials out of the notice-building process; delivery runs in a separate `discord-public` environment job.
- Add deterministic fixed voice-line pools: irritated security, wealthy catalog growth, happy Definitions updates, and cocky/satisfied evidence reviews.
- Add eight notification regression tests covering sanitisation, routing, revision comparisons, deterministic wording, and tone selection.
- Preserve the catalog migration retention guard and marketplace protocol v2 validation while merging the adapted notification workflow.
- No SigmaScope scanner decision/scoring semantics changed.

- Split repository-side catalog/security implementation from the Omega C# client branch.
- Keep the SigmaScope scanner engine at **2.9.0**; the branch split does not change scanner semantics by itself.
- Add explicit `tools/security/deltascope.py` developer entry point over the existing read-only evidence browser/auditor.
- Convert catalog, SigmaScope, source-submission and legacy-compaction workflows to reusable workflows owned by `sigmascope`.
- Require service workflows to explicitly check out `sigmascope` when invoked by thin default-branch callers.
- Keep DeltaScope manual/read-only and outside the production evidence publication path.

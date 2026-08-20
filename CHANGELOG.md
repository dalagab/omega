# Omega security services changelog

## 2.14.0 — Reviewed Omega Core YARA and bounded archive-member scanning

- Bump Omega Security Services / SigmaScope engine to **2.14.0** because artifact-analysis and secondary-evidence semantics change materially.
- Enable the first production Omega Core YARA set: 14 first-party compound rules across credential/exfiltration, execution/injection/security-tamper, persistence, and contextual anomaly classes.
- Keep broad primitives such as HTTP, P/Invoke, Discord URLs, filesystem access, `Process.Start`, PowerShell strings, obfuscation or entropy insufficient by themselves; YARA remains supplemental evidence only.
- Scan YARA against the exact downloaded artifact container plus a bounded generated view of ZIP members instead of only the outer archive.
- Bound YARA member materialization to 256 members, 16 MiB per member and 64 MiB total; reject unsafe/encrypted/suspicious-ratio members and skip large media/font resources.
- Attribute YARA matches back to the original archive member path, member SHA-256 and byte count without ever using the untrusted path for extraction.
- Add `omega.sigmascope.yara-scan-scope.v1` and advance new artifact scans to secondary-security Evidence contract **v3**.
- Fix source-only artifact replay so materialized Evidence-v2 workers preserve the exact artifact-bound secondary-security payload/contract instead of emitting a stale half-contract.
- Preserve historical contract-v2 secondary evidence during source-only reuse; old artifact evidence cannot be falsely upgraded to v3.
- Advance YARA policy/metadata to v2 with exact `reviewedRuleSha256`, reviewer, rule class and confidence; require metadata rule names to exactly match declarations and reject cross-file duplicate rule identifiers.
- Compile-check every enabled YARA file at the Definitions boundary and retain frozen executable identity verification in continuous workers.
- Make regression CI trigger on `security-definitions/**` and install real YARA before tests so rule-only changes are compile-checked.
- Hotfix the daily Catalog preflight and manual compaction workflows to install real YARA before their full repository regression suites; enabled Definitions fixtures intentionally compile-check production rules and therefore require the compiler at test time.
- Add an upstream review queue for YARA Forge/signature-base/embee-style rules without importing any third-party pack wholesale; future accepted rules require exact upstream provenance/license and independent local review.
- Preserve immutable ClamAV transport, artifact/source attribution, lifecycle/requeue, native PE, endpoint and component-summary contracts.
- Replace the continuous worker's hard one-item queue clamp with bounded multi-item processing: up to 20 queue work items per runner while preserving per-item work type, provenance, retry/backoff, source-followup and last-known-good failure retention.
- Reserve the last 300 seconds of the existing 3,300-second batch budget for advisory refresh, Evidence-v2 validation/audit and atomic publication so long scans do not consume the publication window.
- Expose batch diagnostics (`selectedCount`, selected items, budget stop state, invocation count, and aggregate per-plugin elapsed seconds) without persisting runtime timings into semantic Evidence-v2 or changing artifact/source analysis identities.
- Fix source-projection persistence exposed by the first 20-item batch: immutable normalized finding rows are now rebuilt from the final combined source+artifact finding set instead of artifact rows plus only direct source findings. This preserves newly derived endpoint/automation findings and keeps immutable scan counters reproducible.
- Keep the independent developer audit fail-closed; the failed 20-item batch published nothing after it detected five mirrored ActionTimelineReborn source projections with 21/10 recorded caution/informational counts but only 19/9 normalized rows.

## 2.13.0 — Native structural evidence, endpoint intelligence and component summaries

- Compatibility hotfix: validate pre-lifecycle Evidence-v2 plugin summaries using their historical lifecycle-contract-0 field set instead of recomputing them with lifecycle-contract-v1 fields. This repairs incremental startup against existing published snapshots without rewriting or deleting evidence.
- Keep lifecycle-aware production snapshots on contract v1; terminal/superseded validation remains fail-closed and unchanged.
- This is publication/validation compatibility only and does not change SigmaScope artifact/source scanning semantics or require an engine-version bump.
- Bump Omega Security Services / SigmaScope engine to **2.13.0** because artifact-analysis and Evidence-v2 transport semantics change materially.
- Advance the binary-classification contract to **v2**. PE classification now records bounded loader/security characteristics, COFF timestamp, entry-point/image metadata, section permissions/entropy and certificate-table presence without claiming Authenticode verification.
- Add bounded caution evidence for native PE sections marked both writable and executable; high entropy remains contextual metadata only and does not become a malware verdict.
- Expand static endpoint evidence to `omega.sigmascope.endpoint-evidence.v2` with explicit origin type, evidence confidence and concrete-destination semantics.
- Retain low-confidence URL strings from compiled binaries while filtering certificate/revocation infrastructure, source references and navigation/community literals out of concrete-destination findings.
- Preserve secret safety by stripping URL credentials/query/fragment and redacting Discord webhook/secret-like path components before evidence persistence.
- Add `omega.sigmascope.endpoint-summary.v1` with bounded host/classification/origin counts and explicit network-capability-with-undetermined-destination state.
- Add `omega.sigmascope.component-summary.v1` over the existing authoritative dependency graph, keeping NuGet/plugin/IPC/managed/native families separate.
- Correlate managed/native imports with bundled native libraries and Windows platform libraries; retain unresolved/runtime-resolved native dependencies explicitly.
- Mark direct compiled IL calls to P/Invoke targets in native component relationships as very-high-confidence static call evidence without claiming runtime execution.
- Carry bounded endpoint/component summaries through Evidence-v2 transport while retaining detailed normalized dependency/call datasets as the authoritative evidence.
- Bind component-summary and endpoint/native semantics into narrow artifact/source analysis revisions so stale analysis cannot be silently reused.
- Preserve 2.12 terminal lifecycle/typed requeue, 2.11 immutable ClamAV/reviewed-YARA and 2.10 artifact/source-attribution contracts unchanged.

## 2.12.0 — Variant lifecycle, event-driven requeueing and native binary classification

- Bump Omega Security Services / SigmaScope engine to **2.12.0** because Evidence-v2 lifecycle and artifact-analysis semantics change materially.
- Preserve inactive catalog variants as explicit `retired` terminal snapshots instead of deleting their descriptors and garbage-collecting their last immutable artifact analysis.
- Keep terminal variants out of `currentVariants` and out of scan-queue candidates, so historical evidence does not become normal client or worker state.
- Preserve the previous artifact descriptor as a `superseded` historical snapshot when an active variant ID moves to different artifact bytes. Source-only refreshes do not create fake artifact history.
- Add lifecycle contract v1 to Evidence-v2 indexes and fail-closed validation for active, retired and superseded descriptors, including immutable analysis hash/digest validation.
- Replace coarse artifact/source change labels with typed event reasons that declare their allowed work type and invalidated evidence layers.
- Distinguish artifact URL changes, artifact version changes, artifact-analysis semantic changes, advisory changes, source-candidate changes, source observations, source-analysis changes and retry work.
- Preserve the invariant that advisory-only work cannot cause artifact/source scans and source-only events cannot cause binary rescans.
- Add a bounded non-executing PE/ELF/Mach-O classifier. PE records architecture, bitness, role, managed/native status, subsystem, section metadata and bounded import tables.
- Feed native PE imports through the existing SigmaScope rule/capability engine, allowing concrete imported APIs to become high-confidence static evidence without loading the DLL/executable.
- Bind the binary-classifier implementation into `artifactAnalysisRevision`, so parser-semantic changes invalidate artifact-analysis cache identities.
- Retain the 2.11 immutable ClamAV/reviewed-YARA contracts and the 2.10 artifact/source-attribution contracts unchanged.

## 2.11.0 — Immutable ClamAV transport and reviewed YARA provenance

- Bump Omega Security Services / SigmaScope engine to **2.11.0** because secondary-engine execution identity and Evidence-v2 semantics now change materially.
- Add deterministic content-addressed large-definition asset tooling for ClamAV CVD/CLD databases; official databases no longer need to be committed to `catalog-data`.
- Freeze asset URL, SHA-256, byte count, per-database SHA-256/size, and exact `clamscan` executable identity at the daily Definitions boundary.
- Make continuous workers materialize only the exact frozen ClamAV asset. They never run FreshClam, and database/executable mismatches report ClamAV as unavailable instead of falling back to live/system definitions.
- Keep ClamAV supplemental: its availability and matches cannot alter SigmaScope severity or source-review coverage by themselves.
- Add `omega.sigmascope.yara-policy.v1` with fail-closed reviewed metadata sidecars for every YARA rule: rule names, status, provenance, license, review time, scope, false-positive expectation and notes.
- Require a frozen YARA executable identity whenever any rule is enabled; no production YARA rules are enabled in 2.11.0 yet.
- Preserve YARA rule provenance/license/scope/false-positive context into bounded Evidence-v2 match records.
- Advance the secondary-security Evidence contract to v2 for new artifact scans while retaining validation compatibility with legacy 2.10 contract-v1 evidence.
- Bind secondary asset transport, executable identities, policy and metadata into secondary/artifact analysis revisions so cache reuse remains truthful.
- Add dedicated large-asset, tamper, executable-mismatch and unreviewed-YARA regression coverage plus workflow contracts for the Definitions/worker split.

## 2.10.0 — Artifact identity and secondary-security foundation

- Bump the SigmaScope scanner engine to **2.10.0** for the first semantic scanner-model pass after the 2.9.x transport/stability releases.
- Bind new artifact analyses to an explicit `omega.sigmascope.artifact-identity.v1` contract containing SHA-256, package byte count, resolved artifact URL, catalog/artifact versions, and embedded manifest identity.
- Persist a stable `omega.manifest-observation.v1` identity for the exact catalog observation that selected the scanned artifact.
- Validate the 0/40/70/95/100 source-attribution ladder by recomputing it from provenance; hand-authored confidence/coverage values are rejected by the Evidence-v2 validation contract.
- Keep source-only follow-ups backward compatible: they may add current manifest/source attribution to legacy evidence without claiming the old artifact bytes were revalidated.
- Record exact artifact-pinned source commits when a manifest/artifact origin supplies a verified 40-hex commit; reserve 100% coverage for reproducible source-to-artifact proof.
- Add bounded local YARA and ClamAV adapters as **supplemental evidence only**. No plugin bytes are executed, no shell is used, output/time/match counts are bounded, and artifact SHA-256 is verified before secondary scanning.
- Freeze secondary-security definition descriptors into daily Definitions and bind their revision into `artifactAnalysisRevision`, so signature changes invalidate artifact-analysis cache identities.
- Keep secondary engines disabled when no frozen definitions exist. No production YARA rule set is enabled yet. ClamAV database transport remains intentionally disabled until an immutable large-signature mechanism exists rather than committing oversized databases to `catalog-data`.
- Pass `OMEGA_SECONDARY_SECURITY_ROOT` from the continuous worker to the frozen daily Definitions tree.
- Keep DeltaScope outside the production scanner decision/publication path and preserve last-known-good Evidence-v2 behavior.

## 2.9.8 — TONI notification language

- Keep SigmaScope neutral in Discord notices: the scanner reports findings and evidence; personality belongs to TONI.
- Replace the harsh verdict wording with the calmer invitation: `Review the findings if you want to know more.`
- Use factual notification titles such as `New security findings for <plugin>` and `Omega catalog updated`.
- Stop calling a publication the `daily catalog` in TONI messages; use `latest catalog snapshot` so extra manual/test runs read naturally.
- Refresh TONI's fixed deterministic voice pools while preserving the irritated-security, wealthy-catalog, happy-Definitions, and cocky-evidence personalities.
- No scanner, scoring, catalog, Evidence-v2, or Discord routing semantics changed.

## 2.9.7 — Frozen Definitions OSV audit accounting

- Pass the frozen daily `osv-advisories.json` directly into the independent developer audit.
- Verify the exact `queriedPackageVersionPairs` universe independently against the working NuGet dependency set.
- Keep count-only legacy coverage fail-closed: `0/N` queries still fails when no exact frozen query universe is supplied.
- Treat NuGet versions discovered after the daily Definitions freeze as an explicit warning (`osv.coverage.frozen_gap`) instead of a false failure; no live mid-day OSV lookup is introduced.
- Fail if the frozen advisory payload's declared query count disagrees with its exact package/version list, or if the working projection disagrees with the frozen query count.
- Scanner rule/scoring semantics remain SigmaScope engine 2.9.0.

## 2.9.6 — Catalog / Sigmascope mutual exclusion

- Give catalog publication and the continuous Sigmascope worker the same GitHub Actions concurrency group.
- Catalog and Sigmascope can no longer execute simultaneously, including manual catalog runs.
- Keep `cancel-in-progress: false`: an already-running operation finishes and the other waits rather than being killed.
- Add a workflow regression contract for the shared lock.

## 2.9.5 — TONI notification identity

- Discord publication notices now use exactly `TONI` as the visible webhook sender name.
- Message content, routing, sanitisation, retry behaviour, and scanner/catalog semantics are unchanged.

## Unreleased

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

# Internal compatibility policy

Omega/SigmaScope has one authoritative deployment: the state and workflows in the
`dalagab/omega` GitHub repository. Internal GitHub storage formats are implementation
details, not public compatibility contracts.

## Rule

**Only preserve compatibility when it protects a real current consumer, security
provenance, or an external input format. Do not retain compatibility code for retired
internal state merely because an earlier build produced it.**

The primary compatibility boundary is the client database and descriptor actually read
by the Omega plugin (`catalog-latest` / `omega-marketplace.sqlite.zip` and its current
catalog descriptor contract).

Security history is a separate concern. Retained Evidence-v2 lineage may require exact
historical interpretation until the authoritative data has been rewritten or migrated to
the current contract. That is provenance preservation, not a promise to support old
internal deployment formats forever.

External plugin/source formats are also not compatibility baggage: adapters for GitHub,
GitLab, Gitea/Forgejo, codeload URLs, PluginMaster variants, and dependency version
semantics are real acquisition/analysis functionality and remain supported when useful.

## Applied during Phase 4C HOTFIX6

The canonical JSON catalog changes from a monolithic identity document to bounded,
deterministic shards:

- internal catalog storage schema: `omega.catalog-json.v2`;
- logical catalog identity epoch remains `omega-catalog-identity-v1` because file layout
  is not a logical plugin/variant identity change;
- the client-facing canonical revision mapping remains `cat-json-v1-*` because that
  value participates in the current Omega marketplace descriptor contract;
- each identity shard targets 4 MiB and remains protected by the existing 16 MiB hard
  per-file limit;
- the normal catalog reader/materializer understands only the current sharded layout;
- `catalog_json_v1_seed.py` is a Phase-4-only converter for the one existing
  authoritative `catalog-data` predecessor. It preserves exact integer plugin/variant
  identities so current Evidence-v2 remains correctly keyed during cutover. It is not a
  supported compatibility format and should be deleted after the Phase-4 receipt.

## Compatibility-debt audit

### Remove immediately after the Phase-4 cutover receipt

1. **Phase-4 v1 catalog seed converter**
   - `tools/catalog/catalog_json_v1_seed.py`
   - the exact v1 predecessor branch in `.github/workflows/catalog-builder.yml`
   - Reason: after `catalog-data` is v2 there is no second deployment that can need it.

2. **Retained catalog-builder artifact bootstrap fallback**
   - `tools/catalog/stage_catalog_bootstrap.py`
   - related fallback test in `tools/tests/test_pipeline_handoff.py`
   - The code explicitly says the retained builder artifact exists only for the migration
     window. `catalog-latest` is already the real Omega-client distribution boundary.
   - Replace it with: download current `catalog-latest`, validate, or fail closed.

3. **Old marketplace summary-table validation path**
   - `tools/catalog/validate_marketplace_catalog.py`
   - Remove the `marketplace_security_current` branch after confirming the newly
     published `catalog-latest` uses the current `fresh-allowlist-v1` projection.
   - The validator should then validate exactly the database Omega is actually shipped.

4. **Manual legacy SQLite compaction lane**
   - `.github/workflows/catalog-compaction.yml`
   - `tools/catalog/compact_sqlite_catalog.py` and its migration-only tests if no longer
     required by an operator workflow.
   - Current production authority is Git-backed catalog state plus Evidence-v2; the
     compactor is already manual/non-publishing and is primarily retained migration
     machinery.

5. **Pre-orchestration OSV query-set reconstruction**
   - `tools/catalog/definitions_snapshot.py`
   - Production OSV lane results already carry the exact queried package/version set.
     Once Phase 4 is complete, a supplied OSV result missing that set should fail closed
     instead of reconstructing a historical caller shape.

### Remove once authoritative security data proves it no longer contains old forms

6. **Legacy age scheduler / ledger parameters in SigmaScope**
   - `tools/catalog/sigmascope.py::due_rows`
   - Production scheduling is owned by the typed persistent queue. Keep the old
     arguments only until all developer/test callers are moved to the queue contract.

7. **Legacy artifact-analysis revision synthesis**
   - `tools/catalog/sigmascope.py::_artifact_analysis_revision`
   - Remove `legacy:*` synthesis after an Evidence-v2 audit proves every retained current
     row needed by production carries the narrow `artifactAnalysisRevision` contract.

8. **Legacy scan-ledger / combined-row validation**
   - `tools/catalog/validate_security_catalog.py` and related old SQLite validation paths.
   - Remove after the authoritative current evidence no longer depends on those rows.
     Historical evidence may remain archived as data without keeping it executable as a
     current transport contract.

9. **Historical source-follow-up GitHub issue compatibility**
   - `tools/catalog/create_source_followup_issues.py`
   - Run one canonical issue reconciliation, close/consolidate old managed issues, then
     remove marker/key compatibility used only to recognize those historical issue bodies.

### Keep: these are not obsolete deployment compatibility

- `source_resolution.py` and `public_git_source.py` host/fetch fallbacks: real external
  source acquisition functionality.
- dependency/version compatibility logic in SigmaScope: a security/dependency analysis
  feature.
- `analysis_revision.py` semantic compatibility anchors: cache/invalidation semantics,
  not old deployment support.
- SRL legacy-baseline/parity projections until the Stigma-1 cutover is proven: migration
  correctness, not client compatibility.
- DeltaScope generic/forward rendering fallbacks: developer UX with no security authority.
- explicit Git history emergency recovery modes may remain as operator disaster recovery;
  they must stay outside ordinary production paths.

## Review checklist for future work

Before adding a compatibility/fallback path, answer these questions:

1. Does the current Omega plugin consume this exact contract?
2. Is it required to interpret retained security provenance correctly?
3. Is it an external ecosystem/source format we intentionally support?
4. Is it a deliberate disaster-recovery mechanism rather than ordinary execution?

If all four answers are **no**, replace the one authoritative internal state and delete the
old path instead of carrying both formats.

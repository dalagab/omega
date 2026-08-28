# Clean Security Baseline Reset

SigmaScope can deliberately restart plugin security coverage without rebuilding the
marketplace catalog or rediscovering sources.

The reset is **security-state only**. It keeps the current `catalog-data/catalog`,
Definitions, plugin/variant/source identities, scraped website/presentation data,
source observations, frozen advisories, and frozen reputation/threat-intelligence
inputs. Existing Security Evidence v2 remains recoverable in Git history as the parent
of the reset commit.

The manual `Omega SigmaScope · reset security baseline` workflow:

1. materializes the current catalog into a disposable SQLite database;
2. deletes only `plugin_security_*` rows and security-specific metadata in that copy;
3. emits and intrinsically validates a zero-result Security Evidence v2 snapshot;
4. resets Deep Scan state to an empty queue;
5. rebuilds the immutable SigmaScope queue from the unchanged current catalog and
   Definitions, producing first-scan coverage work;
6. republishes `catalog-data` with byte-identical catalog/Definitions inputs and only
   the refreshed queue;
7. republishes the normal Omega customer database so old security conclusions are no
   longer exposed; and
8. queues the ordinary bounded SigmaScope worker to refill coverage.

No wire/schema migration is introduced: Security Evidence remains v2, the scan queue
remains v2, and the Omega customer database contract is unchanged.

The former Phase-4 migration/shadow/authorization workloads are archived under
`.github/retired-workflows/phase4/` and are no longer GitHub Actions workloads. The
exact queue-key parallel result worker remains active for the production refill path.
Workflow-only Phase-4 tests are archived under `tools/retired-tests/phase4/`.

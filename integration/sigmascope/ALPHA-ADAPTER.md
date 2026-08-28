# SigmaScope Alpha calibration adapter

Add exactly one reusable workflow on the `sigmascope` branch, for example `.github/workflows/sigmascope-alpha.yml`.

It accepts one run-bound Alpha artifact plus:

* `alpha_test_id`
* `alpha_registry_revision`
* `alpha_corpus_commit`
* exact artifact SHA-256

The adapter must run the same frozen static analyzer/rule projection used by production, but in **non-publishing calibration mode**. It must not create a catalog variant, mutate Security Evidence v2, enqueue production deep scans, or modify client security state.

Output one artifact containing the independently observed finding rows and engine revisions. The Alpha result adapter then names those rows `ALPHA:<production-finding-id>` and compares them with registry expectations.

Do not create test-only versions of `compound.network-execute` or `compound.credential-network`; the purpose is to test those reviewed production rules themselves.

A useful implementation shape is a small `alpha_scan_adapter.py` around the existing artifact-analysis entry point, not a second scanner. If an arbitrary-artifact entry point is not yet exposed cleanly, add that narrow library function first and make both production and Alpha call it.

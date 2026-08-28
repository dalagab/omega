# Rift Alpha suite orchestration

Keep one Alpha suite workflow on the Rift/control branch. It has a free-form `test_id` input; the selectable user experience should come from DeltaScope reading the registry, because GitHub `workflow_dispatch` choice lists are static and would otherwise require editing workflow YAML every time a test is added.

Flow:

1. checkout Rift runtime;
2. checkout protected `alpha` corpus at a concrete commit;
3. validate registry and source safety contract;
4. resolve `test_id` to project + engines;
5. build a non-installable DLL-only subject and hash it;
6. call SigmaScope Alpha adapter if requested;
7. call Rift only for `sandbox-runtime` tests;
8. build one `omega.alpha.scan-result.v1` result;
9. update the fixed `security-alpha-evidence` branch;
10. upload the same result as a normal Actions artifact.

The Alpha suite itself owns no security verdict authority. It coordinates independent engines and records calibration success/failure.

# Omega security services changelog

## Unreleased

- Split repository-side catalog/security implementation from the Omega C# client branch.
- Keep SigmaScope at **2.9.0**; the split does not change scanner semantics by itself.
- Add explicit `tools/security/deltascope.py` developer entry point over the existing read-only evidence browser/auditor.
- Convert catalog, SigmaScope, source-submission and legacy-compaction workflows to reusable workflows owned by `sigmascope`.
- Require service workflows to explicitly check out `sigmascope` when invoked by thin default-branch callers.
- Keep DeltaScope manual/read-only and outside the production evidence publication path.

# GitHub SigmaScope rule-candidate workflow

Status: implemented on the unreleased 2.15 development line. This workflow does **not** enable production SRL projection.

## Trust boundary

DeltaScope Rule Lab remains local/read-only and has no promotion endpoint. Its final handoff is browser-only: it may construct a pre-filled GitHub Issue Form URL, but it never submits the issue or performs a GitHub API write. GitHub issue YAML and fixture text are treated only as inert bounded data. `tools/security/rule_candidate.py` performs parsing, SRL compilation, fixture execution, Definition Pack collision checks, URL-prefill construction, and reviewed-pack materialization; it performs no GitHub network/git/PR operation and cannot decide who is authorized.

The canonical reusable workflow is `.github/workflows/rule-candidates.yml` on `sigmascope`:

1. `validate` checks out trusted `sigmascope` source with `contents: read`, re-fetches the issue, validates candidate YAML plus positive/negative fixtures, and comments diagnostics. It cannot write repository contents.
2. `promote` has repository-write capability but first resolves `github.actor` through GitHub's repository collaborator-permission API. Only base `write`/`admin` is accepted (`maintain` resolves to base `write`).
3. Only after authorization does promotion check out `sigmascope`, re-fetch the issue, and revalidate/materialize from scratch.
4. Candidate-declared `status`, `author`, reviewer-like text, issue author identity, or a previous validator result never authorizes promotion. The source-controlled materialized copy is stamped `reviewed` only by the authorized promotion action and records the verified GitHub actor plus issue-body SHA-256.
5. Promotion creates a new `reviewed` Definition Pack directory only. Existing pack IDs cannot be overwritten and cross-pack rule/fact collisions fail closed.
6. The workflow pushes a dedicated candidate branch and opens a normal PR against `sigmascope`. It never auto-merges.
7. Normal regression CI, required review/branch protection, and the later Daily Catalog/Definitions freeze are separate gates.

Do not add `pull_request_target` execution of candidate-controlled content.

## Candidate issue fields

`.github/ISSUE_TEMPLATE/sigmascope-rule-candidate.yml` requires:

- candidate pack ID/title;
- SRL rule/ruleset YAML;
- one or more positive fixtures that collectively exercise every candidate rule;
- one or more negative fixtures that match none of the candidate rules;
- rationale;
- false-positive expectations;
- external provenance/source;
- license.

Fixture text may be a single `omega.sigmascope.rule-fixture.v1` mapping or a YAML list of fixture mappings. YAML anchors, aliases, explicit tags, duplicate keys, unsupported observations, path-like pack IDs, failing fixtures, existing-pack overwrite, and duplicate rule/fact identities are rejected.

## Default-branch caller

GitHub issue/comment events are evaluated from the default branch. The `main` branch therefore needs a thin trusted caller that invokes the reusable workflow on `@sigmascope`. A reference caller is included at `docs/workflow-callers/rule-candidates-main.yml` for the companion `main` overlay. The Issue Form itself must also exist on the default branch; `docs/workflow-callers/sigmascope-rule-candidate-main.yml` is an exact regression-checked reference copy of `.github/ISSUE_TEMPLATE/sigmascope-rule-candidate.yml`.

The caller validates `SigmaScope rule candidate:` issues on open/edit/reopen and invokes promotion only for a `/promote-sigmascope-rule` issue comment. The reusable workflow still performs the decisive repository-permission check; the command itself is not authority.

## DeltaScope pre-filled issue handoff

DeltaScope 3.7 exposes `Propose on GitHub` in Rule Lab. The local endpoint `/api/rule-lab/proposal` only validates inert candidate data and returns a GitHub `issues/new` URL; it has `mutationAuthority=none`, `githubApiWrite=false`, and `repositoryCredentialsRequired=false`. The URL uses the canonical Issue Form element IDs (`candidate-pack-id`, `candidate-pack-title`, `candidate-rule-yaml`, positive/negative fixture fields, rationale, false-positive expectations, provenance and license) as query parameters.

The complete URL is limited to 7,500 bytes. Oversized proposals fall back deterministically to metadata, identity, or template-only prefills and tell the operator exactly which fields require manual paste. The Rule Lab can also export a deterministic GitHub-ready ZIP containing `candidate.yaml`, `positive-fixture.yaml` and `negative-fixture.yaml`. No fallback path submits data automatically.

Local proposal validation intentionally does **not** check current repository pack-name collisions because DeltaScope is not repository authority. The GitHub validator performs the authoritative collision/root validation from the freshly checked-out repository before any promotion can proceed.

## Production boundary

A merged reviewed pack is source data only. It does not directly write Evidence-v2 or queue/catalog state, does not change production scanner code, and does not enable SRL production projection. The next deliberate Daily Catalog/Definitions freeze compiles the source-controlled pack fail-closed. Production migration remains gated on compatible 2.15 corpus replay and explicit cutover review.

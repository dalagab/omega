# GitHub Workflow Center

DeltaScope's **Operations → GitHub Workflows** page is a local control-plane view over GitHub Actions. It is operational tooling, not Omega security authority.

## What the page shows

The Workflow Center projects the acquired GitHub workflow inventory into operational families such as security scanning, orchestration, catalog/discovery, intelligence, rules, verification and Rift. Each workflow shows its latest observed state, last branch/run, purpose, running count, recent failure signal and whether detailed run data has been acquired.

The Python projection owns this normalization. The browser only renders the projection and sends explicit operator actions back to the local DeltaScope API.

## Acquisition model

There are two intentionally separate acquisition levels:

1. **GitHub snapshot refresh** acquires the repository workflow inventory and broad recent Actions activity. It is controlled from Data sources or the Workflow Center refresh button.
2. **Acquire details** fetches one selected workflow's YAML definition plus a bounded run history, jobs, steps, artifacts and newest log previews.

Selecting a workflow, changing pages, opening a run or expanding a job performs no GitHub request. DeltaScope keeps the acquired local snapshot until you explicitly refresh/reacquire.

This keeps the Operations UI responsive and prevents page navigation from turning into a GitHub polling loop.

## Dispatch

After **Acquire details**, DeltaScope reads the selected ref's real `workflow_dispatch` declaration and renders its declared inputs. It does not invent parameters.

Dispatch requires locally configured GitHub workflow access and the literal confirmation `DISPATCH`.

For workflows that declare `internal_names`, the plugin-link helper can resolve a GitHub repository/release/file URL against the already-loaded Omega catalog and populate the existing scanner contract. An unknown repository is rejected rather than sent around the catalog contract.

## Run controls

Known acquired runs can expose bounded GitHub controls when authenticated access is configured:

- active run → `CANCEL`
- completed run → `RERUN`
- failed run → `RERUN` for all jobs or failed jobs only

The run ID must already exist in DeltaScope's acquired GitHub snapshot. Arbitrary run IDs are not accepted.

After GitHub accepts an action, DeltaScope deliberately keeps the old local snapshot. Reacquire the selected workflow or refresh GitHub when you want to observe the new state.

## Authority boundary

Workflow Center actions are **GitHub Actions mutations**, not security-state mutations. They cannot directly:

- change a finding or severity;
- edit Evidence-v2;
- change frozen Definitions or Stigma-1 rules;
- mark a plugin safe;
- directly mutate the SigmaScope queue outside the workflow's established server-side contract.

Any security-state change still has to occur through the workflow's normal validated publication contract.

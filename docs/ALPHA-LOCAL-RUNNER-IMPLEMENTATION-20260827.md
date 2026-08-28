# Alpha local runner integration note — 2026-08-27

Production Rift remains unchanged as the real-plugin execution service. Local execution is provided only by the separate Rift Alpha binary from the `alpha` branch.

Rift now documents/accepts the dedicated Alpha contract domain:

- `omega.rift.alpha-execution-request.v1`
- `omega.rift.alpha-run.v1`

The local Alpha result is non-authoritative (`authority=local-alpha`, `published=false`). Trusted CI can later compare its offensive report and Rift observations against independent SigmaScope/SRL/Stigma-1 findings and publish only into the separate Alpha evidence lane.

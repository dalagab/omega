# DeltaScope rule workbench

The Rules workspace is an authoring and investigation environment around one shared Stigma-1/SRL implementation.

## System Rules

Repository/frozen rule source is visible for inspection and reuse. System Rules are read-only in DeltaScope.

## My Rules

My Rules are versioned local files stored under the configured DeltaScope rule home. They are the only intentional local mutation surface in the rule workbench.

Local rules have no production authority.

## Editor surfaces

- **YAML** — direct SRL source editor with validation/formatting/intelligence.
- **Visual** — node/edge representation for selectors, boolean/count conditions and outputs.
- **Explain / Test** — dry-run, replay, fixtures and candidate proposal tools.

The Rule Library can be collapsed so the editor and rule context panels can use the full workspace.

## Data and security boundary

The workbench reads published evidence, registered observation schemas and repository Definitions. It does not expose arbitrary code execution or a production write-back endpoint.

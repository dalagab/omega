# DeltaScope consumer SDK

This directory is the bundled, non-authoritative compatibility layer used by the local
DeltaScope workbench. It contains deterministic SRL parsing/evaluation and stable contract
readers only. It does **not** contain the SigmaScope scanner, acquisition workers,
publication code, Evidence-v2 writers, workflow credentials, or repository mutation code.

At runtime the SDK may be bound to hash-verified **data** registries downloaded by
DeltaScope (`component-registry`, `collector-registry`, and `capability-registry`). No
Python or other executable code is loaded from the network.

# SigmaScope / DeltaScope security-service boundary

SigmaScope is the deterministic production static scanner. It may fetch public plugin artifacts and source material under strict limits, but it never loads or executes the scanned plugin. Candidate Evidence v2 is staged, validated, independently audited, and published fail-closed.

DeltaScope is a developer-only consumer of already-generated evidence. It is read-only by design and must not publish catalog state, Definitions, scanner queues, or Security Evidence v2.

A SigmaScope implementation/rule change changes the frozen worker/scanner revision on `catalog-data`; it does **not** require an Omega C# version bump. A client bump is needed only when the client-side contract or presentation changes.

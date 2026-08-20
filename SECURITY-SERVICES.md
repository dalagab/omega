# SigmaScope / DeltaScope security-service boundary

SigmaScope is the deterministic production static scanner. It may fetch public plugin artifacts and source material under strict limits, but it never loads or executes the scanned plugin. Candidate Evidence v2 is staged, validated, independently audited, and published fail-closed.

DeltaScope is a developer-only consumer of already-generated evidence. It is read-only by design and must not publish catalog state, Definitions, scanner queues, or Security Evidence v2.

DeltaScope 2.14 browser support follows the published evidence contracts rather than maintaining a competing security model. It can browse lifecycle history, artifact-analysis manifests and their declared datasets, queue/revision state, artifact/manifest/source attribution evidence, endpoint/component summaries, native relationships and secondary-engine evidence. Online browsing remains lazy for large immutable forensic shards. DeltaScope labels endpoint/native/YARA/ClamAV material according to SigmaScope semantics (static/supplemental evidence, not runtime intent or an alternate verdict) and never mutates the evidence it displays.

A SigmaScope implementation/rule change changes the frozen worker/scanner revision on `catalog-data`; it does **not** require an Omega C# version bump. A client bump is needed only when the client-side contract or presentation changes.

## Evidence lifecycle and queue boundary

SigmaScope 2.12 treats variant state as evidence rather than as a reason to erase evidence. Active catalog variants remain the only entries in `currentVariants` and the only normal scan candidates. When a variant becomes inactive or disappears, its current descriptor is converted into a terminal `retired` snapshot with `rescanEligible = false`; its immutable artifact analysis remains referenced and validated. If the same active variant ID later changes artifact identity, the prior artifact descriptor is archived as a `superseded` historical snapshot. Mutable derived/source projection data is not retained in terminal snapshots, and source-only rescans never create an artificial superseded artifact.

The queue is event-driven. Every reason has a contract declaring its work type (`artifact`, `source`, or `advisory`), invalidated evidence layer and event identity. Artifact URL/version or artifact-analysis semantic changes may request artifact work; source-candidate/observation/analysis events request source work; advisory changes request advisory projection only. This boundary is fail-closed and intentionally prevents broad `changed` reasons from accidentally escalating work. Retired variants are never reintroduced as queue candidates merely because historical evidence exists.

## Native binary intelligence

SigmaScope 2.12 adds a bounded, non-executing binary classifier for PE, ELF and Mach-O content. PE parsing identifies machine architecture, 32/64-bit form, executable/library role, managed-vs-native status, subsystem, bounded section metadata and bounded import tables. Native PE library/function imports are projected into SigmaScope's existing static rule and permission evidence, allowing exact APIs to strengthen capability findings without executing or dynamically loading the plugin.

ELF and Mach-O classification currently records structural identity/role for later native-analysis work; it does not claim equivalent import/API coverage yet. Parser limits are explicit, malformed binaries fail safely, and classifier source participates in `artifactAnalysisRevision`.

Binary-classification contract v2 additionally records PE loader mitigations, entry/image metadata, section permissions and bounded entropy, plus certificate-table presence. Certificate presence is explicitly marked `verified = false`; SigmaScope does not perform Authenticode chain verification in this pass. Writable+executable native PE sections become bounded caution evidence. Entropy is retained only as context because packed/compressed resources are not themselves malicious.

## Endpoint intelligence

SigmaScope 2.13 uses `omega.sigmascope.endpoint-evidence.v2` to keep network capability separate from destination evidence. Static HTTP(S) literals record an origin type (`artifact-config`, `source-code`, `artifact-text`, `managed-metadata-string` or low-confidence `artifact-binary-string`), confidence, classification and whether the literal is eligible to count as concrete destination evidence. Source/repository references, Discord/community navigation, Lodestone links and certificate/revocation/timestamp infrastructure remain useful forensic literals but are not presented as network destinations.

Endpoint persistence is secret-conscious: credentials, query strings and fragments are removed; Discord webhook tokens and long secret-like path components are redacted. The endpoint summary is bounded and derived. It may say that network capability exists while destinations remain undetermined; that state is preferable to inventing intent from strings. No endpoint classifier performs live DNS, reputation or connectivity checks in the worker.

## Dependency/component presentation boundary

The normalized dependency tables remain authoritative for exact rows, versions, advisory matching, IPC provider resolution, source/artifact comparison and drift. `omega.sigmascope.component-summary.v1` is only a compact derived projection for evidence/client presentation. It keeps NuGet, managed assemblies, native libraries, plugins and IPC relationships separate. Native relationships distinguish exact bundled-library matches, known Windows platform libraries and unresolved/runtime-resolved libraries. A compiled IL call site that directly targets a P/Invoke mapping raises static relationship confidence but never proves that runtime control flow reaches the call.

## Secondary security engines

SigmaScope keeps YARA and ClamAV as **secondary evidence feeds**, never an alternate verdict system. Their matches, availability, engine identity and definition revisions are retained as evidence, while SigmaScope's own artifact/capability findings, severity model and source review coverage remain authoritative.

### ClamAV

Large official ClamAV databases no longer need to live in `catalog-data`. At the daily Definitions boundary the workflow may run FreshClam, collect the resulting CVD/CLD database files, and package them into a deterministic content-addressed ZIP asset on the dedicated `sigmascope-definitions` release. Frozen Definitions record the asset URL, SHA-256, exact byte count, each database hash/size, and the exact `clamscan` executable SHA-256/size/version observed at the same boundary.

Continuous workers **never run FreshClam**. They download only the exact frozen asset, enforce the frozen total byte count, verify the asset SHA-256, allow only the declared archive members, verify every extracted database, and then verify the local `clamscan` executable identity before scanning. A download/materialization failure or executable mismatch leaves ClamAV unavailable for that scan; it does not fall back to system databases or mutable live definitions and it does not block SigmaScope's primary static analysis.

If FreshClam cannot produce a new database at the daily boundary, the catalog workflow attempts to retain the previous frozen content-addressed ClamAV descriptor. If no prior frozen descriptor exists, ClamAV remains disabled rather than inventing an unfrozen input.

### YARA

SigmaScope 2.14 enables the first reviewed production YARA set. Rules remain small enough to live inside frozen Definitions and are governed by `omega.sigmascope.yara-policy.v2`. Every rule file has a same-name `omega.sigmascope.yara-rule-metadata.v2` sidecar containing exact rule names, enabled state, provenance, license, reviewer, review timestamp, **SHA-256 of the exact reviewed rule bytes**, rule class, confidence, false-positive expectation, scope and review notes. The Definitions build fails closed if the sidecar hash differs, if declarations differ from metadata, if names collide across files, or if an enabled file does not compile with the installed YARA executable. Enabled rules also require a frozen executable identity.

The initial Omega Core set contains 14 first-party compound rules across four files. High-signal classes include credential/token access plus exfiltration, classic/NtCreateThreadEx process injection, encoded PowerShell download/execute, Defender tamper commands, base64 PE loading, AMSI memory patching, and Run-key/scheduled-task/service persistence. Anti-debug/anti-VM clusters are explicitly anomaly-class evidence. Broad individual strings such as `HttpClient`, `Process.Start`, P/Invoke, Discord URLs or obfuscation are intentionally insufficient to match.

For ZIP artifacts, YARA no longer sees only the outer container. SigmaScope materializes a bounded generated view of code/config/payload-like members: at most 256 members, 16 MiB each and 64 MiB total, with encrypted/unsafe/suspicious-ratio members rejected and large media/font resources skipped. The original member path is retained only as evidence metadata; it is never used as an extraction path. A YARA match can therefore say which archive member matched, including that member's SHA-256 and byte count. `omega.sigmascope.yara-scan-scope.v1` records target counts, bytes, truncation and skip reasons.

Third-party packs are never imported automatically. `security-definitions/yara/UPSTREAM_REVIEW_QUEUE.md` identifies candidate upstreams such as YARA Forge, signature-base and embee-research for **rule-by-rule** review. Any accepted rule must retain exact upstream provenance/license and pass the same local review/hash contract.

### Shared invariants

Secondary engines remain bound to the exact downloaded artifact SHA-256. ClamAV receives the exact package container; YARA receives that container plus the bounded member view described above. Adapters do not use a shell, do not update signatures, and use bounded execution time/output. Secondary definition, rule-policy, member-scan or executable-identity changes remain bound into `artifactAnalysisRevision`, so stale artifact evidence cannot be silently reused. Historical secondary contract-v2 evidence is preserved as v2; source-only reuse cannot falsely upgrade it to v3. Failing open to live `freshclam`, system databases, unreviewed YARA rules or unpinned enabled engine executables is not acceptable.

## DeltaScope / TONI boundary

TONI is a deterministic presentation layer inside DeltaScope only. It may summarize counts and already-published evidence for the operator, but it is not permitted to scan artifacts, change SigmaScope severity/coverage, alter queue state, write Evidence-v2, or participate in publication decisions. The browser remains read-only.


## DeltaScope researcher boundary

DeltaScope 3.0 is a developer-only, read-only research surface over published evidence. Its triage priority/signals are deterministic presentation hints over existing SigmaScope evidence and have **no authority** over scanner severity, coverage, queueing, Definitions, Evidence-v2 publication or Omega client decisions. Online snapshot-race recovery refreshes the published atomic root/index and retries strict SHA-verified reads; it never accepts mismatched bytes.


### Coverage-first queue / DeltaScope coverage visibility

SigmaScope prioritizes never-scanned active variants before revisiting variants that already have published evidence. DeltaScope surfaces this as `Never scanned` coverage and makes `SOURCE CODE` versus `ARTIFACT ONLY` explicit; source availability is not the same thing as source→artifact verification. Online Evidence-v2 cache filenames are short content-derived keys to remain safe on long Windows cache prefixes.

# Detection systems

Omega has several detection layers because different kinds of evidence require different mechanisms. The preferred extension point depends on what you are trying to detect.

## Detection layers

### Static artifact observations

SigmaScope inspects the installable package, managed assemblies and native binaries. This layer should collect low-level facts that can be retained and reused:

- managed assembly references and calls;
- P/Invoke targets;
- native imports;
- filesystem/process/network APIs;
- endpoints and URL literals;
- dependency/component identities;
- IPC relationships;
- package-safety conditions;
- source and artifact provenance.

If the new security question requires a fact that the platform does not retain today, **add an observation here first**.

### Stigma-1 / SRL rules

Use a rule when the required observations already exist and the security logic can be expressed deterministically over registered collections/facts.

Good rule candidates include:

- a suspicious capability combination;
- a specific endpoint class plus another fact;
- source/provenance inconsistencies;
- a known managed-call pattern;
- a condition that should request deeper static analysis.

Rules are preferable to hard-coded scanner findings when the logic is data-driven, reviewable and expressible in SRL.

### YARA

Use YARA for reviewed byte/string patterns that make sense at file/artifact level. YARA results remain supplemental evidence and should retain the exact rule provenance.

### ClamAV

ClamAV provides conventional malware-signature evidence using a frozen database asset. It is a secondary engine, not a replacement for Omega’s own static analysis.

### OSV advisory intelligence

OSV is used for exact observed NuGet package/version pairs. Advisory results are dependency intelligence; they should not be generalized to packages/versions that were not queried.

### Deep Scan

Use Deep Scan when a normal scan already produced enough evidence to justify a more expensive bounded profile. A rule can request a code-owned analysis profile; the rule cannot provide arbitrary executable instructions.


## Where detection logic lives

| Layer | Main source | Reviewed/frozen data | Useful tests |
| --- | --- | --- | --- |
| Artifact/static observation | `tools/catalog/sigmascope.py` | scanner bundle frozen by the security workflow | `tools/tests/test_local_sigmascope_v2.py`, `tools/tests/test_production_sigmascope_v2_pipeline.py` |
| Observation publication | `tools/security/observation_projection.py`, `tools/security/security_evidence_v2.py` | Evidence-v2 observation contract | `tools/tests/test_security_evidence_v2.py` |
| Stigma-1 / SRL | `tools/security/srl.py` | `security-definitions/packs/*/rules/*.yaml` and fixtures | `tools/tests/test_definition_packs.py`, rule/replay tests |
| Capability vocabulary | scanner/profile/rule mappings | `security-definitions/capabilities/registry.json` | capability/profile normalization tests |
| YARA | secondary scanner integration | `security-definitions/yara/*.yar` + metadata + policy | `tools/tests/test_secondary_definitions.py` |
| ClamAV | secondary scanner integration | `security-definitions/clamav/` transport/metadata | secondary-definition tests |
| OSV advisory intelligence | `tools/catalog/collect_public_advisories.py` | advisory snapshot inside frozen Definitions | collector/Definitions tests |
| Deep Scan | `tools/security/deep_scan_worker.py`, `tools/security/deep_scan_contract.py` | code-owned profile set | deep-scan contract/queue/worker tests |

A production change normally touches more than one row only when a **new primitive observation** is required. For example, a new managed-call detector may require scanner extraction, Evidence-v2 serialization, SRL registration and a rule. A correlation over fields that are already complete should usually require only the rule/fixture path.

## How to add a new detection

### 1. State the security question precisely

Write the question as an observable claim, for example:

> Does this artifact contain a reachable call to an API that writes outside the plugin’s expected data area?

Avoid starting with a severity label. First decide what evidence would prove or disprove the condition.

### 2. Check the retained observation model

Look in the rule data reference and Evidence-v2 observation contract. If the required primitive is already retained completely, prefer a rule or classification definition.

If the primitive is missing, add a new scanner observation dataset or extend an existing registered collection. Include:

- a stable collection name;
- bounded fields;
- completeness semantics;
- provenance/source of the observation;
- serialization into Evidence-v2;
- tests for positive, negative and malformed inputs.

### 3. Choose the interpretation layer

- Existing observations + deterministic logic → **Stigma-1 rule**
- File signature/pattern → **YARA**
- Dependency vulnerability → **OSV/Definitions**
- New primitive evidence → **SigmaScope scanner observation**
- Expensive follow-up justified by current evidence → **analysisRequest / Deep Scan**

### 4. Define severity independently from coverage

Severity should describe the security significance of the evidence. Coverage should describe how complete the analysis was. Do not use missing source, missing secondary engines or bounded transport as a reason to pretend a risky observation is low severity.

### 5. Add tests and fixtures

Every new detection should have:

- a clear positive case;
- a near-miss negative case;
- edge cases that prevent obvious false positives;
- expected output identity/severity;
- replay or serialization tests if the observation is published.

### 6. Preserve explanation

A finding should be able to answer:

- what was observed;
- where it was observed;
- why the condition matters;
- what the detection does **not** prove;
- which rule/Definitions revision produced the conclusion.

### 7. Review and freeze

Source-controlled detector changes should be reviewed before entering frozen Definitions or the production scanner bundle. A local DeltaScope rule is not production policy.

## Avoiding overclaiming

Static analysis can show capability and code relationships. Unless the platform has runtime evidence, avoid language such as “the plugin sent”, “the plugin executed” or “the plugin stole”. Prefer “the artifact contains”, “a call is present”, “the code can”, or “the retained observations match”.

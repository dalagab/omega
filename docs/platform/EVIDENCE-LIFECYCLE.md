# Evidence lifecycle and authority

Security Evidence v2 is designed so that current conclusions can change without destroying the evidence that supported earlier conclusions.

## Current variant

A plugin can have multiple retained versions. One active variant is the current marketplace/security subject. Current dashboard totals and severity counts are derived from the current active variant and its current scan only.

## Immutable analysis

An artifact analysis is keyed by immutable identities such as the artifact SHA-256 and analysis revision. If the same exact artifact is encountered again under equivalent analysis inputs, the retained analysis can be reused rather than pretending it is new evidence.

## Historical snapshots

Older plugin versions and superseded analyses remain useful for:

- identifying when a behavior appeared or disappeared;
- comparing endpoint, capability and dependency changes;
- researching previously risky versions;
- understanding source/artifact lineage;
- reproducing an old finding.

Historical snapshots **do not contribute to current HIGH/CRITICAL totals** unless that historical version is also the current active variant.

## Observations versus projections

An observation is retained evidence such as a managed call, endpoint, native import or dependency. A projection is a conclusion derived from observations: a capability, finding, relationship or rule output.

This split enables rule-only re-evaluation when the retained observation set is complete enough. If a new rule requires data that an older analysis did not retain completely, DeltaScope should report that re-analysis is required rather than treating missing data as a negative result.

## Integrity

Evidence-v2 descriptors include hashes for their referenced objects. DeltaScope verifies those hashes before consuming a shard. When reading a moving publication branch, DeltaScope can recover from a branch/CDN race by pinning the current Git commit and retrying the exact immutable snapshot; it never accepts mismatched bytes simply to make the UI load.

## Source and artifact evidence

Source attribution has several possible strengths:

1. no public source known;
2. likely repository identified;
3. a specific source revision/ref was selected;
4. source and artifact metadata are consistent;
5. source-to-artifact correspondence is reproducibly verified.

DeltaScope should show the actual level achieved. It should not collapse all of these states into “source available”.

## Secondary engines

YARA, ClamAV and advisory intelligence are independent inputs. Their status is retained alongside the scan so an investigator can tell the difference between:

- no matches;
- engine unavailable;
- engine not run;
- engine ran with matches;
- coverage incomplete.

## Reprojection

A deterministic rule may be replayed over retained observations when the observation contract says those inputs are complete enough. Reprojection must preserve the exact rule/Definitions provenance used to create the conclusion.

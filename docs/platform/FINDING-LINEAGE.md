# Finding lineage

Finding lineage answers three investigator questions in this order:

1. **What was found?** — the current finding and the specific retained evidence rows that participated in it.
2. **Why was it found?** — the frozen rule/selector evaluation and the result of every condition DeltaScope can replay.
3. **Why this severity?** — the rule's explicit severity decision plus retained counter-evidence or negative context.

The older producer → collection → rule → finding → publication graph still exists, but it is supporting system provenance rather than the primary explanation.

## Triggering evidence, not collection size

A collection name and row count are not themselves finding lineage. When exact selector replay is available, DeltaScope promotes the selector's retained `evidenceRows` into **Triggering evidence** and keeps their original collection and row identity.

For example, instead of only showing:

```text
managedCallSites · 2,500 rows
```

lineage can show the small set of rows that actually participated in the finding:

```text
metadata · metadata:KamiToolKit.dll:Dalamud.Hooking
metadata · metadata:KamiToolKit.dll:HookFromAddress
il       · KamiToolKit.NativeAddon.InitializeCloseCallback+0x2b
```

For older/static findings, DeltaScope first tries to link the finding to the frozen supporting primitive rule and replay it over retained observations. It can additionally map exact published finding-evidence strings back to retained rows. If that mapping is not possible, the item is explicitly labelled **finding evidence only**; DeltaScope does not invent a retained-row match.

**Inspect matched rows** opens the collection contract with only the rows mapped into the current lineage. It does not make an investigator sift through the whole collection just to rediscover the evidence that triggered the finding.

## Rule evaluation trace

A rule ID is a label; the evaluation trace explains the decision.

The trace shows, where frozen Definitions and retained observations permit it:

- rule ID, pack and rule revision;
- rule kind/status and published scope;
- the frozen boolean condition;
- every contributing selector, including selectors in upstream fact-producing rules;
- whether a selector is required, an alternative, an exclusion, or context;
- collection/fact input;
- predicates;
- match count / matched facts;
- resolved result;
- the final rule decision.

For a correlation rule, this means the trace does not stop at “required fact matched.” It also shows the contributing observation rule that produced that fact and the concrete row(s) that satisfied it.

For a legacy/static finding, a current frozen primitive rule may be shown as **supporting frozen rule/fact** when its emitted fact corresponds to the published finding identity. That is useful provenance, but DeltaScope does not falsely claim that a newer supporting rule was necessarily the historical finding emitter.

## Why this severity

DeltaScope distinguishes explicit severity causality from useful context.

If the frozen finding-emitting rule says:

```yaml
emit:
  severity: caution
```

then lineage can state that `caution` is the rule's direct output and that no higher arm is encoded in that rule.

If a retained collection has zero rows (for example `nativeImports = 0`) it can be shown as **counter-evidence / negative context**. But DeltaScope only says that the absence caused a downgrade when the frozen rule actually consumes it as a severity condition. Otherwise the UI says that it is relevant context, **not a proven severity modifier**.

A complete retained collection with zero rows is valid negative evidence. A missing/bounded collection is not.

## Version, time and scope

The narrative includes per-step provenance for:

- **Collection** — scanner/artifact/source analysis revision when retained, scan time, current variant and contributing collections;
- **Rule evaluation** — rule revision, frozen rule-set/Definitions revision, evaluation time when independently retained, and rule scope;
- **Publication** — Security Evidence revision, publication/snapshot time, scan ID and artifact identity.

When a producer or evaluation does not have an independent timestamp/revision in the Evidence contract, DeltaScope says so instead of filling the gap with the current wall clock.

## Other variants this rule matched

The lineage sidebar contains **Other variants this rule matched**.

Cross-variant fan-out can require loading many current variant descriptors, so it is never fetched merely because the lineage drawer opened. Press **Acquire rule fan-out** to perform an explicit bounded Evidence-v2 acquisition.

The fan-out shows:

- other current variants with the same rule/finding identity;
- plugin/version/severity;
- compact evidence previews;
- recurring evidence prefixes such as `metadata:KamiToolKit.dll` and how many matched variants share them.

This is the bridge from one Investigator finding to Security Researcher pattern-cluster work. The search is bounded and the UI reports how many candidate variants were inspected; absence from the bounded result is not a global “never matched” claim.

## Developer-friendly export

**Copy developer explanation** produces deterministic text from:

- the finding;
- linked frozen rule description;
- triggering evidence;
- explicit severity basis;
- counter-evidence / negative context.

The export is intended for the Plugin Developer “Why was this flagged?” conversation. It adds context only and cannot suppress a finding, lower severity, mark a review accepted, or become security authority.

## Exact replay versus bounded explanation

DeltaScope only claims exact Stigma-1 selector/fact replay when every required observation collection is present with the observation contract's complete `retained` semantics and all retained rows needed for evaluation were loaded.

A bounded preview, missing collection, historical observation contract, or transport limit does not become an invented match. In those cases the structural lineage is still shown, but the drawer says that exact selector replay could not be claimed.

## Current version only

Finding lineage follows the selected plugin's **current active version**. Historical versions remain available through version history and comparison views, but an archived risky finding does not become part of the current finding lineage or current severity totals.

## Endpoint and host classification

Endpoint intelligence is deterministic static classification of retained URL/host/IP observations. Omega can identify categories such as known platforms, collection/webhook endpoints, telemetry, certificate infrastructure, documentation/source references, insecure HTTP, private/loopback/special-use addresses, public IP literals, and otherwise unrecognised public hosts.

This is **not live reputation lookup**. Omega collects supported threat-intelligence feeds separately and freezes them into Definitions with provenance/revision information. A public IP literal is not labelled malicious merely because it is an IP address; only an exact active feed match (or a rule correlation built from it) adds reputation context.

## DLL and native-library scope

DLLs bundled in the plugin artifact are scanner inputs. SigmaScope identifies `.dll`, `.exe`, `.so`, and `.dylib` members, hashes the full member, classifies the binary, and performs bounded static parsing. Managed Windows assemblies can contribute CLR metadata, references, symbols, P/Invoke declarations and managed call-site observations. Native binaries can contribute native classification/import/interoperability observations.

There is an important runtime boundary: a plugin may call `LoadLibrary`, `NativeLibrary.Load`, `Assembly.Load*`, or related APIs to load a DLL from outside its package. SigmaScope can detect the loading capability/reference when statically observable, but it cannot inspect unknown external DLL bytes that were never acquired as artifact/source evidence. Those bytes need to be acquired through an explicit evidence/deep-analysis path before Omega can make claims about their contents.

## Authority boundary

Finding lineage is explanation, not policy. It has:

```text
readOnly = true
mutationAuthority = none
policyInput = false
```

Opening, replaying, exporting, or acquiring rule fan-out cannot change severity, create or remove findings, enqueue a scan, modify Definitions, or publish Security Evidence.

# Finding lineage

Finding lineage answers one question:

> Why does Omega currently say this about this plugin?

It reconstructs a bounded, read-only chain from the machinery that acquired or produced an observation through the rule/projection logic that emitted the current finding and into published Security Evidence.

The normal shape is:

```text
collector / producer
        ↓
retained observation collection
        ↓
matched observation row
        ↓
Stigma-1 selector
        ↓
fact / correlation
        ↓
finding
        ↓
published current Security Evidence
```

For older SigmaScope findings that do not come from an active Stigma-1 rule, DeltaScope uses a static lineage projection instead. It links the finding to the most specific retained observation collections and exact finding evidence that can be justified without pretending that a newer rule engine produced an older conclusion.

## Open lineage

Use **Trace lineage** beside a current finding in a plugin dossier, Latest Findings, or an Investigator case.

The lineage drawer groups nodes by stage:

- producer;
- retained evidence;
- facts;
- rule evaluation;
- finding;
- publication.

Observation collections are clickable and open the Data Collection inspector. Stigma-1 rule nodes are clickable and open the corresponding System Rule.

## Exact replay versus bounded explanation

DeltaScope only claims exact Stigma-1 selector/fact replay when every required observation collection is present with the observation contract's complete `retained` semantics and all retained rows needed for evaluation were loaded.

A bounded preview, missing collection, historical observation contract, or transport limit does not become an invented match. In those cases the structural lineage is still shown, but the drawer says that exact selector replay could not be claimed.

A complete collection with zero rows is valid negative evidence. It is not a missing collection.

## Current version only

Finding lineage follows the selected plugin's **current active version**. Historical versions remain available through version history and comparison views, but an archived risky finding does not become part of the current finding lineage or current severity totals.

## Endpoint and host classification

Endpoint intelligence is deterministic static classification of retained URL/host/IP observations. Omega can currently identify categories such as known platforms, collection/webhook endpoints, telemetry, certificate infrastructure, documentation/source references, insecure HTTP, private/loopback/special-use addresses, public IP literals, and otherwise unrecognised public hosts.

This is **not live reputation lookup**. Omega now collects supported threat-intelligence feeds separately and freezes them into daily Definitions with provenance/revision information. A public IP literal is still not labelled malicious merely because it is an IP address; only an exact active feed match (or a rule correlation built from it) adds reputation context. SigmaScope never makes arbitrary live reputation calls while scanning an artifact.

## DLL and native-library scope

DLLs bundled in the plugin artifact are scanner inputs. SigmaScope identifies `.dll`, `.exe`, `.so`, and `.dylib` members, hashes the full member, classifies the binary, and performs bounded static parsing. Managed Windows assemblies can contribute CLR metadata, references, symbols, P/Invoke declarations and managed call-site observations. Native binaries can contribute native classification/import/interoperability observations.

YARA supplemental analysis also scans bounded safe archive members including DLL/native-library candidates in addition to the artifact container. The ClamAV adapter is given the artifact container; DeltaScope does not claim that every DLL is independently materialised for ClamAV by Omega.

There is an important runtime boundary: a plugin may call `LoadLibrary`, `NativeLibrary.Load`, `Assembly.Load*`, or related APIs to load a DLL from outside its package. SigmaScope can detect the loading capability/reference when statically observable, but it cannot inspect unknown external DLL bytes that were never acquired as artifact/source evidence. Those bytes need to be acquired through an explicit evidence/deep-analysis path before Omega can make claims about their contents.

## Authority boundary

Finding lineage is explanation, not policy. It has:

```text
readOnly = true
mutationAuthority = none
policyInput = false
```

Opening or replaying lineage cannot change severity, create or remove findings, enqueue a scan, modify Definitions, or publish Security Evidence.

# Developer declaration versus observed behavior

Behavior consistency compares the developer’s optional `.omega/plugin.yaml` declaration with independently retained SigmaScope observations.

The purpose is explanation and discrepancy detection, not trust scoring.

## Typical states

### Observed and explained

SigmaScope observed the capability and the developer declared it as expected with a reason.

### Observed but undeclared

The artifact contains evidence for a capability that the current profile does not explain. This can be completely legitimate; DeltaScope presents it as an explanation gap.

### Observed but marked not expected

The developer profile explicitly says a capability is not expected, but SigmaScope observed it. This deserves review because the declaration and artifact disagree.

### Expected but not observed

The profile declares a capability as expected but the static analysis did not observe it. This can happen when behavior is optional, dynamically loaded, outside static coverage or the profile is stale.

### Destination mismatch

A network capability is explained but the retained endpoint set contains destinations not covered by the profile’s expected destinations.

## What consistency does not prove

A match between declaration and observation does not prove the plugin is safe. A mismatch does not prove malicious intent. It simply exposes where the developer explanation and independently observed evidence align or diverge.

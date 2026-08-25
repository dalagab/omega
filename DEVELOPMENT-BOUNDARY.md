# SigmaScope ↔ DeltaScope boundary

SigmaScope is a producer/authority-side service tree. DeltaScope is an independent read-only consumer.

When adding a component, provider, observation type, capability, SRL pack, or execution node, publish/extend the corresponding versioned contract. Do not add DeltaScope-specific rendering logic here.

The platform may publish descriptive data for DeltaScope, but production decisions must never depend on DeltaScope state.

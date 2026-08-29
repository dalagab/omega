# Independent development boundary

DeltaScope is a consumer. New SigmaScope/SRL components should become visible by publishing compatible component, collector, capability, execution-topology and SRL contracts. A DeltaScope code change is only required for new human-facing visualization/interaction, not basic discovery.

Do not copy scanner implementation into this tree. If a platform change requires executable compatibility logic, version the consumer contract/SDK deliberately.

Desktop native window dependencies are pinned separately in `desktop/requirements.txt`; they are presentation-only and must not be imported into security authority code.

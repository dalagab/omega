# Historical hand-written service stubs

These sources belong to the pre-API-15 Rift prototype. They are retained only
for design archaeology and are not compiled. API-15 execution uses
`RuntimeServiceRegistry` + `InstrumentedServiceProxy`, which follows the frozen
contract at runtime instead of maintaining a hand-written service implementation
for every Dalamud interface revision.

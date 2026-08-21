#!/usr/bin/env python3
from pathlib import Path
import sys
root=Path(__file__).resolve().parents[1]
checks=[]
def require(path, needle, desc):
    text=(root/path).read_text(encoding='utf-8')
    if needle not in text:
        print(f'FAIL: {desc}: {path} missing {needle!r}', file=sys.stderr); sys.exit(1)
    checks.append(desc)
def forbid(path, needle, desc):
    text=(root/path).read_text(encoding='utf-8')
    if needle in text:
        print(f'FAIL: {desc}: {path} still contains {needle!r}', file=sys.stderr); sys.exit(1)
    checks.append(desc)
require(Path('InterdimensionalRift/Host/SandboxHost.cs'), 'LoadAsync', 'API-15 async lifecycle')
forbid(Path('InterdimensionalRift/Host/SandboxHost.cs'), 'InitializeAsync', 'obsolete async lifecycle removed')
forbid(Path('InterdimensionalRift/Host/SandboxHost.cs'), 'GetMethod("Initialize")', 'obsolete sync lifecycle removed')
require(Path('InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs'), 'PluginServiceAttribute', 'PluginService injection')
require(Path('InterdimensionalRift/Runtime/DalamudContract.cs'), 'RIFT_DALAMUD_CONTRACT_DIR', 'frozen real Dalamud contract loader')
require(Path('InterdimensionalRift/Host/PluginLoader.cs'), 'DalamudContract.Assembly', 'shared real Dalamud assembly identity')
require(Path('InterdimensionalRift/Host/PluginLoader.cs'), 'TryResolveTrusted', 'trusted runtime sibling resolution')
forbid(Path('InterdimensionalRift/InterdimensionalRift.csproj'), 'InterdimensionalRift.DalamudShim', 'host no longer builds generated shim')
for project in [Path('samples/SamplePlugin/SamplePlugin.csproj'), Path('samples/AsyncSamplePlugin/AsyncSamplePlugin.csproj'), Path('tests/fixtures/RiftHostileCanary/RiftHostileCanary.csproj')]:
    require(project, 'Rift.Dalamud.Contract.props', f'{project.parent.name} compiles against frozen real contract')
    forbid(project, 'InterdimensionalRift.DalamudShim', f'{project.parent.name} does not target generated shim')
require(Path('tools/publish-rift-runtime.ps1'), '--inspect-only', 'DalaInspect is metadata-only in publication path')
require(Path('tests/InterdimensionalRift.Tests/SmokeTest.cs'), 'Assert.Equal("ok", report.Plugin.LoadOutcome)', 'positive fixture fails closed')
print(f'Rift source-contract checks: {len(checks)}/{len(checks)} passed')

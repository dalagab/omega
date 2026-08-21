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
require(Path('InterdimensionalRift/Host/PluginLoader.cs'), 'using InterdimensionalRift.Runtime;', 'PluginLoader imports real-contract runtime namespace')
require(Path('InterdimensionalRift/Host/PluginLoader.cs'), 'System.Reflection.AssemblyName.GetAssemblyName', 'AssemblyName factory is unambiguous')
require(Path('samples/SamplePlugin/Plugin.cs'), 'ClientState.IsLoggedIn', 'sync fixture uses current API-15 IClientState member')
forbid(Path('samples/SamplePlugin/Plugin.cs'), 'ClientState.LocalPlayer', 'sync fixture does not use removed LocalPlayer member')
require(Path('tests/fixtures/RiftHostileCanary/Plugin.cs'), 'ClientState.IsLoggedIn', 'hostile canary uses current API-15 IClientState member')
forbid(Path('tests/fixtures/RiftHostileCanary/Plugin.cs'), 'ClientState.LocalPlayer', 'hostile canary does not use removed LocalPlayer member')
require(Path('tests/InterdimensionalRift.Tests/SmokeTest.cs'), 'get_IsLoggedIn', 'runtime assertion tracks current IClientState touch')
forbid(Path('InterdimensionalRift/InterdimensionalRift.csproj'), 'InterdimensionalRift.DalamudShim', 'host no longer builds generated shim')
for project in [Path('samples/SamplePlugin/SamplePlugin.csproj'), Path('samples/AsyncSamplePlugin/AsyncSamplePlugin.csproj'), Path('tests/fixtures/RiftHostileCanary/RiftHostileCanary.csproj')]:
    require(project, 'Rift.Dalamud.Contract.props', f'{project.parent.name} compiles against frozen real contract')
    forbid(project, 'InterdimensionalRift.DalamudShim', f'{project.parent.name} does not target generated shim')
require(Path('tools/publish-rift-runtime.ps1'), '--inspect-only', 'DalaInspect is metadata-only in publication path')
require(Path('tests/InterdimensionalRift.Tests/SmokeTest.cs'), 'Assert.Equal("ok", report.Plugin.LoadOutcome)', 'positive fixture fails closed')

require(Path('InterdimensionalRift/Host/PluginLoader.cs'), 'ArtifactNativeLibraryResolver.Find', 'artifact RID-native fallback is active')
require(Path('InterdimensionalRift/Host/ArtifactNativeLibraryResolver.cs'), 'runtimes', 'artifact native resolver understands RID layout')
require(Path('InterdimensionalRift/Host/ArtifactNativeLibraryResolver.cs'), 'linux-', 'artifact native resolver supports Linux RID assets')
require(Path('tests/InterdimensionalRift.Tests/ArtifactNativeLibraryResolverTest.cs'), 'libe_sqlite3.so', 'native RID regression fixture covers e_sqlite3 layout')
require(Path('InterdimensionalRift/Reporting/FindingReporter.cs'), 'FindingKind.ServiceInjection => "service_injection"', 'service injection summary is explicit')
require(Path('InterdimensionalRift/Reporting/FindingReporter.cs'), 'FindingKind.Lifecycle => "lifecycle"', 'lifecycle summary is explicit')

loader_text=(root/Path('InterdimensionalRift/Host/PluginLoader.cs')).read_text(encoding='utf-8')
local_pos=loader_text.find('ResolveAssemblyToPath(assemblyName)')
trusted_pos=loader_text.find('TryResolveTrusted(assemblyName)')
if local_pos < 0 or trusted_pos < 0 or local_pos > trusted_pos:
    print('FAIL: plugin-local managed dependencies must resolve before trusted-runtime fallback', file=sys.stderr); sys.exit(1)
checks.append('plugin-local dependencies precede trusted-runtime fallback')

print(f'Rift source-contract checks: {len(checks)}/{len(checks)} passed')

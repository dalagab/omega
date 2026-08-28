#!/usr/bin/env python3
from pathlib import Path
import re, sys
ROOT=Path(__file__).resolve().parents[1]
CLIENT=ROOT/'client/RiftAlpha'
errors=[]
all_text='\n'.join(p.read_text(encoding='utf-8',errors='replace') for p in CLIENT.glob('*.cs'))
program=(CLIENT/'Program.cs').read_text(encoding='utf-8',errors='replace')
if '$\"\"\"<Project' in program or '$\"\"\"using Omega.Alpha;' in program:
    errors.append('Alpha scaffold generator contains an invalid multiline interpolated raw-string opener')
project=(CLIENT/'RiftAlpha.csproj').read_text(encoding='utf-8')
for forbidden in ('using Dalamud','PluginLoader','IDalamudPlugin','InterdimensionalRift.Host','--plugin','plugin.dll','PackageReference Include="Dalamud','ProjectReference Include="../InterdimensionalRift'):
    if forbidden in all_text or forbidden in project: errors.append(f'Rift Alpha client contains forbidden normal-plugin surface: {forbidden}')
if 'Omega.Alpha.Sdk' not in project: errors.append('Rift Alpha client must reference only the Alpha SDK workload contract')
for required in ('IAlphaScenario','RIFT_ALPHA_EXECUTOR','bwrap','systemd-run','--unshare-net','--seccomp 3','static-only and cannot be executed'):
    if required not in all_text and required not in (ROOT/'sdk/Omega.Alpha.Sdk/AlphaContracts.cs').read_text(encoding='utf-8'):
        errors.append(f'Rift Alpha client missing isolation invariant: {required}')
workflow=(ROOT/'.github/workflows/alpha-client-build.yml')
if not workflow.is_file(): errors.append('Alpha client autobuild workflow missing')
else:
    wf=workflow.read_text(encoding='utf-8')
    for path in ('client/RiftAlpha/**','sdk/Omega.Alpha.Sdk/**','shared/rift-boundary/**'):
        if path not in wf: errors.append(f'workflow is not watching shared/source path {path}')
    for rid in ('win-x64','linux-x64'):
        if rid not in wf: errors.append(f'workflow is not publishing {rid}')
if errors:
    for e in errors: print('FAIL:',e,file=sys.stderr)
    raise SystemExit(1)
print('Rift Alpha client contract: PASS (no normal plugin loader; Windows/WSL + Linux boundary; autobuild watched paths)')

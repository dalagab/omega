param(
    [Parameter(Mandatory=$true)][string]$HooksDir,
    [string]$Output = "artifacts/rift-linux-x64"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$hooks = (Resolve-Path $HooksDir).Path
$dalamud = Join-Path $hooks "Dalamud.dll"
if (-not (Test-Path $dalamud)) { throw "Dalamud.dll not found in $hooks" }
foreach ($name in @("Lumina.dll","FFXIVClientStructs.dll","Serilog.dll","Dalamud.Bindings.ImGui.dll")) {
    if (-not (Test-Path (Join-Path $hooks $name))) { throw "required frozen dependency missing: $name" }
}
$surface = Join-Path $root "artifacts/dalamud-surface.json"
New-Item -ItemType Directory -Force -Path (Split-Path $surface) | Out-Null

dotnet run --project (Join-Path $root "InterdimensionalRift.DalamudShim/tools/DalaInspect/DalaInspect.csproj") --configuration Release -- $dalamud $surface --inspect-only

dotnet test (Join-Path $root "tests/InterdimensionalRift.Tests/InterdimensionalRift.Tests.csproj") --configuration Release -p:HooksDir="$hooks"

dotnet publish (Join-Path $root "InterdimensionalRift/InterdimensionalRift.csproj") `
    --configuration Release `
    --runtime linux-x64 `
    --self-contained true `
    -p:HooksDir="$hooks" `
    --output (Join-Path $root $Output)

Write-Host "Rift runtime published to $Output"

$ErrorActionPreference = 'Stop'
$Desktop = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $Desktop
$Dist = Join-Path $Root 'dist'
New-Item -ItemType Directory -Force -Path $Dist | Out-Null
Push-Location $Desktop
try {
    go test ./...
    go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=4.21.12 -X main.buildFlavor=gui" -o (Join-Path $Dist 'DeltaScope.exe') ./cmd/deltascope-desktop
    go build -trimpath -ldflags "-s -w -X main.version=4.21.12 -X main.buildFlavor=console" -o (Join-Path $Dist 'DeltaScope-console.exe') ./cmd/deltascope-desktop
    Write-Host "Built $Dist\DeltaScope.exe (quiet desktop)"
    Write-Host "Built $Dist\DeltaScope-console.exe (developer diagnostics)"
} finally {
    Pop-Location
}

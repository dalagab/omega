$ErrorActionPreference = 'Stop'
$Desktop = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $Desktop
$Dist = Join-Path $Root 'dist'
$LauncherVersion = (Get-Content (Join-Path $Desktop 'launcher-version.txt') -Raw).Trim()
if ($LauncherVersion -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid DeltaScope launcher version '$LauncherVersion'" }
New-Item -ItemType Directory -Force -Path $Dist | Out-Null
Push-Location $Desktop
try {
    go test ./...
    go build -trimpath -ldflags "-s -w -H windowsgui -X main.launcherVersion=$LauncherVersion -X main.buildFlavor=gui" -o (Join-Path $Dist 'DeltaScope.exe') ./cmd/deltascope-desktop
    go build -trimpath -ldflags "-s -w -X main.launcherVersion=$LauncherVersion -X main.buildFlavor=console" -o (Join-Path $Dist 'DeltaScope-console.exe') ./cmd/deltascope-desktop
    Write-Host "Built $Dist\DeltaScope.exe (launcher $LauncherVersion, quiet desktop)"
    Write-Host "Built $Dist\DeltaScope-console.exe (launcher $LauncherVersion, developer diagnostics)"
} finally {
    Pop-Location
}

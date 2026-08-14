[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$RepositoryUrl = 'https://raw.githubusercontent.com/dalagab/omega/main/repository/pluginmaster.json',
    [string]$ConfigPath,
    [switch]$WhatIfOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-DalamudConfiguration {
    param([string]$RequestedPath)
    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) { return [System.IO.Path]::GetFullPath($RequestedPath) }
    return Join-Path $env:APPDATA 'XIVLauncher\dalamudConfig.json'
}

function Assert-DalamudIsNotRunning {
    $names = @('ffxiv', 'ffxiv_dx11', 'XIVLauncher', 'XIVLauncher.Core')
    $running = Get-Process -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.ProcessName }
    if ($running) { throw 'Close FINAL FANTASY XIV and XIVLauncher before changing Dalamud configuration.' }
}

$path = Resolve-DalamudConfiguration -RequestedPath $ConfigPath
Assert-DalamudIsNotRunning
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Dalamud configuration was not found: $path" }
$config = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
$entries = @($config.ThirdRepoList)
$remaining = @($entries | Where-Object {
    -not ($_.PSObject.Properties['Url'] -and [string]::Equals(([string]$_.Url).TrimEnd('/'), $RepositoryUrl.TrimEnd('/'), [System.StringComparison]::OrdinalIgnoreCase))
})
if ($remaining.Count -eq $entries.Count) { Write-Host 'Omega repository was not registered. No change required.'; return }
$config.ThirdRepoList = $remaining
if ($WhatIfOnly -or $WhatIfPreference) { Write-Host 'WhatIf: Omega repository entry would be removed; no files were changed.'; return }
if ($PSCmdlet.ShouldProcess($path, 'Remove the Omega repository entry')) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup = "$path.omega-backup-$stamp"
    Copy-Item -LiteralPath $path -Destination $backup
    $temp = Join-Path (Split-Path -Parent $path) ('.omega-dalamudConfig-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $json = $config | ConvertTo-Json -Depth 100
        [System.IO.File]::WriteAllText($temp, $json, [System.Text.UTF8Encoding]::new($false))
        $null = Get-Content -LiteralPath $temp -Raw -Encoding UTF8 | ConvertFrom-Json
        [System.IO.File]::Replace($temp, $path, $null)
    }
    finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue } }
    Write-Host "Omega repository removed. Backup created: $backup"
    Write-Host 'This script does not uninstall Omega. Uninstall the plugin through Dalamud if desired.'
}

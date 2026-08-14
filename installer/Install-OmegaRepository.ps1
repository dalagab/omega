[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$RepositoryUrl = 'https://raw.githubusercontent.com/dalagab/omega/main/repository/pluginmaster.json',
    [string]$ConfigPath,
    [switch]$WhatIfOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Find-DalamudConfiguration {
    param([string]$RequestedPath)

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        return [System.IO.Path]::GetFullPath($RequestedPath)
    }

    if ([string]::IsNullOrWhiteSpace($env:APPDATA)) {
        throw 'APPDATA is unavailable. Pass -ConfigPath explicitly.'
    }

    return Join-Path $env:APPDATA 'XIVLauncher\dalamudConfig.json'
}

function Assert-OmegaRepositoryUrl {
    param([string]$Url)

    $uri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https') {
        throw 'Omega repository URL must be an absolute HTTPS URL.'
    }
}

function Assert-DalamudIsNotRunning {
    $names = @('ffxiv', 'ffxiv_dx11', 'XIVLauncher', 'XIVLauncher.Core')
    $running = Get-Process -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.ProcessName }
    if ($running) {
        $list = ($running.ProcessName | Sort-Object -Unique) -join ', '
        throw "Close FINAL FANTASY XIV and XIVLauncher before changing Dalamud configuration. Running: $list"
    }
}

function Read-DalamudConfiguration {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Dalamud configuration was not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw 'Dalamud configuration is empty; refusing to modify it.'
    }

    try {
        return $raw | ConvertFrom-Json
    }
    catch {
        throw "Dalamud configuration is not valid JSON; refusing to modify it. $($_.Exception.Message)"
    }
}

function Ensure-ThirdRepoList {
    param([object]$Configuration)

    $property = $Configuration.PSObject.Properties['ThirdRepoList']
    if ($null -eq $property) {
        $Configuration | Add-Member -NotePropertyName ThirdRepoList -NotePropertyValue @()
        return
    }

    if ($null -eq $Configuration.ThirdRepoList) {
        $Configuration.ThirdRepoList = @()
        return
    }

    if ($Configuration.ThirdRepoList -isnot [System.Collections.IEnumerable]) {
        throw 'ThirdRepoList has an unexpected shape; refusing to modify Dalamud configuration.'
    }
}

function Add-OrEnableOmegaRepository {
    param(
        [object]$Configuration,
        [string]$Url
    )

    Ensure-ThirdRepoList -Configuration $Configuration
    $items = @($Configuration.ThirdRepoList)
    $existing = $items | Where-Object {
        $_ -and $_.PSObject.Properties['Url'] -and
        [string]::Equals(([string]$_.Url).TrimEnd('/'), $Url.TrimEnd('/'), [System.StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1

    if ($null -ne $existing) {
        if (-not $existing.PSObject.Properties['IsEnabled']) {
            $existing | Add-Member -NotePropertyName IsEnabled -NotePropertyValue $true
            return 'enabled-existing'
        }

        if (-not [bool]$existing.IsEnabled) {
            $existing.IsEnabled = $true
            return 'enabled-existing'
        }

        return 'already-enabled'
    }

    $newEntry = [pscustomobject]@{
        Url = $Url
        IsEnabled = $true
    }
    $Configuration.ThirdRepoList = @($items + $newEntry)
    return 'added'
}

function Backup-DalamudConfiguration {
    param([string]$Path)

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup = "$Path.omega-backup-$stamp"
    Copy-Item -LiteralPath $Path -Destination $backup -ErrorAction Stop
    return $backup
}

function Write-DalamudConfigurationAtomically {
    param(
        [object]$Configuration,
        [string]$Path
    )

    $directory = Split-Path -Parent $Path
    $temp = Join-Path $directory ('.omega-dalamudConfig-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $json = $Configuration | ConvertTo-Json -Depth 100
        [System.IO.File]::WriteAllText($temp, $json, [System.Text.UTF8Encoding]::new($false))
        $null = Get-Content -LiteralPath $temp -Raw -Encoding UTF8 | ConvertFrom-Json
        [System.IO.File]::Replace($temp, $Path, $null)
    }
    finally {
        if (Test-Path -LiteralPath $temp) {
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-OmegaRepositoryRegistration {
    param(
        [string]$Path,
        [string]$Url
    )

    $configuration = Read-DalamudConfiguration -Path $Path
    $entries = @($configuration.ThirdRepoList)
    $match = $entries | Where-Object {
        $_ -and $_.PSObject.Properties['Url'] -and
        [string]::Equals(([string]$_.Url).TrimEnd('/'), $Url.TrimEnd('/'), [System.StringComparison]::OrdinalIgnoreCase) -and
        [bool]$_.IsEnabled
    } | Select-Object -First 1

    if ($null -eq $match) {
        throw 'Omega repository registration could not be verified after writing the configuration.'
    }
}

function Invoke-OmegaRepositoryInstallation {
    $resolvedConfig = Find-DalamudConfiguration -RequestedPath $ConfigPath
    Assert-OmegaRepositoryUrl -Url $RepositoryUrl
    Assert-DalamudIsNotRunning

    $configuration = Read-DalamudConfiguration -Path $resolvedConfig
    $result = Add-OrEnableOmegaRepository -Configuration $configuration -Url $RepositoryUrl

    Write-Host "Dalamud configuration: $resolvedConfig"
    Write-Host "Omega repository:      $RepositoryUrl"
    Write-Host "Planned result:         $result"

    if ($WhatIfOnly -or $WhatIfPreference) {
        Write-Host 'WhatIf: no files were changed.'
        return
    }

    if ($result -eq 'already-enabled') {
        Write-Host 'Omega repository is already registered and enabled. No write was required.'
        return
    }

    if ($PSCmdlet.ShouldProcess($resolvedConfig, 'Register and enable the Omega Dalamud repository')) {
        $backup = Backup-DalamudConfiguration -Path $resolvedConfig
        Write-DalamudConfigurationAtomically -Configuration $configuration -Path $resolvedConfig
        Test-OmegaRepositoryRegistration -Path $resolvedConfig -Url $RepositoryUrl
        Write-Host "Backup created: $backup"
        Write-Host 'Omega repository registered. Start XIVLauncher, open /xlplugins, search for Omega, and install it through Dalamud.'
    }
}

Invoke-OmegaRepositoryInstallation

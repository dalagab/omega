param([string]$ProjectRoot = "")
$ErrorActionPreference = 'Stop'
# Retired compatibility tombstone for the temporary 0.7.4.0 overlay validator.
# Current validation lives in Omega.RegressionTests and tools/validate-package.ps1.
Write-Host 'Omega legacy marketplace overlay validator: retired/no-op.'
exit 0

param(
    [string]$ProjectRoot,
    [switch]$FromBuild
)

$ErrorActionPreference = 'Stop'

# Compatibility tombstone for the temporary 0.7.4.0 build-time source overlay.
# ZipRunner does not delete files omitted by later ZIPs, so this harmless script is
# shipped to overwrite the stale mutating implementation on existing worktrees.
# Omega 0.7.4.3 contains the marketplace UI changes directly in Omega/UI/*.cs.
Write-Host 'Omega marketplace UI design pass: retired/no-op (source is already integrated).'
exit 0

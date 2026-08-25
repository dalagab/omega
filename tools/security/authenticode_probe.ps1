param(
    [Parameter(Mandatory=$true)]
    [string]$Path
)

$ErrorActionPreference = 'Stop'
$sig = Get-AuthenticodeSignature -LiteralPath $Path

function Convert-Certificate($cert) {
    if ($null -eq $cert) { return $null }
    return [ordered]@{
        subject = [string]$cert.Subject
        issuer = [string]$cert.Issuer
        thumbprint = ([string]$cert.Thumbprint).ToLowerInvariant()
        serialNumber = [string]$cert.SerialNumber
        notBeforeUtc = $cert.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        notAfterUtc = $cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        signatureAlgorithm = [string]$cert.SignatureAlgorithm.Value
        publicKeyAlgorithm = [string]$cert.PublicKey.Oid.Value
    }
}

[ordered]@{
    schema = 'omega.authenticode.windows-probe.v1'
    status = [string]$sig.Status
    statusMessage = [string]$sig.StatusMessage
    validationPlatform = [string][System.Environment]::OSVersion.VersionString
    validationMethod = 'Get-AuthenticodeSignature/WinVerifyTrust'
    validationEngineVersion = [string]$PSVersionTable.PSVersion
    validatedAtUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    validationTrustContext = 'current Windows runner trust configuration'
    validationNetworkPolicy = 'platform-default'
    signer = Convert-Certificate $sig.SignerCertificate
    timestamper = Convert-Certificate $sig.TimeStamperCertificate
} | ConvertTo-Json -Depth 5 -Compress

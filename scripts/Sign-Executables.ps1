<#
.SYNOPSIS
    Creates a self-signed code-signing certificate (if needed) and signs ADapp executables.
.DESCRIPTION
    - Creates/uses a self-signed code-signing cert in Cert:\LocalMachine\My
    - Trusts the cert locally by adding it to LocalMachine Root and TrustedPublisher
    - Signs ADapp.exe and LockedMonitor.exe
    - Verifies and prints signature status
.PARAMETER Subject
    Certificate subject CN to use. Default: "SWHC IT".
.PARAMETER ForceNewCert
    If set, always create a new certificate even if one exists.
.EXAMPLE
    .\scripts\Sign-Executables.ps1
#>
param(
    [string]$Subject = 'SWHC IT',
    [switch]$ForceNewCert
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).
        IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "Administrator privileges required for LocalMachine certificate stores."
    }
}

function Get-CodeSigningCert {
    param([string]$SubjectName)

    $targetSubject = "CN=$SubjectName"
    $existing = Get-ChildItem -Path Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq $targetSubject -and $_.EnhancedKeyUsageList.FriendlyName -contains 'Code Signing' } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if ($existing -and -not $ForceNewCert) {
        return $existing
    }

    Write-Host "Creating self-signed code-signing cert: $targetSubject" -ForegroundColor Cyan
    return New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $targetSubject `
        -CertStoreLocation 'Cert:\LocalMachine\My' `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(3)
}

function Ensure-Trusted {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

    $tempFile = Join-Path $env:TEMP ("ADapp-CodeSigning-" + [Guid]::NewGuid().ToString("N") + ".cer")
    try {
        Export-Certificate -Cert $Cert -FilePath $tempFile | Out-Null

        $rootMatch = Get-ChildItem -Path Cert:\LocalMachine\Root |
            Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
        if (-not $rootMatch) {
            Write-Host "Adding cert to LocalMachine Root trust store" -ForegroundColor Cyan
            Import-Certificate -FilePath $tempFile -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
        }

        $publisherMatch = Get-ChildItem -Path Cert:\LocalMachine\TrustedPublisher |
            Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
        if (-not $publisherMatch) {
            Write-Host "Adding cert to LocalMachine TrustedPublisher" -ForegroundColor Cyan
            Import-Certificate -FilePath $tempFile -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
        }
    } finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
    }
}

function Sign-File {
    param(
        [string]$FilePath,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }

    Write-Host "Signing $FilePath" -ForegroundColor White
    $result = Set-AuthenticodeSignature -FilePath $FilePath -Certificate $Cert
    if ($result.Status -ne 'Valid') {
        throw "Signing failed for ${FilePath}: $($result.StatusMessage)"
    }
}

function Verify-File {
    param([string]$FilePath)

    $sig = Get-AuthenticodeSignature -FilePath $FilePath
    [PSCustomObject]@{
        File   = Split-Path -Leaf $FilePath
        Status = $sig.Status
        Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'None' }
    }
}

try {
    Assert-Admin

    $repoRootPath = Resolve-Path (Join-Path $PSScriptRoot '..') | Select-Object -First 1 -ExpandProperty Path
    $exePaths = @(
        (Join-Path $repoRootPath 'ADapp.exe')
        (Join-Path $repoRootPath 'LockedMonitor.exe')
    )

    $cert = Get-CodeSigningCert -SubjectName $Subject
    Ensure-Trusted -Cert $cert

    foreach ($exe in $exePaths) {
        Sign-File -FilePath $exe -Cert $cert
    }

    Write-Host "`nSignature verification:" -ForegroundColor Cyan
    $exePaths | ForEach-Object { Verify-File -FilePath $_ } | Format-Table -AutoSize
    Write-Host "`nSigning complete." -ForegroundColor Green
} catch {
    Write-Host "Signing failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-Host $_.InvocationInfo.PositionMessage -ForegroundColor DarkGray
    }
    exit 1
}

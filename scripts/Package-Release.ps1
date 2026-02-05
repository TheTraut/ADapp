<#
.SYNOPSIS
    Creates a production-ready release package.
.DESCRIPTION
    Builds a zip containing runtime assets, documentation, and installer scripts.
    Excludes dev-only folders such as tools/ and tests/.
.PARAMETER OutputPath
    Destination zip path. Defaults to .\dist\ADapp-Release.zip
.EXAMPLE
    .\scripts\Package-Release.ps1
#>
param(
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$repoRootPath = $repoRoot.Path
if ($repoRootPath -is [System.Array]) { $repoRootPath = $repoRootPath[0] }

$defaultOut = Join-Path $repoRootPath 'dist\ADapp-Release.zip'
$outPath = if ($OutputPath) { $OutputPath } else { $defaultOut }
$outDir = Split-Path -Parent $outPath

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

function Copy-IfExists {
    param(
        [Parameter(Mandatory=$true)][string]$Source,
        [Parameter(Mandatory=$true)][string]$Dest
    )
    if (Test-Path $Source) {
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $Dest) -Force
        Copy-Item -Path $Source -Destination $Dest -Recurse -Force
        return $true
    }
    return $false
}

$staging = Join-Path $env:TEMP ("ADapp-Release-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $staging -Force | Out-Null

try {
    # Core runtime assets
    Copy-IfExists -Source (Join-Path $repoRootPath 'ADapp.ps1') -Dest (Join-Path $staging 'ADapp.ps1') | Out-Null
    Copy-IfExists -Source (Join-Path $repoRootPath 'ADapp.exe') -Dest (Join-Path $staging 'ADapp.exe') | Out-Null
    Copy-IfExists -Source (Join-Path $repoRootPath 'LockedMonitor.exe') -Dest (Join-Path $staging 'LockedMonitor.exe') | Out-Null
    Copy-IfExists -Source (Join-Path $repoRootPath 'LockedMonitor.ps1') -Dest (Join-Path $staging 'LockedMonitor.ps1') | Out-Null
    Copy-IfExists -Source (Join-Path $repoRootPath 'Modules') -Dest (Join-Path $staging 'Modules') | Out-Null
    Copy-IfExists -Source (Join-Path $repoRootPath 'config') -Dest (Join-Path $staging 'config') | Out-Null
    Copy-IfExists -Source (Join-Path $repoRootPath 'assets') -Dest (Join-Path $staging 'assets') | Out-Null

    # Optional items
    Copy-IfExists -Source (Join-Path $repoRootPath 'docs') -Dest (Join-Path $staging 'docs') | Out-Null
    # Installer scripts are expected in production packages.
    Copy-IfExists -Source (Join-Path $repoRootPath 'scripts\Install.ps1') -Dest (Join-Path $staging 'scripts\Install.ps1') | Out-Null
    Copy-IfExists -Source (Join-Path $repoRootPath 'scripts\Uninstall.ps1') -Dest (Join-Path $staging 'scripts\Uninstall.ps1') | Out-Null

    # Always include readme/changelog/about/quickstart if present
    Copy-IfExists -Source (Join-Path $repoRootPath 'README.md') -Dest (Join-Path $staging 'README.md') | Out-Null
    Copy-IfExists -Source (Join-Path $repoRootPath 'CHANGELOG.md') -Dest (Join-Path $staging 'CHANGELOG.md') | Out-Null
    Copy-IfExists -Source (Join-Path $repoRootPath 'ABOUT.md') -Dest (Join-Path $staging 'ABOUT.md') | Out-Null
    Copy-IfExists -Source (Join-Path $repoRootPath 'QUICKSTART.md') -Dest (Join-Path $staging 'QUICKSTART.md') | Out-Null

    if (Test-Path $outPath) {
        Remove-Item $outPath -Force
    }

    Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $outPath -Force
    Write-Host "Release package created: $outPath" -ForegroundColor Green
} finally {
    if (Test-Path $staging) {
        Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}


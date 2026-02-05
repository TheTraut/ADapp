<#
.SYNOPSIS
    Synchronizes version numbers across the codebase.
.DESCRIPTION
    Updates version numbers in config/settings.json, C# launchers, and CHANGELOG
    to ensure consistency.
.PARAMETER Version
    The version number to set (format: X.Y.Z).
.PARAMETER WhatIf
    Show what would be changed without making changes.
.EXAMPLE
    .\tools\Sync-Version.ps1 -Version "1.0.18"
#>
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,
    
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent

Write-Host "Syncing version to: $Version" -ForegroundColor Cyan

$files = @(
    @{
        Path = Join-Path $repoRoot 'config\settings.json'
        Pattern = '"Version":\s*"[\d.]+"'
        Replacement = "`"Version`":  `"$Version`""
    },
    @{
        Path = Join-Path $repoRoot 'src\ADapp.Launcher\Program.cs'
        Pattern = '\[assembly: AssemblyVersion\("[\d.]+"\)\]'
        Replacement = "[assembly: AssemblyVersion(`"$Version.0`")]"
    },
    @{
        Path = Join-Path $repoRoot 'src\ADapp.Launcher\Program.cs'
        Pattern = '\[assembly: AssemblyFileVersion\("[\d.]+"\)\]'
        Replacement = "[assembly: AssemblyFileVersion(`"$Version.0`")]"
    },
    @{
        Path = Join-Path $repoRoot 'src\LockedMonitor.Launcher\Program.cs'
        Pattern = '\[assembly: AssemblyVersion\("[\d.]+"\)\]'
        Replacement = "[assembly: AssemblyVersion(`"$Version.0`")]"
    },
    @{
        Path = Join-Path $repoRoot 'src\LockedMonitor.Launcher\Program.cs'
        Pattern = '\[assembly: AssemblyFileVersion\("[\d.]+"\)\]'
        Replacement = "[assembly: AssemblyFileVersion(`"$Version.0`")]"
    }
)

foreach ($file in $files) {
    if (-not (Test-Path $file.Path)) {
        Write-Warning "File not found: $($file.Path)"
        continue
    }
    
    $content = Get-Content $file.Path -Raw
    $newContent = [regex]::Replace($content, $file.Pattern, $file.Replacement)
    
    if ($content -ne $newContent) {
        if ($WhatIf) {
            Write-Host "Would update: $($file.Path)" -ForegroundColor Yellow
        } else {
            $newContent | Set-Content $file.Path -NoNewline
            Write-Host "Updated: $($file.Path)" -ForegroundColor Green
        }
    } else {
        Write-Host "Already up to date: $($file.Path)" -ForegroundColor Gray
    }
}

Write-Host "`nDon't forget to update CHANGELOG.md manually!" -ForegroundColor Cyan

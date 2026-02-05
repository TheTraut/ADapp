<#
.SYNOPSIS
    Uninstallation script for ADapp.
.DESCRIPTION
    Removes ADapp shortcuts, application data, and built executables.
.PARAMETER KeepData
    Preserve application data in ProgramData.
.PARAMETER KeepAppFiles
    Preserve built executables in the repository root.
.PARAMETER KeepRepo
    Preserve the repository folder.
.PARAMETER RemoveShortcuts
    Remove desktop and start menu shortcuts.
.EXAMPLE
    .\scripts\Uninstall.ps1
    Removes shortcuts, application data, and built executables.
.EXAMPLE
    .\scripts\Uninstall.ps1 -KeepData
    Removes shortcuts and built executables only.
.EXAMPLE
    .\scripts\Uninstall.ps1 -KeepAppFiles
    Removes shortcuts and application data only.
.EXAMPLE
    .\scripts\Uninstall.ps1 -KeepRepo
    Removes shortcuts, application data, and built executables only.
#>
param(
    [switch]$KeepData,
    [switch]$KeepAppFiles,
    [switch]$KeepRepo,
    [switch]$RemoveShortcuts = $true
)

$ErrorActionPreference = 'Continue'
$scriptPath = $PSScriptRoot
$repoRoot = Resolve-Path (Join-Path $scriptPath '..')
$repoRootPath = $repoRoot.Path

function Write-Step {
    param([string]$Message)
    Write-Host "`n>> $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "   [OK] $Message" -ForegroundColor Green
}

function Write-Skip {
    param([string]$Message)
    Write-Host "   [SKIP] $Message" -ForegroundColor Yellow
}

Write-Host @"

  ADapp Uninstaller

"@ -ForegroundColor Magenta

$processNames = @('ADapp', 'LockedMonitor')
$running = Get-Process -Name $processNames -ErrorAction SilentlyContinue
if ($running) {
    Write-Step "Closing running applications"
    Write-Warning "Running instances detected; they will be closed to complete uninstall."
    foreach ($proc in $running) {
        try {
            if ($proc.MainWindowHandle -ne 0) {
                $null = $proc.CloseMainWindow()
            }
        } catch {}
    }
    try { $running | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue } catch {}
    $stillRunning = Get-Process -Name $processNames -ErrorAction SilentlyContinue
    if ($stillRunning) {
        Write-Step "Stopping remaining processes"
        foreach ($proc in $stillRunning) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Success "Stopped: $($proc.ProcessName) (PID $($proc.Id))"
            } catch {
                Write-Warning "Failed to stop: $($proc.ProcessName) (PID $($proc.Id)) - $_"
            }
        }
    }
}

if ($RemoveShortcuts) {
    Write-Step "Removing shortcuts"
    
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $startMenuPath = [Environment]::GetFolderPath('Programs')
    
    $shortcuts = @(
        (Join-Path $desktopPath 'ADapp.lnk'),
        (Join-Path $desktopPath 'Locked Users Monitor.lnk'),
        (Join-Path $startMenuPath 'ADapp.lnk'),
        (Join-Path $startMenuPath 'Locked Users Monitor.lnk')
    )
    
    foreach ($shortcut in $shortcuts) {
        if (Test-Path $shortcut) {
            try {
                Remove-Item $shortcut -Force
                Write-Success "Removed: $shortcut"
            } catch {
                Write-Warning "Failed to remove: $shortcut"
            }
        } else {
            Write-Skip "Not found: $shortcut"
        }
    }
}

if (-not $KeepData) {
    Write-Step "Removing application data"
    
    $dataDirs = @(
        "$env:ProgramData\ADapp"
    )
    
    foreach ($dir in $dataDirs) {
        if (Test-Path $dir) {
            try {
                Remove-Item $dir -Recurse -Force
                Write-Success "Removed: $dir"
            } catch {
                Write-Warning "Failed to remove: $dir - $_"
            }
        } else {
            Write-Skip "Not found: $dir"
        }
    }
}

if ($KeepRepo -and -not $KeepAppFiles) {
    Write-Step "Removing application executables"

    $appFiles = @(
        (Join-Path $repoRoot 'ADapp.exe'),
        (Join-Path $repoRoot 'LockedMonitor.exe')
    )

    foreach ($file in $appFiles) {
        if (Test-Path $file) {
            try {
                Remove-Item $file -Force
                Write-Success "Removed: $file"
            } catch {
                Write-Warning "Failed to remove: $file - $_"
            }
        } else {
            Write-Skip "Not found: $file"
        }
    }
}

if (-not $KeepRepo) {
    Write-Step "Removing repository folder"

    if (Test-Path $repoRootPath) {
        try {
            if ($PWD.Path -like "$repoRootPath*") {
                Set-Location -Path $env:TEMP
            }
            $escapedRoot = $repoRootPath.Replace('"', '""')
            $removeCmd = "timeout /t 1 /nobreak > nul & rmdir /s /q `"$escapedRoot`""
            Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", $removeCmd) -WindowStyle Hidden
            Write-Success "Removal started: $repoRootPath"
        } catch {
            Write-Warning "Failed to start repo removal: $repoRootPath - $_"
        }
    } else {
        Write-Skip "Not found: $repoRootPath"
    }
}

Write-Host "`nUninstall complete." -ForegroundColor Green
if ($KeepRepo) {
    Write-Host "Note: The repository folder was not removed. Delete it manually if desired." -ForegroundColor Gray
}
Write-Host ""

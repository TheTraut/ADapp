<#
.SYNOPSIS
    Installation and setup script for ADapp.
.DESCRIPTION
    Performs initial setup for ADapp including:
    - Verifying prerequisites (PowerShell version, modules)
    - Creating required directories
    - Setting up initial configuration
    - Optionally creating desktop/start menu shortcuts
.PARAMETER SkipShortcuts
    Skip creating desktop and start menu shortcuts.
.PARAMETER SkipPrerequisites
    Skip prerequisite checks (use if you know they're met).
.EXAMPLE
    .\scripts\Install.ps1
    Full installation with all steps.
.EXAMPLE
    .\scripts\Install.ps1 -SkipShortcuts
    Install without creating shortcuts.
#>
param(
    [switch]$SkipShortcuts,
    [switch]$SkipPrerequisites
)

$ErrorActionPreference = 'Stop'
$scriptPath = $PSScriptRoot
$repoRoot = Resolve-Path (Join-Path $scriptPath '..')
$repoRootPath = $repoRoot.Path
if ($repoRootPath -is [System.Array]) {
    $repoRootPath = $repoRootPath[0]
}

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

function Write-Fail {
    param([string]$Message)
    Write-Host "   [FAIL] $Message" -ForegroundColor Red
}

# Header
Write-Host @"

    ___    ____                      
   /   |  / __ \____ _____  ____  
  / /| | / / / / __ `/ __ \/ __ \ 
 / ___ |/ /_/ / /_/ / /_/ / /_/ / 
/_/  |_/_____/\__,_/ .___/ .___/  
                  /_/   /_/       

  Active Directory Management Tool
  Installation Script

"@ -ForegroundColor Magenta

# Check admin rights for certain operations
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $SkipPrerequisites) {
    Write-Step "Checking prerequisites"
    
    # PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        Write-Success "PowerShell $($psVersion.Major).$($psVersion.Minor)"
    } else {
        Write-Fail "PowerShell 5.1 or higher required (found $psVersion)"
        exit 1
    }
    
    # .NET Framework
    $dotNetKey = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
    if ($dotNetKey -and $dotNetKey.Release -ge 461808) {
        Write-Success ".NET Framework 4.7.2 or higher"
    } else {
        Write-Fail ".NET Framework 4.7.2 or higher required"
        Write-Host "   Download from: https://dotnet.microsoft.com/download/dotnet-framework" -ForegroundColor Gray
    }
    
    # Active Directory module
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Success "ActiveDirectory PowerShell module"
    } else {
        Write-Fail "ActiveDirectory module not found"
        Write-Host "   Install RSAT tools or run: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Gray
    }
    
    # Windows Forms (should always be present on Windows)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Write-Success "System.Windows.Forms assembly"
    } catch {
        Write-Fail "System.Windows.Forms assembly not available"
    }
}

Write-Step "Creating data directories"

$directories = @(
    "$env:ProgramData\ADapp",
    "$env:ProgramData\ADapp\Logs",
    "$env:ProgramData\ADapp\Data",
    "$env:ProgramData\ADapp\config"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        try {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Success "Created: $dir"
        } catch {
            Write-Fail "Failed to create: $dir"
            Write-Host "   Error: $_" -ForegroundColor Gray
        }
    } else {
        Write-Skip "Already exists: $dir"
    }
}

Write-Step "Checking configuration"

Write-Step "Validating repository"

$repoChecks = @(
    @{ Path = Join-Path $repoRootPath 'config\settings.json'; Label = 'config/settings.json' },
    @{ Path = Join-Path $repoRootPath 'Modules'; Label = 'Modules/' }
)

$missingRepoItems = @()
foreach ($check in $repoChecks) {
    if (-not (Test-Path $check.Path)) {
        $missingRepoItems += $check.Label
    }
}

if ($missingRepoItems.Count -gt 0) {
    Write-Fail "Repository is missing required items: $($missingRepoItems -join ', ')"
    Write-Host "   Run this script from a full ADapp repo clone." -ForegroundColor Gray
    exit 1
}

$settingsPath = Join-Path $repoRootPath 'config\settings.json'
$localSettingsPath = Join-Path $env:ProgramData 'ADapp\config\settings.local.json'

if (Test-Path $settingsPath) {
    Write-Success "config/settings.json found"
} else {
    Write-Fail "config/settings.json not found - application may not start correctly"
}

if (Test-Path $localSettingsPath) {
    Write-Success "%ProgramData%\\ADapp\\config\\settings.local.json found (local overrides active)"
} else {
    Write-Skip "No %ProgramData%\\ADapp\\config\\settings.local.json (using defaults)"
    
    $examplePath = Join-Path $repoRootPath 'config\settings.local.json.example'
    if (Test-Path $examplePath) {
        Write-Host "   Copy config/settings.local.json.example to %ProgramData%\\ADapp\\config\\settings.local.json to customize" -ForegroundColor Gray
    }
}

if (-not $SkipShortcuts) {
    $launcherTargets = @()
    $launcherTargets += (Join-Path -Path $repoRootPath -ChildPath 'ADapp.exe')
    $launcherTargets += (Join-Path -Path $repoRootPath -ChildPath 'LockedMonitor.exe')

    if ($launcherTargets | Where-Object { -not (Test-Path $_) }) {
        Write-Step "Building launchers (missing executables)"
        try {
            & (Join-Path $scriptPath 'Build.ps1') -Task Build
            Write-Success "Build task completed"
        } catch {
            Write-Fail "Build task failed"
            Write-Host "   Error: $_" -ForegroundColor Gray
        }
    }

    Write-Step "Creating shortcuts"
    
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $startMenuPath = [Environment]::GetFolderPath('Programs')
    
    $shortcuts = @(
        @{
            Name = 'ADapp'
            TargetPath = Join-Path $repoRootPath 'ADapp.exe'
            IconPath = Join-Path $repoRootPath 'assets\icons\adapp.ico'
            Description = 'Active Directory Management Tool'
        },
        @{
            Name = 'Locked Users Monitor'
            TargetPath = Join-Path $repoRootPath 'LockedMonitor.exe'
            IconPath = Join-Path $repoRootPath 'assets\icons\LockedMonitor.ico'
            Description = 'Monitor locked AD accounts'
        }
    )
    
    $shell = New-Object -ComObject WScript.Shell
    
    foreach ($shortcut in $shortcuts) {
        if (-not (Test-Path $shortcut.TargetPath)) {
            Write-Skip "$($shortcut.Name) - executable not found"
            continue
        }
        
        # Desktop shortcut
        $desktopShortcutPath = Join-Path $desktopPath "$($shortcut.Name).lnk"
        try {
            $lnk = $shell.CreateShortcut($desktopShortcutPath)
            $lnk.TargetPath = $shortcut.TargetPath
            $lnk.WorkingDirectory = $repoRootPath
            $lnk.Description = $shortcut.Description
            if (Test-Path $shortcut.IconPath) {
                $lnk.IconLocation = $shortcut.IconPath
            }
            $lnk.Save()
            Write-Success "Desktop: $($shortcut.Name)"
        } catch {
            Write-Fail "Desktop shortcut: $($shortcut.Name)"
        }
        
        # Start Menu shortcut
        $startMenuShortcutPath = Join-Path $startMenuPath "$($shortcut.Name).lnk"
        try {
            $lnk = $shell.CreateShortcut($startMenuShortcutPath)
            $lnk.TargetPath = $shortcut.TargetPath
            $lnk.WorkingDirectory = $repoRootPath
            $lnk.Description = $shortcut.Description
            if (Test-Path $shortcut.IconPath) {
                $lnk.IconLocation = $shortcut.IconPath
            }
            $lnk.Save()
            Write-Success "Start Menu: $($shortcut.Name)"
        } catch {
            Write-Fail "Start Menu shortcut: $($shortcut.Name)"
        }
    }
    
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
}

Write-Step "Verifying module structure"

$modules = Get-ChildItem -Path (Join-Path $repoRootPath 'Modules') -Filter '*.psm1' -ErrorAction SilentlyContinue
if ($modules) {
    Write-Success "Found $($modules.Count) modules in Modules/"
} else {
    Write-Fail "No modules found in Modules/ directory"
}

# Summary
Write-Host "`n" + ("=" * 50) -ForegroundColor Green
Write-Host " Installation Complete!" -ForegroundColor Green
Write-Host ("=" * 50) -ForegroundColor Green

Write-Host "`nTo start ADapp:" -ForegroundColor White
Write-Host "  - Double-click ADapp.exe" -ForegroundColor Gray
Write-Host "  - Or run: .\ADapp.ps1" -ForegroundColor Gray

if (-not $isAdmin) {
    Write-Host "`nNote: Some AD operations may require running as Administrator" -ForegroundColor Yellow
}

Write-Host "`nFor development:" -ForegroundColor White
Write-Host "  - Run: .\scripts\Build.ps1 -Task All" -ForegroundColor Gray
Write-Host "  - See: CONTRIBUTING.md" -ForegroundColor Gray

Write-Host ""

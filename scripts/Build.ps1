<#
.SYNOPSIS
    Build script for ADapp - runs analysis, builds C# launchers, and validates configuration.
.DESCRIPTION
    Orchestrates the build process for ADapp:
    - Runs PSScriptAnalyzer for code quality
    - Builds C# launcher executables
    - Validates config/settings.json schema
.PARAMETER Task
    The task to run: 'All', 'Analyze', 'Build', 'Validate', 'Test'. Defaults to 'All'.
.PARAMETER Fix
    If specified with Analyze task, attempts to auto-fix issues where possible.
.EXAMPLE
    .\scripts\Build.ps1
    Runs all build tasks.
.EXAMPLE
    .\scripts\Build.ps1 -Task Analyze
    Runs only the PSScriptAnalyzer.
.EXAMPLE
    .\scripts\Build.ps1 -Task Test
    Runs Pester tests.
#>
param(
    [ValidateSet('All', 'Analyze', 'Build', 'Validate', 'Test')]
    [string]$Task = 'All',
    [switch]$Fix
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

function Write-TaskHeader {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Invoke-Analyze {
    Write-TaskHeader "Running PSScriptAnalyzer"
    
    $settingsPath = Join-Path $repoRoot 'tools\PSScriptAnalyzerSettings.psd1'
    
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Write-Host "Installing PSScriptAnalyzer..." -ForegroundColor Yellow
        Install-Module PSScriptAnalyzer -Force -Scope CurrentUser
    }
    
    Import-Module PSScriptAnalyzer
    
    $results = Invoke-ScriptAnalyzer -Path $repoRoot -Recurse -Settings $settingsPath -ReportSummary
    
    $errors = $results | Where-Object { $_.Severity -eq 'Error' }
    $warnings = $results | Where-Object { $_.Severity -eq 'Warning' }
    
    if ($errors.Count -gt 0) {
        Write-Host "`nErrors found:" -ForegroundColor Red
        $errors | Format-Table -Property ScriptName, Line, RuleName, Message -AutoSize
        throw "Analysis failed with $($errors.Count) error(s)"
    }
    
    if ($warnings.Count -gt 0) {
        Write-Host "`nWarnings: $($warnings.Count)" -ForegroundColor Yellow
    }
    
    Write-Host "`nAnalysis passed!" -ForegroundColor Green
}

function Invoke-Build {
    Write-TaskHeader "Building C# Launchers"
    
    $cscPath = $null
    
    # Try to find csc.exe
    $frameworkPaths = @(
        "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    )
    
    foreach ($path in $frameworkPaths) {
        if (Test-Path $path) {
            $cscPath = $path
            break
        }
    }
    
    if (-not $cscPath) {
        Write-Host "C# compiler not found. Skipping launcher build." -ForegroundColor Yellow
        Write-Host "Install .NET Framework SDK or use Visual Studio to build launchers." -ForegroundColor Yellow
        return
    }
    
    $launchers = @(
        @{ Name = 'ADapp'; Source = 'src\ADapp.Launcher\Program.cs'; Output = 'ADapp.exe' },
        @{ Name = 'LockedMonitor'; Source = 'src\LockedMonitor.Launcher\Program.cs'; Output = 'LockedMonitor.exe' }
    )
    
    foreach ($launcher in $launchers) {
        $sourcePath = Join-Path $repoRoot $launcher.Source
        $outputPath = Join-Path $repoRoot $launcher.Output
        
        if (-not (Test-Path $sourcePath)) {
            Write-Host "Source not found: $sourcePath" -ForegroundColor Yellow
            continue
        }
        
        Write-Host "Building $($launcher.Name)..." -ForegroundColor White
        
        $iconFile = if ($launcher.Name -eq 'ADapp') { 'adapp.ico' } else { 'LockedMonitor.ico' }
        $iconPath = Join-Path $repoRoot ("assets\\icons\\{0}" -f $iconFile)
        $iconArg = if (Test-Path $iconPath) { "/win32icon:`"$iconPath`"" } else { "" }
        
        $args = @(
            "/target:winexe",
            "/out:`"$outputPath`"",
            "/reference:System.Windows.Forms.dll",
            $iconArg,
            "`"$sourcePath`""
        ) | Where-Object { $_ }
        
        $process = Start-Process -FilePath $cscPath -ArgumentList $args -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -ne 0) {
            throw "Failed to build $($launcher.Name)"
        }
        
        Write-Host "  Built: $outputPath" -ForegroundColor Green
    }
    
    Write-Host "`nBuild completed!" -ForegroundColor Green
}

function Invoke-Validate {
    Write-TaskHeader "Validating Configuration"
    
    $settingsPath = Join-Path $repoRoot 'config\settings.json'
    
    if (-not (Test-Path $settingsPath)) {
        throw "config/settings.json not found at $settingsPath"
    }
    
    Write-Host "Validating config/settings.json..." -ForegroundColor White
    
    try {
        $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
    } catch {
        throw "Invalid JSON in config/settings.json: $_"
    }
    
    # Required sections
    $requiredSections = @('Application', 'UI', 'Search', 'AD', 'Connections', 'Logging')
    $missingSections = @()
    
    foreach ($section in $requiredSections) {
        if (-not $settings.$section) {
            $missingSections += $section
        }
    }
    
    if ($missingSections.Count -gt 0) {
        Write-Host "  Missing sections: $($missingSections -join ', ')" -ForegroundColor Yellow
    }
    
    # Check for secrets in tracked file
    if ($settings.Connections.VNCPassword -and $settings.Connections.VNCPassword -ne '') {
        Write-Host "  WARNING: VNCPassword is set in config/settings.json. Move to config/settings.local.json!" -ForegroundColor Red
    }
    
    # Validate version format
    if ($settings.Application.Version -and $settings.Application.Version -notmatch '^\d+\.\d+\.\d+$') {
        Write-Host "  WARNING: Version format should be X.Y.Z" -ForegroundColor Yellow
    }
    
    Write-Host "  Validation passed!" -ForegroundColor Green
    
    # Check for local settings
    $localSettingsPath = Join-Path $env:ProgramData 'ADapp\config\settings.local.json'
    if (Test-Path $localSettingsPath) {
        Write-Host "  Found %ProgramData%\\ADapp\\config\\settings.local.json (local overrides active)" -ForegroundColor Cyan
    }
    
    Write-Host "`nConfiguration validation completed!" -ForegroundColor Green
}

function Invoke-Test {
    Write-TaskHeader "Running Pester Tests"
    
    $testsPath = Join-Path $repoRoot 'tests'
    
    if (-not (Test-Path $testsPath)) {
        Write-Host "No tests directory found. Skipping tests." -ForegroundColor Yellow
        return
    }
    
    if (-not (Get-Module -ListAvailable -Name Pester)) {
        Write-Host "Installing Pester..." -ForegroundColor Yellow
        Install-Module Pester -Force -Scope CurrentUser -SkipPublisherCheck
    }
    
    Import-Module Pester
    
    # Support both Pester v5+ (New-PesterConfiguration) and v3/v4
    if (Get-Command New-PesterConfiguration -ErrorAction SilentlyContinue) {
    $config = New-PesterConfiguration
    $config.Run.Path = $testsPath
    $config.Output.Verbosity = 'Detailed'
    $config.Run.Exit = $true
    Invoke-Pester -Configuration $config
    } else {
        Write-Host "Using legacy Pester invocation (v3/v4)" -ForegroundColor Yellow
        # Avoid -EnableExit to prevent the host from terminating (can crash terminals)
        if ((Get-Command Invoke-Pester).Parameters.ContainsKey('PassThru')) {
            $result = Invoke-Pester -Script $testsPath -Verbose -PassThru
            if ($result -and $result.FailedCount -gt 0) { throw "Pester failed: $($result.FailedCount) test(s)" }
        } else {
            Invoke-Pester -Script $testsPath -Verbose
        }
    }
}

# Main execution
try {
    Write-Host "ADapp Build Script" -ForegroundColor Magenta
    Write-Host "Repository: $repoRoot" -ForegroundColor Gray
    
    switch ($Task) {
        'All' {
            Invoke-Analyze
            Invoke-Validate
            Invoke-Build
            Invoke-Test
        }
        'Analyze' { Invoke-Analyze }
        'Build' { Invoke-Build }
        'Validate' { Invoke-Validate }
        'Test' { Invoke-Test }
    }
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host " Build completed successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
} catch {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host " Build failed: $_" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    exit 1
}

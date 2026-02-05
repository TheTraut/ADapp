Param(
    [string]$Path
)

$ErrorActionPreference = 'Stop'

$repoRoot = if ($Path) { Resolve-Path $Path } else { Resolve-Path (Join-Path $PSScriptRoot '..') }
$settingsPath = Join-Path $repoRoot 'tools\PSScriptAnalyzerSettings.psd1'

Write-Host "Analyzing PowerShell code under: $repoRoot" -ForegroundColor Cyan

try {
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Write-Host "PSScriptAnalyzer not found; installing..." -ForegroundColor Yellow
        & (Join-Path $PSScriptRoot 'Install-DevTools.ps1')
    }
    Import-Module PSScriptAnalyzer -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Could not ensure PSScriptAnalyzer is available: $_"
    exit 1
}

if (-not (Test-Path $settingsPath)) {
    Write-Warning "Settings file not found at $settingsPath; using default rules."
}

$results = Invoke-ScriptAnalyzer -Path $repoRoot -Recurse -Settings $settingsPath -ReportSummary

if ($results) {
    $grouped = $results | Group-Object RuleName | Sort-Object Count -Descending
    Write-Host "\nSummary:" -ForegroundColor Cyan
    foreach ($g in $grouped) {
        Write-Host ("{0,4}  {1}" -f $g.Count, $g.Name)
    }
}
